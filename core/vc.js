// AgentID passports as W3C Verifiable Credentials 2.0, secured with a Data Integrity
// proof using the eddsa-jcs-2022 cryptosuite. Runs in browsers and Node (WebCrypto only).
//
// Who issues the credential: the *authority*, not the principal. The authority never
// holds principals' keys, so it cannot re-sign the passport in the principal's name.
// What it can honestly say is "this passport is registered with me and was valid when I
// checked", so the credential's issuer is the authority's did:key, and the original
// principal-signed passport rides along in `evidence` so a verifier who wants the
// principal's own signature can still check it. Status can change after issuance
// (revocation, freeze); a relying party that needs live status asks the authority.
//
// did:agentid and did:key name the same Ed25519 public key in two encodings:
//   did:agentid:<base64url(raw)>   ↔   did:key:z<base58btc(0xed 0x01 ‖ raw)>

import { b64u, unb64u, utf8, canonical } from './encoding.js';
import { didFromPublicKey, publicKeyFromDid, verifySealed } from './keys.js';

const ALG = { name: 'Ed25519' };
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_PUB = [0xed, 0x01]; // multicodec varint for ed25519-pub
const DID_KEY = 'did:key:';
export const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const CRYPTOSUITE = 'eddsa-jcs-2022';

// ---------------------------------------------------------------- base58btc

export function base58btcEncode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  return '1'.repeat(zeros) + digits.reverse().map((d) => B58[d]).join('');
}

export function base58btcDecode(str) {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;
  const bytes = [];
  for (let i = zeros; i < str.length; i++) {
    let carry = B58.indexOf(str[i]);
    if (carry < 0) throw new Error('invalid base58btc character');
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  return Uint8Array.from([...new Array(zeros).fill(0), ...bytes.reverse()]);
}

const multibase = (bytes) => 'z' + base58btcEncode(bytes);
function unmultibase(s) {
  if (typeof s !== 'string' || s[0] !== 'z') throw new Error('expected a base58btc multibase value (z…)');
  return base58btcDecode(s.slice(1));
}

// ---------------------------------------------------------------- did:key

export const didKeyFromPublicKey = (raw) => DID_KEY + multibase(Uint8Array.from([...ED25519_PUB, ...raw]));

export function publicKeyFromDidKey(didKey) {
  if (typeof didKey !== 'string' || !didKey.startsWith(DID_KEY)) throw new Error('not a did:key');
  const bytes = unmultibase(didKey.slice(DID_KEY.length).split('#')[0]);
  if (bytes[0] !== ED25519_PUB[0] || bytes[1] !== ED25519_PUB[1] || bytes.length !== 34) throw new Error('did:key is not an Ed25519 key');
  return bytes.slice(2);
}

export const didKeyFromAgentId = (did) => didKeyFromPublicKey(publicKeyFromDid(did));
export const agentIdFromDidKey = (didKey) => didFromPublicKey(publicKeyFromDidKey(didKey));

// The verification method id for a did:key is the DID plus its own multibase key as fragment.
const verificationMethod = (didKey) => didKey + '#' + didKey.slice(DID_KEY.length);

// ---------------------------------------------------------------- credentials

const iso = (sec) => new Date(sec * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const sha256 = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(s)));

// proofConfigHash ‖ documentHash, both over JCS. canonical() is JCS for the JSON we
// produce: keys sorted by UTF-16 code units, ECMAScript number and string serialisation.
async function hashData(doc, proofConfig) {
  const [a, b] = await Promise.all([sha256(canonical(proofConfig)), sha256(canonical(doc))]);
  const out = new Uint8Array(64);
  out.set(a, 0);
  out.set(b, 32);
  return out;
}

// `signer` is the authority's Signer (or ExternalSigner); `issuerDid` defaults to its did.
// `status` and `principal` are what the authority knows about the passport right now.
export async function passportToCredential(passport, signer, { issuerDid, principal, status = 'active', created } = {}) {
  if (passport?.type !== 'AgentPassport') throw new Error('not an agent passport');
  const issuer = didKeyFromAgentId(issuerDid || signer.did);
  const credential = {
    '@context': [VC_CONTEXT],
    id: 'urn:agentid:passport:' + passport.id,
    type: ['VerifiableCredential', 'AgentPassportCredential'],
    issuer,
    validFrom: iso(passport.iat),
    validUntil: iso(passport.exp),
    credentialSubject: {
      id: didKeyFromAgentId(passport.sub),
      agentid: passport.sub,
      name: passport.name,
      purpose: passport.purpose,
      model: passport.model,
      runtime: passport.runtime,
      depth: passport.depth,
      principal: principal || undefined,
      status,
    },
    evidence: [{
      id: 'urn:agentid:passport:' + passport.id,
      type: ['AgentIDPassport'],
      description: 'The principal-signed AgentID passport this credential attests to',
      passport,
    }],
  };
  const proofConfig = {
    '@context': credential['@context'],
    type: 'DataIntegrityProof',
    cryptosuite: CRYPTOSUITE,
    created: created || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    verificationMethod: verificationMethod(issuer),
    proofPurpose: 'assertionMethod',
  };
  // canonical() drops undefined, so the JSON round trip below hashes the same bytes.
  const doc = JSON.parse(JSON.stringify(credential));
  const sig = unb64u(await signer.signBytes(await hashData(doc, proofConfig)));
  return { ...doc, proof: { ...proofConfig, proofValue: multibase(sig) } };
}

const fail = (reason) => ({ ok: false, reason });

// Checks the Data Integrity proof, the validity window and that the embedded passport
// is the one described. `issuer` optionally pins the expected issuer (did:key or did:agentid).
export async function verifyCredential(vc, { issuer, now = Date.now(), checkEvidence = true } = {}) {
  try {
    const { proof, ...doc } = vc || {};
    if (!doc.type?.includes('VerifiableCredential')) return fail('not a verifiable credential');
    if (doc['@context']?.[0] !== VC_CONTEXT) return fail('first @context must be the VC 2.0 context');
    if (proof?.type !== 'DataIntegrityProof' || proof.cryptosuite !== CRYPTOSUITE) return fail(`proof is not a ${CRYPTOSUITE} DataIntegrityProof`);
    if (proof.proofPurpose !== 'assertionMethod') return fail('proof purpose must be assertionMethod');
    const issuerId = typeof doc.issuer === 'string' ? doc.issuer : doc.issuer?.id;
    if (!proof.verificationMethod?.startsWith(issuerId + '#')) return fail('proof was not made by the issuer');
    if (issuer && issuer !== issuerId && !(issuer.startsWith('did:agentid:') && didKeyFromAgentId(issuer) === issuerId)) return fail('credential comes from a different issuer');
    const { proofValue, ...proofConfig } = proof;
    if (proofConfig['@context'] && canonical(proofConfig['@context']) !== canonical(doc['@context'])) return fail('proof @context does not match the document');
    const key = await crypto.subtle.importKey('raw', publicKeyFromDidKey(issuerId), ALG, false, ['verify']);
    if (!(await crypto.subtle.verify(ALG, key, unmultibase(proofValue), await hashData(doc, proofConfig)))) return fail('proof signature is invalid');
    if (doc.validFrom && Date.parse(doc.validFrom) > now + 30_000) return fail('credential is not valid yet');
    if (doc.validUntil && Date.parse(doc.validUntil) < now) return fail('credential expired');
    const subject = doc.credentialSubject;
    if (subject?.agentid && didKeyFromAgentId(subject.agentid) !== subject.id) return fail('subject did:key and did:agentid name different keys');
    const pp = doc.evidence?.find((e) => e.passport)?.passport;
    if (checkEvidence && pp) {
      if (pp.sub !== subject?.agentid) return fail('embedded passport belongs to a different agent');
      if (!(await verifySealed(pp))) return fail('embedded passport signature is invalid');
    }
    return { ok: true, credential: vc, issuer: issuerId, subject: subject?.agentid ?? null };
  } catch (e) {
    return fail(e.message);
  }
}

// Exposed for tests and for callers that want the raw JWK of a did:key.
export const jwkFromDidKey = (didKey) => ({ kty: 'OKP', crv: 'Ed25519', x: b64u(publicKeyFromDidKey(didKey)) });
