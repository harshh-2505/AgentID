// AWS Nitro Enclaves attestation documents as proof of runtime.
//
// The Nitro hypervisor signs a COSE_Sign1 document (CBOR) with a short-lived per-host
// key whose certificate chains to the AWS Nitro root. The document carries the enclave
// image's PCRs (hash of the image, kernel, application, signing certificate, ...) plus
// up to 1 KiB each of user_data and public_key chosen by the code inside the enclave.
//
// The binding we require:
//   * the chain verifies up to the pinned root, with every certificate in date,
//   * the PCRs pinned in the agent's passport (passport.runtime.pcrs) match,
//   * user_data or public_key names the agent's DID (or holds its SHA-256), so a document
//     from the right enclave cannot be replayed by a different agent key, and
//   * the document is fresh.
// The intent that carries the document is signed by the agent key, so the pairing of
// "this key" and "this enclave image" is attested by hardware, not asserted by a host.
//
// att = { format: 'aws-nitro', document: base64 or base64url of the COSE_Sign1 bytes }

import { X509Certificate, createHash, verify as nodeVerify } from 'node:crypto';
import { decodeCbor } from '../../core/webauthn.js';

// AWS Nitro Enclaves Root-G1, from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// SHA-256 fingerprint 64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
export const AWS_NITRO_ROOT_G1 = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

const COSE_ES384 = -35;
const MAX_AGE_MS = 5 * 60 * 1000;
const SKEW_MS = 60 * 1000;

// ---------------------------------------------------------------- CBOR encoding
// core/virtual-authenticator.js encodes only what WebAuthn needs; COSE also needs
// arrays, null and 64-bit lengths (timestamps). Exported for tests that build documents.

const cat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  if (n < 0x100000000) { const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b; }
  const b = Buffer.alloc(9); b[0] = (major << 5) | 27; b.writeBigUInt64BE(BigInt(n), 1); return b;
}

export function encodeCbor(v) {
  if (v === null || v === undefined) return Buffer.from([0xf6]);
  if (typeof v === 'boolean') return Buffer.from([v ? 0xf5 : 0xf4]);
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('only integer CBOR numbers are supported');
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (typeof v === 'string') { const b = Buffer.from(v, 'utf8'); return cat(head(3, b.length), b); }
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (Array.isArray(v)) return cat(head(4, v.length), ...v.map(encodeCbor));
  if (v instanceof Map) return cat(head(5, v.size), ...[...v].flatMap(([k, x]) => [encodeCbor(k), encodeCbor(x)]));
  throw new Error('unsupported CBOR value');
}

// ---------------------------------------------------------------- helpers

const toBytes = (b64) => new Uint8Array(Buffer.from(String(b64).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
const hexOf = (b) => Buffer.from(b).toString('hex');
const asBytes = (v) => (v instanceof Uint8Array ? v : null);
const fail = (reason) => ({ ok: false, reason });

function contains(hay, needle) {
  if (!hay || !needle.length || hay.length < needle.length) return false;
  return Buffer.from(hay).indexOf(Buffer.from(needle)) !== -1;
}

// Parses and checks the COSE_Sign1 envelope; returns the payload map and leaf cert.
export function parseNitroDocument(bytes) {
  const cose = decodeCbor(bytes).value; // a leading tag 18 is skipped by the decoder
  if (!Array.isArray(cose) || cose.length !== 4) throw new Error('not a COSE_Sign1 structure');
  const [protectedBytes, , payloadBytes, signature] = cose;
  if (!asBytes(protectedBytes) || !asBytes(payloadBytes) || !asBytes(signature)) throw new Error('malformed COSE_Sign1');
  const protectedHeader = protectedBytes.length ? decodeCbor(protectedBytes).value : new Map();
  const payload = decodeCbor(payloadBytes).value;
  if (!(payload instanceof Map)) throw new Error('attestation payload is not a map');
  return { protectedBytes, protectedHeader, payloadBytes, payload, signature };
}

// Verifies leaf <- cabundle <- pinned root. The cabundle is ordered root first; its first
// element must be the pinned root itself or be issued by it.
function verifyChain(leafDer, cabundle, root, nowMs) {
  const at = new Date(nowMs);
  const inDate = (c) => new Date(c.validFrom) <= at && at <= new Date(c.validTo);
  const certs = cabundle.map((d) => new X509Certificate(Buffer.from(d)));
  if (certs.length && certs[0].fingerprint256 === root.fingerprint256) certs.shift();
  const chain = [root, ...certs, new X509Certificate(Buffer.from(leafDer))];
  for (let i = 0; i < chain.length; i++) {
    const c = chain[i];
    if (!inDate(c)) return `certificate ${c.subject.replace(/\n/g, ', ')} is not valid now`;
    if (i === 0) continue;
    const parent = chain[i - 1];
    if (!parent.ca) return `${parent.subject.replace(/\n/g, ', ')} is not a CA`;
    if (!c.checkIssued(parent) || !c.verify(parent.publicKey)) return i === 1 ? 'certificate chain does not lead to the pinned Nitro root' : 'certificate chain is broken';
  }
  return { leaf: chain[chain.length - 1] };
}

// options:
//   root      PEM of the trust anchor (default: the real AWS Nitro root G1); override for tests
//   maxAgeMs  how old a document may be (default 5 minutes)
export function nitroVerifier({ root = AWS_NITRO_ROOT_G1, maxAgeMs = MAX_AGE_MS } = {}) {
  const anchor = new X509Certificate(root);
  return async function verifyNitro(att, { passport, agent, nowMs }) {
    nowMs ??= Date.now();
    if (att?.format !== 'aws-nitro' || !att.document) return fail('not an aws-nitro attestation');
    const want = passport?.runtime?.pcrs;
    if (!want || typeof want !== 'object' || !Object.keys(want).length) return fail('passport pins no enclave PCRs');

    let doc;
    try { doc = parseNitroDocument(toBytes(att.document)); } catch (e) { return fail('attestation document is malformed: ' + e.message); }
    const p = doc.payload;
    if (doc.protectedHeader.get?.(1) !== COSE_ES384) return fail('attestation must be signed with ES384');
    if (p.get('digest') !== 'SHA384') return fail('unexpected PCR digest algorithm');
    const leafDer = asBytes(p.get('certificate'));
    const cabundle = p.get('cabundle');
    if (!leafDer || !Array.isArray(cabundle) || !cabundle.every(asBytes)) return fail('attestation carries no certificate chain');

    // 1. Signature by the leaf certificate's key, chain to the pinned root.
    let chain;
    try { chain = verifyChain(leafDer, cabundle, anchor, nowMs); } catch (e) { return fail('certificate parse error: ' + e.message); }
    if (typeof chain === 'string') return fail(chain);
    const sigStructure = encodeCbor(['Signature1', doc.protectedBytes, new Uint8Array(0), doc.payloadBytes]);
    const sigOk = nodeVerify('sha384', sigStructure, { key: chain.leaf.publicKey, dsaEncoding: 'ieee-p1363' }, doc.signature);
    if (!sigOk) return fail('attestation document signature is invalid');

    // 2. Freshness.
    const ts = p.get('timestamp');
    if (typeof ts !== 'number') return fail('attestation has no timestamp');
    if (ts > nowMs + SKEW_MS) return fail('attestation is dated in the future');
    if (nowMs - ts > maxAgeMs) return fail(`attestation is ${Math.round((nowMs - ts) / 1000)}s old`);

    // 3. The enclave image is the one the passport pins.
    const pcrs = p.get('pcrs');
    if (!(pcrs instanceof Map)) return fail('attestation has no PCRs');
    for (const [idx, hexWant] of Object.entries(want)) {
      const got = asBytes(pcrs.get(Number(idx)));
      if (!got || hexOf(got) !== String(hexWant).toLowerCase()) return fail(`PCR${idx} does not match the passport (running ${got ? hexOf(got).slice(0, 12) + '…' : 'nothing'})`);
    }

    // 4. The document speaks for this agent's key.
    const didBytes = Buffer.from(agent, 'utf8');
    const didHash = createHash('sha256').update(didBytes).digest();
    const didHashHex = Buffer.from(didHash.toString('hex'), 'utf8');
    const bound = [asBytes(p.get('user_data')), asBytes(p.get('public_key'))].some((b) => contains(b, didBytes) || contains(b, didHash) || contains(b, didHashHex));
    if (!bound) return fail('attestation is not bound to this agent key (user_data/public_key must carry its DID or SHA-256)');

    const pcr0 = asBytes(pcrs.get(0));
    return { ok: true, detail: `Nitro enclave ${p.get('module_id') || ''}`.trim() + (pcr0 ? ` · PCR0 ${hexOf(pcr0).slice(0, 12)}…` : '') + ` · ${Object.keys(want).length} PCR(s) pinned` };
  };
}
