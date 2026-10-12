// Ed25519 keys and self-certifying identifiers.
//
// An AgentID identifier is `did:agentid:<base64url public key>`. Anyone can check a
// signature from the identifier alone, so no registry lookup sits on the hot path.

import { b64u, unb64u, utf8, canonical } from './encoding.js';

const ALG = { name: 'Ed25519' };
const DID_PREFIX = 'did:agentid:';
const verifyKeyCache = new Map();

export const didFromPublicKey = (raw) => DID_PREFIX + b64u(raw);

export function publicKeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith(DID_PREFIX)) throw new Error('not an AgentID identifier');
  const raw = unb64u(did.slice(DID_PREFIX.length));
  if (raw.length !== 32) throw new Error('identifier does not hold a 32-byte Ed25519 key');
  return raw;
}

export const isDid = (s) => typeof s === 'string' && s.startsWith(DID_PREFIX);

// Short, human-checkable form of an identifier, like an SSH fingerprint.
export function shortDid(did) {
  if (!isDid(did)) return String(did);
  const k = did.slice(DID_PREFIX.length);
  return k.slice(0, 4) + '·' + k.slice(4, 8) + '·' + k.slice(-4);
}

async function importVerifyKey(did) {
  let key = verifyKeyCache.get(did);
  if (!key) {
    key = await crypto.subtle.importKey('raw', publicKeyFromDid(did), ALG, false, ['verify']);
    verifyKeyCache.set(did, key);
  }
  return key;
}

export class Signer {
  constructor(did, privateKey, jwk) {
    this.did = did;
    this.privateKey = privateKey;
    this.jwk = jwk;
  }

  static async generate() {
    const kp = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    return new Signer(didFromPublicKey(raw), kp.privateKey, jwk);
  }

  static async fromJwk(jwk) {
    const privateKey = await crypto.subtle.importKey('jwk', jwk, ALG, true, ['sign']);
    return new Signer(didFromPublicKey(unb64u(jwk.x)), privateKey, jwk);
  }

  async signBytes(bytes) {
    return b64u(new Uint8Array(await crypto.subtle.sign(ALG, this.privateKey, bytes)));
  }

  // Returns a copy of `body` carrying a detached proof over its canonical form.
  async seal(body) {
    const { proof: _drop, ...clean } = body;
    const sig = await this.signBytes(utf8(canonical(clean)));
    return { ...clean, proof: { alg: 'Ed25519', kid: this.did, sig } };
  }

  export() {
    return this.jwk;
  }
}

// True when `obj.proof` is a valid signature by `expectedKid` (or by whatever key
// the proof names, when no expectation is given).
export async function verifySealed(obj, expectedKid) {
  try {
    const { proof, ...body } = obj || {};
    // One signature, one spelling: exactly 86 unpadded base64url characters, canonical tail bits.
    if (!proof || proof.alg !== 'Ed25519' || typeof proof.sig !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(proof.sig)) return false;
    if (b64u(unb64u(proof.sig)) !== proof.sig) return false;
    if (expectedKid && proof.kid !== expectedKid) return false;
    const key = await importVerifyKey(proof.kid);
    return await crypto.subtle.verify(ALG, key, unb64u(proof.sig), utf8(canonical(body)));
  } catch {
    return false;
  }
}

// A signer whose private key lives somewhere else: a cloud KMS, Vault's transit
// engine, an HSM. Only the public identifier and a signing callback are local.
export class ExternalSigner extends Signer {
  constructor(did, signFn, label = 'external signer') {
    super(did, null, null);
    this.signFn = signFn;
    this.label = label;
  }

  async signBytes(bytes) {
    const sig = await this.signFn(bytes);
    return typeof sig === 'string' ? sig : b64u(sig);
  }

  export() {
    return null;
  }
}

