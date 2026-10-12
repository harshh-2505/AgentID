// Passkeys (WebAuthn) for principals.
//
// A held request is approved by a passkey assertion whose challenge is the hash of
// that exact approval. The private key never leaves the person's phone or security
// key, approval needs the device's own user verification (Face ID, fingerprint, PIN),
// and a stolen laptop or a leaked API token cannot produce one.
//
// Runs in browsers and Node: CBOR, COSE and signature checks use WebCrypto only.

import { b64u, unb64u, utf8, canonical } from './encoding.js';

// ---------------------------------------------------------------- CBOR (RFC 8949), decode only

export function decodeCbor(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let o = 0;
  const readLen = (info) => {
    if (info < 24) return info;
    if (info === 24) return view.getUint8(o++);
    if (info === 25) { const v = view.getUint16(o); o += 2; return v; }
    if (info === 26) { const v = view.getUint32(o); o += 4; return v; }
    if (info === 27) { const v = Number(view.getBigUint64(o)); o += 8; return v; }
    throw new Error('unsupported CBOR length');
  };
  const item = () => {
    const ib = view.getUint8(o++);
    const major = ib >> 5;
    const info = ib & 31;
    switch (major) {
      case 0: return readLen(info);
      case 1: return -1 - readLen(info);
      case 2: { const n = readLen(info); const v = bytes.slice(o, o + n); o += n; return v; }
      case 3: { const n = readLen(info); const v = new TextDecoder().decode(bytes.slice(o, o + n)); o += n; return v; }
      case 4: { const n = readLen(info); const a = []; for (let i = 0; i < n; i++) a.push(item()); return a; }
      case 5: { const n = readLen(info); const m = new Map(); for (let i = 0; i < n; i++) { const k = item(); m.set(k, item()); } return m; }
      case 6: readLen(info); return item();
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22 || info === 23) return null;
        if (info === 25) { o += 2; return NaN; }
        if (info === 26) { const v = view.getFloat32(o); o += 4; return v; }
        if (info === 27) { const v = view.getFloat64(o); o += 8; return v; }
        throw new Error('unsupported CBOR simple value');
      default: throw new Error('bad CBOR');
    }
  };
  const value = item();
  return { value, length: o };
}

// ---------------------------------------------------------------- COSE keys

export function coseToJwk(cose) {
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (kty === 2 && alg === -7) return { kty: 'EC', crv: 'P-256', x: b64u(cose.get(-2)), y: b64u(cose.get(-3)), alg: 'ES256' };
  if (kty === 1 && alg === -8) return { kty: 'OKP', crv: 'Ed25519', x: b64u(cose.get(-2)), alg: 'EdDSA' };
  if (kty === 3 && alg === -257) return { kty: 'RSA', n: b64u(cose.get(-1)), e: b64u(cose.get(-2)), alg: 'RS256' };
  throw new Error(`unsupported passkey algorithm (kty ${kty}, alg ${alg})`);
}

async function importPasskey(jwk) {
  if (jwk.kty === 'EC') return { key: await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']), algo: { name: 'ECDSA', hash: 'SHA-256' }, der: true };
  if (jwk.kty === 'OKP') return { key: await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify']), algo: { name: 'Ed25519' } };
  if (jwk.kty === 'RSA') return { key: await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']), algo: { name: 'RSASSA-PKCS1-v1_5' } };
  throw new Error('unsupported passkey key');
}

// WebAuthn ECDSA signatures are DER; WebCrypto wants raw r||s.
export function derToRaw(der, size = 32) {
  let o = 2;
  if (der[1] & 0x80) o = 2 + (der[1] & 0x7f);
  const read = () => {
    if (der[o++] !== 0x02) throw new Error('bad DER signature');
    const len = der[o++];
    let v = der.slice(o, o + len);
    o += len;
    while (v.length > size && v[0] === 0) v = v.slice(1);
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  };
  const r = read();
  const s = read();
  const raw = new Uint8Array(size * 2);
  raw.set(r);
  raw.set(s, size);
  return raw;
}

// ---------------------------------------------------------------- authenticator data

export function parseAuthData(ad) {
  const flags = ad[32];
  const out = {
    rpIdHash: ad.slice(0, 32),
    up: !!(flags & 0x01),
    uv: !!(flags & 0x04),
    at: !!(flags & 0x40),
    signCount: new DataView(ad.buffer, ad.byteOffset + 33, 4).getUint32(0),
  };
  if (out.at) {
    const credLen = (ad[53] << 8) | ad[54];
    out.credentialId = ad.slice(55, 55 + credLen);
    const { value } = decodeCbor(ad.slice(55 + credLen));
    out.cose = value;
  }
  return out;
}

const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function checkClientData(clientDataJSON, { type, challenge, origins }) {
  const cd = JSON.parse(new TextDecoder().decode(clientDataJSON));
  if (cd.type !== type) throw new Error(`expected ${type}`);
  if (cd.challenge !== challenge) throw new Error('passkey response is for a different challenge');
  if (origins?.length && !origins.includes(cd.origin)) throw new Error(`origin ${cd.origin} is not allowed`);
  return cd;
}

// Verifies navigator.credentials.create() output and returns the stored credential.
// Attestation statements are not checked (format "none" is the common case); the
// principal's own signature over the enrollment is what binds the key to them.
export async function verifyRegistration({ clientDataJSON, attestationObject }, { challenge, rpId, origins }) {
  const cdBytes = unb64u(clientDataJSON);
  checkClientData(cdBytes, { type: 'webauthn.create', challenge, origins });
  const att = decodeCbor(unb64u(attestationObject)).value;
  const ad = parseAuthData(att.get('authData'));
  if (!same(ad.rpIdHash, await sha256(utf8(rpId)))) throw new Error('passkey was created for a different site');
  if (!ad.up) throw new Error('user presence flag missing');
  if (!ad.at) throw new Error('no credential in registration');
  return { credentialId: b64u(ad.credentialId), jwk: coseToJwk(ad.cose), signCount: ad.signCount, uv: ad.uv };
}

// Verifies navigator.credentials.get() output against a stored credential.
export async function verifyAssertion({ authenticatorData, clientDataJSON, signature }, cred, { challenge, rpId, origins, requireUV = true }) {
  const cdBytes = unb64u(clientDataJSON);
  checkClientData(cdBytes, { type: 'webauthn.get', challenge, origins });
  const adBytes = unb64u(authenticatorData);
  const ad = parseAuthData(adBytes);
  if (!same(ad.rpIdHash, await sha256(utf8(rpId)))) throw new Error('passkey assertion is for a different site');
  if (!ad.up) throw new Error('user presence flag missing');
  if (requireUV && !ad.uv) throw new Error('the device did not verify the user (no biometric or PIN)');
  if (cred.signCount && ad.signCount && ad.signCount <= cred.signCount) throw new Error('signature counter went backwards; the passkey may be cloned');
  const { key, algo, der } = await importPasskey(cred.jwk);
  let sig = unb64u(signature);
  if (der) sig = derToRaw(sig);
  const signed = new Uint8Array([...adBytes, ...(await sha256(cdBytes))]);
  if (!(await crypto.subtle.verify(algo, key, sig, signed))) throw new Error('passkey signature is invalid');
  return { signCount: ad.signCount };
}

// The challenge a principal's passkey signs to decide a held request.
export async function approvalChallenge({ approval, intentHash, decision }) {
  return b64u(await sha256(utf8(canonical({ approval, intentHash, decision, purpose: 'agentid-cosign' }))));
}
