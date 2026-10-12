// A software WebAuthn authenticator that produces byte-for-byte standard responses
// (packed "none" attestation, ES256, DER signatures). It exists for tests and for the
// demo console when the browser cannot reach a real passkey, for example inside a
// sandboxed frame. The authority verifies its output with the same code path it uses
// for Face ID, Windows Hello or a YubiKey; it is labelled "virtual" everywhere it shows.

import { b64u, utf8 } from './encoding.js';

const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const cat = (...parts) => { const o = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; };

function cborHead(major, n) {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  return new Uint8Array([(major << 5) | 25, n >> 8, n & 255]);
}

export function encodeCbor(v) {
  if (typeof v === 'number') return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (typeof v === 'string') { const b = utf8(v); return cat(cborHead(3, b.length), b); }
  if (v instanceof Uint8Array) return cat(cborHead(2, v.length), v);
  if (v instanceof Map) return cat(cborHead(5, v.size), ...[...v].flatMap(([k, x]) => [encodeCbor(k), encodeCbor(x)]));
  throw new Error('unsupported CBOR value');
}

function rawToDer(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); return b[0] & 0x80 ? cat(new Uint8Array([0]), b) : b; };
  const r = int(raw.slice(0, 32));
  const s = int(raw.slice(32));
  const body = cat(new Uint8Array([2, r.length]), r, new Uint8Array([2, s.length]), s);
  return cat(new Uint8Array([0x30, body.length]), body);
}

export class VirtualAuthenticator {
  constructor() {
    this.creds = new Map();
  }

  static async restore(list = []) {
    const va = new VirtualAuthenticator();
    for (const c of list) {
      const key = await crypto.subtle.importKey('jwk', c.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
      va.creds.set(c.id, { id: c.id, key, jwk: c.jwk, count: c.count, rpId: c.rpId });
    }
    return va;
  }

  export() {
    return [...this.creds.values()].map(({ id, jwk, count, rpId }) => ({ id, jwk, count, rpId }));
  }

  async create({ challenge, rpId, origin }) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    const idBytes = crypto.getRandomValues(new Uint8Array(16));
    const id = b64u(idBytes);
    const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, pub.slice(1, 33)], [-3, pub.slice(33, 65)]]);
    const authData = cat(await sha(utf8(rpId)), new Uint8Array([0x45, 0, 0, 0, 0]), new Uint8Array(16), new Uint8Array([0, 16]), idBytes, encodeCbor(cose));
    const attestationObject = encodeCbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    const clientDataJSON = utf8(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false }));
    this.creds.set(id, { id, key: kp.privateKey, jwk, count: 0, rpId });
    return { id, clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject) };
  }

  async get({ credentialId, challenge, rpId, origin, userVerified = true }) {
    const c = this.creds.get(credentialId);
    if (!c) throw new Error('no such credential on this authenticator');
    c.count += 1;
    const count = new Uint8Array([c.count >>> 24, (c.count >>> 16) & 255, (c.count >>> 8) & 255, c.count & 255]);
    const authenticatorData = cat(await sha(utf8(rpId)), new Uint8Array([userVerified ? 0x05 : 0x01]), count);
    const clientDataJSON = utf8(JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, c.key, cat(authenticatorData, await sha(clientDataJSON))));
    return { credentialId, authenticatorData: b64u(authenticatorData), clientDataJSON: b64u(clientDataJSON), signature: b64u(rawToDer(raw)) };
  }
}
