// Encoding helpers shared by every part of AgentID.
// Runs unchanged in browsers and in Node 20+ (both expose WebCrypto, btoa and atob).

const encoder = new TextEncoder();

export const utf8 = (s) => encoder.encode(s);

export function b64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64u(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

// Deterministic JSON: object keys sorted, undefined dropped. Every signature in
// AgentID is computed over this form so that two parties always hash the same bytes.
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map((v) => (v === undefined ? 'null' : canonical(v))).join(',') + ']';
  return '{' + Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort()
    .map((k) => JSON.stringify(k) + ':' + canonical(value[k]))
    .join(',') + '}';
}

export async function sha256(data) {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

export const hashObject = (obj) => sha256(canonical(obj));

export function randomId(prefix) {
  return prefix + '_' + b64u(crypto.getRandomValues(new Uint8Array(9)));
}

export const nowSec = () => Math.floor(Date.now() / 1000);
