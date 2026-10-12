// RFC 9162 (Certificate Transparency v2) Merkle tree over ledger entry hashes.
//
// The hash chain already makes the ledger tamper-evident end to end. The Merkle tree
// adds two things the chain cannot do cheaply:
//   * inclusion proofs: "entry #n is in the log of size s" in O(log s) hashes, and
//   * consistency proofs: "the log of size s2 extends the log of size s1" without
//     downloading it, which is what lets independent witnesses co-sign checkpoints.

import { hex } from './encoding.js';

const fromHex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));

async function sha(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export const leafHash = (leaf) => sha(concat(new Uint8Array([0]), leaf));
export const nodeHash = (l, r) => sha(concat(new Uint8Array([1]), l, r));

const largestPow2Below = (n) => { let k = 1; while (k << 1 < n) k <<= 1; return k; };
const isPow2 = (n) => n > 0 && (n & (n - 1)) === 0;

// A tree over hex leaf strings. Complete (power-of-two) subtrees never change once
// written, so their hashes are cached across calls as the log grows.
export class MerkleTree {
  constructor() {
    this.cache = new Map();
  }

  async #mth(leaves, start, size) {
    if (size === 0) return sha(new Uint8Array());
    const key = start + ':' + size;
    if (isPow2(size) && this.cache.has(key)) return this.cache.get(key);
    let h;
    if (size === 1) h = await leafHash(fromHex(leaves[start]));
    else {
      const k = largestPow2Below(size);
      h = await nodeHash(await this.#mth(leaves, start, k), await this.#mth(leaves, start + k, size - k));
    }
    if (isPow2(size)) this.cache.set(key, h);
    return h;
  }

  async root(leaves, size = leaves.length) {
    return hex(await this.#mth(leaves, 0, size));
  }

  async inclusionProof(leaves, index, size = leaves.length) {
    if (index < 0 || index >= size) throw new Error('index outside the tree');
    const path = [];
    const walk = async (m, start, n) => {
      if (n === 1) return;
      const k = largestPow2Below(n);
      if (m < k) { await walk(m, start, k); path.push(await this.#mth(leaves, start + k, n - k)); }
      else { await walk(m - k, start + k, n - k); path.push(await this.#mth(leaves, start, k)); }
    };
    await walk(index, 0, size);
    return path.map(hex);
  }

  async consistencyProof(leaves, first, second = leaves.length) {
    if (first < 1 || first > second) throw new Error('consistency proof needs 1 <= first <= second');
    const proof = [];
    const sub = async (m, start, n, b) => {
      if (m === n) { if (!b) proof.push(await this.#mth(leaves, start, n)); return; }
      const k = largestPow2Below(n);
      if (m <= k) { await sub(m, start, k, b); proof.push(await this.#mth(leaves, start + k, n - k)); }
      else { await sub(m - k, start + k, n - k, false); proof.push(await this.#mth(leaves, start, k)); }
    };
    await sub(first, 0, second, true);
    return proof.map(hex);
  }
}

export async function verifyInclusion(leafHex, index, size, proofHex, rootHex) {
  if (index >= size) return false;
  let fn = index, sn = size - 1;
  let r = await leafHash(fromHex(leafHex));
  for (const p of proofHex.map(fromHex)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (!(fn & 1)) while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && hex(r) === rootHex;
}

export async function verifyConsistency(first, second, firstRoot, secondRoot, proofHex) {
  if (first === second) return proofHex.length === 0 && firstRoot === secondRoot;
  if (first < 1 || first > second) return false;
  let proof = proofHex.map(fromHex);
  if (isPow2(first)) proof = [fromHex(firstRoot), ...proof];
  if (!proof.length) return false;
  let fn = first - 1, sn = second - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = proof[0], sr = proof[0];
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if (!(fn & 1)) while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return hex(fr) === firstRoot && hex(sr) === secondRoot && sn === 0;
}
