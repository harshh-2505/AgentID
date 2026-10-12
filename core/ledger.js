// Append-only, hash-chained, signed decision log.
// Each entry commits to the previous one, so editing or dropping any entry breaks
// every hash after it, and the authority's signature on each hash pins authorship.

import { canonical, sha256 } from './encoding.js';
import { verifySealed } from './keys.js';

export const GENESIS = '0'.repeat(64);

export async function entryHash({ seq, ts, kind, data, prev }) {
  return sha256(canonical({ seq, ts, kind, data, prev }));
}

export class Ledger {
  constructor(signer, entries = []) {
    this.signer = signer;
    this.entries = entries;
  }

  get head() {
    return this.entries.length ? this.entries[this.entries.length - 1].hash : GENESIS;
  }

  async append(kind, data, ts = Date.now()) {
    const seq = this.entries.length;
    const prev = this.head;
    const hash = await entryHash({ seq, ts, kind, data, prev });
    const { proof } = await this.signer.seal({ hash });
    const entry = { seq, ts, kind, data, prev, hash, sig: proof.sig };
    this.entries.push(entry);
    return entry;
  }
}

// Recomputes the whole chain. Returns the first broken entry, if any, and why.
export async function verifyChain(entries, authorityDid) {
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.seq !== i) return { ok: false, brokenAt: i, reason: 'sequence gap', checked: i };
    if (e.prev !== prev) return { ok: false, brokenAt: i, reason: 'link to previous entry does not match', checked: i };
    const h = await entryHash(e);
    if (h !== e.hash) return { ok: false, brokenAt: i, reason: 'entry content does not match its hash', checked: i };
    const sigOk = await verifySealed({ hash: e.hash, proof: { alg: 'Ed25519', kid: authorityDid, sig: e.sig } }, authorityDid);
    if (!sigOk) return { ok: false, brokenAt: i, reason: 'authority signature is invalid', checked: i };
    prev = e.hash;
  }
  return { ok: true, checked: entries.length, head: prev };
}
