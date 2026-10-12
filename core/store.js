// Storage behind the authority.
//
// Every write the authority makes happens inside `store.transaction(fn)`. The store
// guarantees that transactions do not interleave, which is what makes nonce and budget
// checks safe. MemoryStore serialises them in-process; the Postgres store (server/store/
// postgres.js) takes a database lock, so several authority processes can share one
// database without double-spending a budget or accepting a replay twice.
//
// Records are plain JSON documents addressed by (kind, id). A transaction must `put`
// any record it changes; reads may return copies.

export class MemoryStore {
  constructor(data) {
    this.d = data || { records: {}, nonces: {}, ledger: [], meta: {} };
    this.queue = Promise.resolve();
  }

  transaction(fn) {
    const run = this.queue.then(() => fn(this.#tx()));
    this.queue = run.catch(() => {});
    return run;
  }

  // Reads outside a transaction see committed state. In memory that is the same view.
  read(fn) {
    return fn(this.#tx());
  }

  export() {
    return this.d;
  }

  #tx() {
    const d = this.d;
    const bucket = (kind) => (d.records[kind] ||= {});
    return {
      get: async (kind, id) => (id === undefined || id === null ? null : bucket(kind)[id] ?? null),
      put: async (kind, id, value) => { bucket(kind)[id] = value; return value; },
      del: async (kind, id) => { delete bucket(kind)[id]; },
      list: async (kind) => Object.values(bucket(kind)),
      getMeta: async (key, fallback = null) => d.meta[key] ?? fallback,
      putMeta: async (key, value) => { d.meta[key] = value; },
      claimNonce: async (nonce, exp, now) => {
        if (Object.keys(d.nonces).length > 5000) for (const [n, e] of Object.entries(d.nonces)) if (e < now) delete d.nonces[n];
        if (d.nonces[nonce] && d.nonces[nonce] >= now) return false;
        d.nonces[nonce] = exp;
        return true;
      },
      appendLedger: async (build) => {
        const seq = d.ledger.length;
        const prev = seq ? d.ledger[seq - 1].hash : null;
        const entry = await build(seq, prev);
        d.ledger.push(entry);
        return entry;
      },
      ledgerSlice: async (from, limit) => d.ledger.slice(from, from + limit),
      ledgerHeight: async () => d.ledger.length,
      ledgerHashes: async (from, to) => d.ledger.slice(from, to).map((e) => e.hash),
    };
  }
}
