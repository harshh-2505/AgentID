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

  // Writes are staged and applied only when fn resolves, so a failed transaction leaves
  // no trace and readers never see a half-finished one.
  transaction(fn) {
    const run = this.queue.then(async () => {
      const stage = { records: new Map(), nonces: new Map(), ledger: [], meta: new Map() };
      const result = await fn(this.#tx(stage));
      this.#commit(stage);
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }

  read(fn) {
    return fn(this.#tx(null));
  }

  export() {
    return this.d;
  }

  #commit(st) {
    const d = this.d;
    for (const [key, v] of st.records) {
      const [kind, id] = JSON.parse(key);
      const b = (d.records[kind] ||= {});
      if (v === undefined) delete b[id]; else b[id] = v;
    }
    for (const [n, e] of st.nonces) { if (e === undefined) delete d.nonces[n]; else d.nonces[n] = e; }
    d.ledger.push(...st.ledger);
    for (const [k, v] of st.meta) d.meta[k] = v;
  }

  #tx(st) {
    const d = this.d;
    const copy = (v) => (v === undefined || v === null ? v ?? null : structuredClone(v));
    const ro = () => { if (!st) throw new Error('read-only view'); };
    const k = (kind, id) => JSON.stringify([kind, String(id)]);
    return {
      get: async (kind, id) => {
        if (id === undefined || id === null) return null;
        if (st?.records.has(k(kind, id))) return copy(st.records.get(k(kind, id)));
        return copy(d.records[kind]?.[id]);
      },
      put: async (kind, id, value) => { ro(); st.records.set(k(kind, id), copy(value)); return value; },
      del: async (kind, id) => { ro(); st.records.set(k(kind, id), undefined); },
      list: async (kind) => {
        const out = { ...(d.records[kind] || {}) };
        if (st) for (const [key, v] of st.records) { const [kk, id] = JSON.parse(key); if (kk === kind) { if (v === undefined) delete out[id]; else out[id] = v; } }
        return Object.values(out).map(copy);
      },
      getMeta: async (key, fallback = null) => copy(st?.meta.has(key) ? st.meta.get(key) : d.meta[key]) ?? fallback,
      putMeta: async (key, value) => { ro(); st.meta.set(key, copy(value)); },
      claimNonce: async (nonce, exp, now) => {
        ro();
        if (Object.keys(d.nonces).length > 5000) for (const [n, e] of Object.entries(d.nonces)) if (e < now) st.nonces.set(n, undefined);
        const cur = st.nonces.has(nonce) ? st.nonces.get(nonce) : d.nonces[nonce];
        if (cur && cur >= now) return false;
        st.nonces.set(nonce, exp);
        return true;
      },
      appendLedger: async (build) => {
        ro();
        const seq = d.ledger.length + st.ledger.length;
        const prev = st.ledger.length ? st.ledger.at(-1).hash : d.ledger.length ? d.ledger.at(-1).hash : null;
        const entry = await build(seq, prev);
        st.ledger.push(entry);
        return entry;
      },
      ledgerSlice: async (from, limit) => [...d.ledger, ...(st?.ledger || [])].slice(from, from + limit),
      ledgerHeight: async () => d.ledger.length + (st?.ledger.length || 0),
      ledgerHashes: async (from, to) => [...d.ledger, ...(st?.ledger || [])].slice(from, to).map((e) => e.hash),
    };
  }
}
