// Postgres storage for the authority, with the exact transaction interface of MemoryStore.
//
// Concurrency model. Every write transaction takes one global advisory lock
// (pg_advisory_xact_lock) right after BEGIN, so writers are serialised across every
// authority process that shares the database. That single lock is what makes the
// authority's invariants hold under horizontal scaling:
//   * a nonce is claimed at most once (replay protection),
//   * budget checks and spend updates cannot interleave (no double spend),
//   * ledger seq numbers are contiguous and each entry links to the true previous head.
// The lock is released automatically at COMMIT or ROLLBACK, and also if the connection
// dies, so a crashed process cannot wedge the cluster.
//
// Throughput is therefore bounded by one writer at a time (a verifyIntent is a handful of
// indexed queries plus one Ed25519 signature, so a few hundred to a few thousand
// decisions per second). The scale-out path is sharding by principal: give each shard
// its own lock key (or its own database and ledger), since no transaction ever touches
// two principals' budgets. Reads (checkpoints, proofs, snapshots) take no lock.
//
// Accepts either a pool-like object with connect() returning a client with query() and
// release() (pg.Pool), or a single connection with only query() (PGlite, one pg.Client).
// A single connection cannot hold two transactions at once, so those are queued
// in-process, per connection: several PostgresStore objects over one PGlite stay safe.

const DEFAULT_LOCK = 0x41474944; // "AGID"
const NONCE_SWEEP_MS = 60_000;
const singleQueues = new WeakMap();

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS agentid_records (kind text NOT NULL, id text NOT NULL, doc jsonb NOT NULL, PRIMARY KEY (kind, id))`,
  `CREATE TABLE IF NOT EXISTS agentid_nonces (nonce text PRIMARY KEY, exp bigint NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS agentid_nonces_exp ON agentid_nonces (exp)`,
  `CREATE TABLE IF NOT EXISTS agentid_ledger (seq bigint PRIMARY KEY, entry jsonb NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS agentid_meta (key text PRIMARY KEY, value jsonb NOT NULL)`,
];

// Values always go in as JSON text cast to jsonb: pg would otherwise turn JS arrays
// into Postgres arrays. `undefined` becomes null, as JSON.stringify would drop it.
// A connection whose ROLLBACK failed is in an unknown state: tell the pool to discard it.
async function rollback(c, err) {
  try { await c.query('ROLLBACK'); } catch (e) { if (err && typeof err === 'object') err.poisoned = e; }
}

const j = (v) => JSON.stringify(v === undefined ? null : v);

export class PostgresStore {
  // db: pg.Pool, or a single connection such as PGlite.
  // opts.lockKey: advisory lock key; use one per shard when sharding by principal.
  constructor(db, { lockKey = DEFAULT_LOCK, nonceSweepMs = NONCE_SWEEP_MS } = {}) {
    this.db = db;
    this.pooled = typeof db.connect === 'function';
    this.lockKey = lockKey;
    this.nonceSweepMs = nonceSweepMs;
    this.lastSweep = 0;
  }

  // Opens a pg.Pool. `pg` is an optional dependency, imported only when used.
  static async connect(url, opts = {}) {
    let pg;
    try { pg = (await import('pg')).default; } catch { throw new Error('PostgresStore.connect needs the "pg" package: npm install pg'); }
    const pool = new pg.Pool({ connectionString: url, max: opts.max || 10 });
    pool.on('error', (e) => console.warn('postgres pool error:', e.message));
    const store = new PostgresStore(pool, opts);
    if (opts.migrate !== false) await store.migrate();
    return store;
  }

  async migrate() {
    await this.#withClient(async (c) => {
      for (const sql of SCHEMA) await c.query(sql);
    });
    return this;
  }

  async close() {
    if (this.pooled && typeof this.db.end === 'function') await this.db.end();
    else if (typeof this.db.close === 'function') await this.db.close();
  }

  transaction(fn) {
    return this.#withClient(async (c) => {
      await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      try {
        // READ COMMITTED on purpose: each statement after the lock sees everything the
        // previous lock holder committed. A REPEATABLE READ snapshot would predate the lock.
        await c.query('SELECT pg_advisory_xact_lock($1::bigint)', [this.lockKey]);
        const result = await fn(this.#tx(c, true));
        await c.query('COMMIT');
        return result;
      } catch (e) {
        await rollback(c, e);
        throw e;
      }
    });
  }

  // Lock-free reads from one consistent snapshot, so a checkpoint's size and leaves agree.
  read(fn) {
    return this.#withClient(async (c) => {
      await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      try {
        const result = await fn(this.#tx(c, false));
        await c.query('COMMIT');
        return result;
      } catch (e) {
        await rollback(c, e);
        throw e;
      }
    });
  }

  async #withClient(fn) {
    if (this.pooled) {
      const c = await this.db.connect();
      let poisoned;
      try { return await fn(c); } catch (e) { poisoned = e?.poisoned; throw e; } finally { c.release(poisoned); }
    }
    // Single connection: queue everything (reads too) so statements never interleave.
    const prev = singleQueues.get(this.db) || Promise.resolve();
    const run = prev.then(() => fn(this.db));
    singleQueues.set(this.db, run.catch(() => {}));
    return run;
  }

  #tx(c, writable) {
    const q = async (sql, params) => (await c.query(sql, params)).rows;
    const ro = () => { if (!writable) throw new Error('write attempted in a read-only store view'); };
    return {
      get: async (kind, id) => {
        if (id === undefined || id === null) return null;
        const rows = await q('SELECT doc FROM agentid_records WHERE kind = $1 AND id = $2', [kind, String(id)]);
        return rows.length ? rows[0].doc : null;
      },
      put: async (kind, id, value) => {
        ro();
        await q('INSERT INTO agentid_records (kind, id, doc) VALUES ($1, $2, $3::jsonb) ON CONFLICT (kind, id) DO UPDATE SET doc = EXCLUDED.doc', [kind, String(id), j(value)]);
        return value;
      },
      del: async (kind, id) => { ro(); await q('DELETE FROM agentid_records WHERE kind = $1 AND id = $2', [kind, String(id)]); },
      list: async (kind) => (await q('SELECT doc FROM agentid_records WHERE kind = $1 ORDER BY id', [kind])).map((r) => r.doc),
      getMeta: async (key, fallback = null) => {
        const rows = await q('SELECT value FROM agentid_meta WHERE key = $1', [key]);
        return rows.length ? rows[0].value ?? fallback : fallback;
      },
      putMeta: async (key, value) => {
        ro();
        await q('INSERT INTO agentid_meta (key, value) VALUES ($1, $2::jsonb) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value', [key, j(value)]);
      },
      // Claims `nonce` unless an unexpired claim exists. The upsert only overwrites an
      // expired row, and RETURNING tells us whether this statement won.
      claimNonce: async (nonce, exp, now) => {
        ro();
        if (Date.now() - this.lastSweep > this.nonceSweepMs) {
          this.lastSweep = Date.now();
          await q('DELETE FROM agentid_nonces WHERE exp < $1', [now]);
        }
        const rows = await q(
          'INSERT INTO agentid_nonces (nonce, exp) VALUES ($1, $2) ON CONFLICT (nonce) DO UPDATE SET exp = EXCLUDED.exp WHERE agentid_nonces.exp < $3 RETURNING nonce',
          [String(nonce), exp, now],
        );
        return rows.length === 1;
      },
      // Safe only under the advisory lock: the head read and the insert must not interleave
      // with another writer. The primary key on seq is a second line of defence.
      appendLedger: async (build) => {
        ro();
        const rows = await q("SELECT seq, entry->>'hash' AS hash FROM agentid_ledger ORDER BY seq DESC LIMIT 1");
        const seq = rows.length ? Number(rows[0].seq) + 1 : 0;
        const entry = await build(seq, rows.length ? rows[0].hash : null);
        await q('INSERT INTO agentid_ledger (seq, entry) VALUES ($1, $2::jsonb)', [seq, j(entry)]);
        return entry;
      },
      ledgerSlice: async (from, limit) =>
        (await q('SELECT entry FROM agentid_ledger WHERE seq >= $1 ORDER BY seq LIMIT $2', [from, limit])).map((r) => r.entry),
      ledgerHeight: async () => Number((await q('SELECT coalesce(max(seq) + 1, 0) AS n FROM agentid_ledger'))[0].n),
      ledgerHashes: async (from, to) =>
        (await q("SELECT entry->>'hash' AS hash FROM agentid_ledger WHERE seq >= $1 AND seq < $2 ORDER BY seq", [from, to])).map((r) => r.hash),
    };
  }
}
