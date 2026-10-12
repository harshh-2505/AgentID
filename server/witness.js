// Independent witnesses for the authority's ledger.
//
// An authority could show one history to one auditor and another history to everyone
// else (a split view), or quietly roll its log back. A witness is a separate party with
// its own key that remembers the last checkpoint it co-signed for each authority and
// co-signs a new one only if a Merkle consistency proof shows it extends the old one.
// Relying parties that require k witness co-signatures on a checkpoint therefore see
// one append-only history, or none.
//
// Two signed checkpoints that cannot both be true (same size and different roots, or a
// newer checkpoint that is smaller or not an extension) are proof the authority
// misbehaved; the witness keeps both as an alarm and refuses to co-sign.
//
// This file has both sides: createWitness() for the witness process (see witness-cli.js),
// and routes(ctx) for the authority server.

import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import path from 'node:path';
import { verifySealed, isDid } from '../core/keys.js';
import { verifyConsistency } from '../core/merkle.js';

const FUTURE_SKEW_MS = 5 * 60 * 1000;
const httpError = (status, message) => Object.assign(new Error(message), { status });

// store: a file path for durable state, or 'memory' / undefined.
// authorities: optional allowlist of authority DIDs this witness vouches for.
export async function createWitness({ signer, name = 'witness', store = 'memory', authorities = null, clock = () => Date.now() }) {
  const file = typeof store === 'string' && store !== 'memory' ? store : null;
  let state = { logs: {}, alarms: [] };
  if (file) {
    try { state = JSON.parse(await readFile(file, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  let queue = Promise.resolve();

  const save = async () => {
    if (!file) return;
    await mkdir(path.dirname(path.resolve(file)), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(state, null, 2));
    await rename(tmp, file);
  };

  const alarm = async (kind, message, previous, offered) => {
    const a = { kind, authority: offered.authority, message, at: clock(), previous, offered };
    state.alarms.push(a);
    await save();
    throw Object.assign(new Error(`refusing to co-sign: ${message}`), { status: 409, alarm: a });
  };

  async function check(cp, proofArg) {
    if (cp?.type !== 'Checkpoint' || !isDid(cp.authority) || !Number.isInteger(cp.size) || cp.size < 0 || typeof cp.root !== 'string') throw httpError(400, 'not a checkpoint');
    if (authorities && !authorities.includes(cp.authority)) throw httpError(403, 'this witness does not vouch for that authority');
    if (!(await verifySealed(cp, cp.authority))) throw httpError(400, 'checkpoint is not signed by the authority it names');
    if (cp.ts > clock() + FUTURE_SKEW_MS) throw httpError(400, 'checkpoint is dated in the future');

    const last = state.logs[cp.authority];
    if (last) {
      const prev = last.checkpoint;
      const proof = Array.isArray(proofArg) ? proofArg : proofArg?.proof || [];
      if (proofArg && !Array.isArray(proofArg) && (proofArg.first !== prev.size || proofArg.second !== cp.size)) throw httpError(400, `consistency proof must cover ${prev.size} -> ${cp.size}`);
      if (cp.size === prev.size) {
        if (cp.root !== prev.root) await alarm('fork', `two different logs of size ${cp.size}`, prev, cp);
      } else if (cp.size < prev.size) {
        // An older checkpoint replayed to us is harmless; a newer one that shrank is a rollback.
        if (cp.ts > prev.ts) await alarm('rollback', `log shrank from ${prev.size} to ${cp.size}`, prev, cp);
        throw httpError(409, `already co-signed size ${prev.size}; this checkpoint is older`);
      } else if (prev.size > 0 && !proof.length) {
        throw httpError(400, `a consistency proof from size ${prev.size} is required`);
      } else if (prev.size > 0 && !(await verifyConsistency(prev.size, cp.size, prev.root, cp.root, proof))) {
        await alarm('fork', `size ${cp.size} does not extend the co-signed size ${prev.size}`, prev, cp);
      }
    }
    state.logs[cp.authority] = { checkpoint: cp, cosignedAt: clock() };
    await save();
    return signer.seal({ type: 'WitnessCosignature', v: 1, witness: signer.did, name, checkpoint: cp, iat: Math.floor(clock() / 1000) });
  }

  return {
    did: signer.did,
    name,
    // Verifies and co-signs, or throws (status 409 with .alarm on equivocation).
    // consistencyProof: the array, or { first, second, proof } as the authority serves it.
    observe(checkpoint, consistencyProof) {
      const run = queue.then(() => check(checkpoint, consistencyProof));
      queue = run.catch(() => {});
      return run;
    },
    last: (authority) => state.logs[authority]?.checkpoint || null,
    alarms: () => [...state.alarms],
  };
}

// One witnessing round against an authority's HTTP API: fetch its checkpoint, a
// consistency proof from what we last co-signed, co-sign, and hand the co-signature back.
export async function pollOnce({ witness, url, fetch: fetchFn = globalThis.fetch }) {
  const base = url.replace(/\/$/, '');
  const getJson = async (p, init) => {
    const res = await fetchFn(base + p, init);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`${p}: ${res.status} ${body.error || ''}`.trim());
    return body;
  };
  const cp = await getJson('/v1/checkpoint');
  const last = witness.last(cp.authority);
  let proof = [];
  if (last && last.size > 0 && cp.size > last.size) proof = await getJson(`/v1/proofs/consistency?first=${last.size}&second=${cp.size}`);
  const cosig = await witness.observe(cp, proof);
  await getJson('/v1/witness', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(cosig) });
  return cosig;
}

// ---------------------------------------------------------------- authority-side routes

const param = (query, key) => (typeof query?.get === 'function' ? query.get(key) : query?.[key]) ?? null;

function int(query, key, { required = false } = {}) {
  const v = param(query, key);
  if (v === null || v === '') {
    if (required) throw httpError(400, `${key} is required`);
    return undefined;
  }
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw httpError(400, `${key} must be a non-negative integer`);
  return n;
}

const asClientError = (p) => p.catch((e) => { throw e.status ? e : httpError(400, e.message); });

// ctx.config.witnesses: optional allowlist of witness DIDs whose co-signatures we store.
export function routes(ctx) {
  const A = () => ctx.authority();
  return [
    ['GET', '/v1/checkpoint', () => A().checkpoint()],
    ['GET', '/v1/proofs/inclusion', (_, __, q) => asClientError(A().inclusionProof(int(q, 'seq', { required: true }), int(q, 'size')))],
    ['GET', '/v1/proofs/consistency', (_, __, q) => asClientError(A().consistencyProof(int(q, 'first', { required: true }), int(q, 'second')))],
    ['POST', '/v1/witness', (body) => {
      const allow = ctx.config?.witnesses;
      if (allow?.length && !allow.includes(body?.witness)) throw httpError(403, 'not a witness this authority recognises');
      return asClientError(A().recordWitness(body));
    }],
  ];
}
