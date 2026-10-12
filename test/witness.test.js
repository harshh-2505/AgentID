import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Authority, Principal, Signer, verifySealed, verifyInclusion } from '../core/index.js';
import { createWitness, pollOnce, routes } from '../server/witness.js';

const grow = async (A, n) => { for (let i = 0; i < n; i++) await A.registerPrincipal(await (await Principal.create({ name: 'p' + i })).registration()); };

// Minimal server for a routes(ctx) table, mirroring the module contract.
async function serve(table) {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const hit = table.find(([m, p]) => m === req.method && p === url.pathname);
    res.setHeader('content-type', 'application/json');
    if (!hit) { res.statusCode = 404; return res.end('{}'); }
    let raw = '';
    for await (const c of req) raw += c;
    try {
      res.end(JSON.stringify(await hit[2](raw ? JSON.parse(raw) : null, {}, url.searchParams, req)));
    } catch (e) {
      res.statusCode = e.status || 500;
      res.end(JSON.stringify({ error: e.message }));
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

test('witness: co-signs honest growth and the authority records it', async () => {
  const A = await Authority.create();
  const w = await createWitness({ signer: await Signer.generate(), name: 'w1' });
  const c0 = await A.checkpoint();
  const s0 = await w.observe(c0, []);
  assert.ok(await verifySealed(s0, w.did));
  await grow(A, 3);
  const c1 = await A.checkpoint();
  const s1 = await w.observe(c1, []); // previous size was 0: nothing to prove
  await grow(A, 5);
  const c2 = await A.checkpoint();
  await assert.rejects(w.observe(c2, []), (e) => e.status === 400 && !e.alarm, 'an extension needs its proof');
  await assert.rejects(w.observe(c2, (await A.consistencyProof(2, c2.size)).proof), (e) => e.alarm?.kind === 'fork', 'a proof that does not hold is an alarm');
  const w2 = await createWitness({ signer: await Signer.generate(), name: 'w2' });
  await w2.observe(c1);
  const s2 = await w2.observe(c2, await A.consistencyProof(c1.size, c2.size));
  assert.equal(s2.checkpoint.size, 8);
  await A.recordWitness(s1);
  await A.recordWitness(s2);
  const witnessed = (await A.snapshot()).ledger.witnessed;
  assert.deepEqual(witnessed.map((x) => [x.name, x.size]).sort(), [['w1', 3], ['w2', 8]]);
  assert.match((await w.observe(c0, []).catch((e) => e)).message, /older/, 'old checkpoints are refused without alarm');
  assert.equal(w2.alarms().length, 0);
  assert.equal(w.alarms().length, 1);
});

test('witness: a forked log with the same key is refused and recorded', async () => {
  const signer = await Signer.generate();
  const honest = await Authority.create({ signer });
  const evil = await Authority.create({ signer: await Signer.fromJwk(signer.export()) });
  await grow(honest, 4);
  await grow(evil, 4); // same authority DID, different history

  const w = await createWitness({ signer: await Signer.generate(), name: 'w' });
  await w.observe(await honest.checkpoint());

  const split = await evil.checkpoint();
  const e1 = await w.observe(split, []).catch((e) => e);
  assert.equal(e1.alarm?.kind, 'fork');
  assert.match(e1.message, /two different logs of size 4/);

  await grow(evil, 3);
  const longer = await evil.checkpoint();
  const e2 = await w.observe(longer, await evil.consistencyProof(4, longer.size)).catch((e) => e);
  assert.equal(e2.alarm?.kind, 'fork');
  assert.match(e2.message, /does not extend/);

  // A newer, smaller checkpoint is a rollback.
  await grow(honest, 4);
  await w.observe(await honest.checkpoint(), await honest.consistencyProof(4, 8));
  const rolled = await Authority.create({ signer: await Signer.fromJwk(signer.export()), clock: () => Date.now() + 1000 });
  await grow(rolled, 2);
  assert.equal((await w.observe(await rolled.checkpoint(), []).catch((e) => e)).alarm?.kind, 'rollback');

  const alarms = w.alarms();
  assert.equal(alarms.length, 3);
  assert.ok(await verifySealed(alarms[0].previous, signer.did) && await verifySealed(alarms[0].offered, signer.did), 'alarm holds both signed checkpoints as evidence');
  assert.equal(w.last(signer.did).size, 8, 'state stays on the honest log');

  const forged = { ...(await honest.checkpoint()), size: 99 };
  await assert.rejects(w.observe(forged, []), /not signed/);
});

test('witness: state survives restarts, and the HTTP round trip works', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'witness-'));
  const A = await Authority.create();
  const { server, url } = await serve(routes({ authority: () => A, world: () => null, config: {} }));
  try {
    const store = path.join(dir, 'state.json');
    const wsigner = await Signer.generate();
    const w = await createWitness({ signer: wsigner, name: 'ci', store });
    await grow(A, 2);
    assert.equal((await pollOnce({ witness: w, url })).checkpoint.size, 2);
    await grow(A, 3);
    const restarted = await createWitness({ signer: wsigner, name: 'ci', store });
    assert.equal(restarted.last(A.did).size, 2);
    assert.equal((await pollOnce({ witness: restarted, url })).checkpoint.size, 5, 'consistency proof fetched over HTTP');
    assert.equal((await A.snapshot()).ledger.witnessed[0].size, 5);

    const cp = await (await fetch(url + '/v1/checkpoint')).json();
    const incl = await (await fetch(`${url}/v1/proofs/inclusion?seq=3&size=${cp.size}`)).json();
    assert.ok(await verifyInclusion(incl.leaf, 3, cp.size, incl.proof, cp.root));
    assert.equal((await fetch(`${url}/v1/proofs/inclusion?seq=abc`)).status, 400);
    assert.equal((await fetch(`${url}/v1/proofs/consistency?first=9&second=2`)).status, 400);
    assert.equal((await fetch(url + '/v1/witness', { method: 'POST', body: JSON.stringify({ type: 'nope' }) })).status, 400);

    const pinned = routes({ authority: () => A, world: () => null, config: { witnesses: ['did:agentid:other'] } });
    const post = pinned.find(([m, p]) => m === 'POST' && p === '/v1/witness')[2];
    await assert.rejects(async () => post(await restarted.observe(await A.checkpoint())), (e) => e.status === 403);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
