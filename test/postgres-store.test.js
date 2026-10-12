import test from 'node:test';
import assert from 'node:assert/strict';
import { PGlite } from '@electric-sql/pglite';
import { Authority, Principal, Attestor, AgentRuntime, Signer, verifyReceipt, verifyChain } from '../core/index.js';
import { checkpointExtends } from '../core/authority.js';
import { PostgresStore } from '../server/store/postgres.js';

async function freshStore(db = new PGlite()) {
  const store = new PostgresStore(db);
  await store.migrate();
  return { db, store };
}

async function org(A, { cosign = { above: 500 }, budget = 10000 } = {}) {
  const p = await Principal.create({ name: 'Acme' });
  const host = await Attestor.create('host');
  await A.registerPrincipal(await p.registration());
  await A.endorseAttestor(await p.endorseAttestor(host));
  const agent = await AgentRuntime.create({ name: 'Payer', purpose: 'pays', model: 'm', manifest: { model: 'm', tools: ['pay'] } });
  agent.passport = await p.issuePassport(agent, { depth: 1 });
  await A.registerPassport(agent.passport);
  agent.mandate = await p.issueMandate({ sub: agent.did, depth: 1, caps: [{ action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 5000 } } }], budget: { amount: budget, currency: 'USD' }, cosign });
  await A.registerMandate(agent.mandate);
  agent.attestation = await host.attest(agent.did, agent.manifest);
  return { p, host, agent };
}

const pay = (agent, amount) => agent.intent({ action: 'payments.send', resource: 'vendor:x', params: { amount, currency: 'USD' }, reason: 'invoice' });

test('postgres store: a full authority scenario', async () => {
  const { db, store } = await freshStore();
  const A = await Authority.create({ store });
  const { p, agent } = await org(A);

  const ok = await A.verifyIntent(await pay(agent, 100));
  assert.equal(ok.decision, 'allow', JSON.stringify(ok.checks));
  assert.ok((await verifyReceipt(ok.receipt, A.did)).ok);

  const held = await A.verifyIntent(await pay(agent, 700));
  assert.equal(held.decision, 'step_up');
  const ap = await A.approval(held.approvalId);
  assert.equal(ap.status, 'pending');
  const done = await A.resolveApproval(await p.cosign(ap));
  assert.equal(done.status, 'approved');
  assert.deepEqual(done.decision.receipt.cosigners, [p.did]);
  const spend = await store.read((tx) => tx.get('spend', agent.mandate.id));
  assert.deepEqual([spend.spent, spend.reserved], [800, 0]);

  const intent = await pay(agent, 5);
  assert.equal((await A.verifyIntent(intent)).decision, 'allow');
  assert.equal((await A.verifyIntent(intent)).failedAt, 'freshness', 'replay is blocked by the nonce table');

  await A.revoke(await p.revoke(agent.passport.id, 'test'));
  assert.equal((await A.verifyIntent(await pay(agent, 5))).failedAt, 'identity');

  const v = await A.verifyLedger();
  assert.ok(v.ok, v.reason);
  const c1 = await A.checkpoint();
  assert.equal(c1.size, v.checked);
  await A.verifyIntent(await pay(agent, 5));
  const c2 = await A.checkpoint();
  assert.ok(await checkpointExtends(c1, c2, (await A.consistencyProof(c1.size, c2.size)).proof));

  const snap = await A.snapshot();
  assert.equal(snap.principals.length, 1);
  assert.equal(snap.stats.allowed, 3);
  await db.close();
});

test('postgres store: a failed transaction leaves nothing behind', async () => {
  const { db, store } = await freshStore();
  await assert.rejects(store.transaction(async (tx) => {
    await tx.put('x', 'a', { v: 1 });
    await tx.appendLedger(async (seq, prev) => ({ seq, prev, hash: 'h' }));
    throw new Error('boom');
  }), /boom/);
  assert.equal(await store.read((tx) => tx.get('x', 'a')), null);
  assert.equal(await store.read((tx) => tx.ledgerHeight()), 0);
  await store.transaction((tx) => tx.putMeta('list', [1, 'two', { three: 3 }]));
  assert.deepEqual(await store.read((tx) => tx.getMeta('list')), [1, 'two', { three: 3 }], 'arrays round-trip as JSON, not Postgres arrays');
  assert.equal(await store.transaction((tx) => tx.claimNonce('n1', 100, 50)), true);
  assert.equal(await store.transaction((tx) => tx.claimNonce('n1', 100, 60)), false, 'unexpired nonce cannot be claimed again');
  assert.equal(await store.transaction((tx) => tx.claimNonce('n1', 300, 200)), true, 'expired nonce can be reused');
  await db.close();
});

test('postgres store: two authority processes on one database never double-spend', async () => {
  const db = new PGlite();
  const signer = await Signer.fromJwk((await Signer.generate()).export());
  const s1 = new PostgresStore(db);
  const s2 = new PostgresStore(db);
  await s1.migrate();
  const A1 = new Authority(signer, { store: s1 });
  const A2 = new Authority(await Signer.fromJwk(signer.export()), { store: s2 });
  const { agent } = await org(A1, { cosign: null });

  const intent = await pay(agent, 10);
  const same = await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? A1 : A2).verifyIntent(intent)));
  assert.equal(same.filter((r) => r.decision === 'allow').length, 1, 'one nonce, one allow, across both instances');

  const burst = await Promise.all(Array.from({ length: 30 }, async (_, i) => (i % 2 ? A1 : A2).verifyIntent(await pay(agent, 900))));
  const allowed = burst.filter((r) => r.decision === 'allow').length;
  const spend = await s2.read((tx) => tx.get('spend', agent.mandate.id));
  assert.ok(spend.spent <= 10000, `spent ${spend.spent}`);
  assert.equal(spend.spent, 10 + allowed * 900);
  assert.equal(allowed, 11, 'only what fits in the 10,000 budget clears (10 + 11 × 900)');

  const entries = await s1.read(async (tx) => tx.ledgerSlice(0, await tx.ledgerHeight()));
  assert.deepEqual(entries.map((e) => e.seq), entries.map((_, i) => i), 'ledger seq is contiguous');
  assert.ok((await verifyChain(entries, signer.did)).ok);
  assert.ok((await A2.verifyLedger()).ok);
  const [c1, c2] = [await A1.checkpoint(), await A2.checkpoint()];
  assert.equal(c1.root, c2.root, 'both instances checkpoint the same log');
  await db.close();
});

// Runs only against a real Postgres (CI sets AGENTID_TEST_DATABASE_URL). Two pools mean
// real concurrent connections, so this exercises the advisory lock, not an in-process queue.
test('postgres store: two pools on a real server serialise through the advisory lock', { skip: !process.env.AGENTID_TEST_DATABASE_URL && 'set AGENTID_TEST_DATABASE_URL to run' }, async () => {
  const url = process.env.AGENTID_TEST_DATABASE_URL;
  const s1 = await PostgresStore.connect(url);
  const s2 = await PostgresStore.connect(url);
  await s1.db.query('TRUNCATE agentid_records, agentid_nonces, agentid_ledger, agentid_meta');
  try {
    const signer = await Signer.generate();
    const A1 = new Authority(signer, { store: s1 });
    const A2 = new Authority(await Signer.fromJwk(signer.export()), { store: s2 });
    const { agent } = await org(A1, { cosign: null });
    const burst = await Promise.all(Array.from({ length: 30 }, async (_, i) => (i % 2 ? A1 : A2).verifyIntent(await pay(agent, 900))));
    assert.equal(burst.filter((r) => r.decision === 'allow').length, 11);
    const entries = await A1.ledgerEntries({ limit: 1000 });
    assert.deepEqual(entries.map((e) => e.seq), entries.map((_, i) => i), 'ledger seq is contiguous');
    assert.ok((await verifyChain(entries, A1.did)).ok);
  } finally {
    await s1.close();
    await s2.close();
  }
});
