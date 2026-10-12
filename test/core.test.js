import test from 'node:test';
import assert from 'node:assert/strict';
import {
  Authority, Principal, Attestor, AgentRuntime, Signer, verifyReceipt, verifyChain,
  capsWithin, authorize, patternWithin,
} from '../core/index.js';
import { DemoWorld, ATTACKS } from '../core/demo-world.js';

async function setup({ cosign = { above: 500 }, quorum } = {}) {
  const A = await Authority.create();
  const org = await Principal.create({ name: 'Acme' });
  const host = await Attestor.create('Acme host');
  await A.registerPrincipal(await org.registration());
  await A.endorseAttestor(await org.endorseAttestor(host));
  const agent = await AgentRuntime.create({ name: 'Payer', purpose: 'pays', model: 'm1', manifest: { model: 'm1', tools: ['pay'] } });
  agent.passport = await org.issuePassport(agent, { depth: 1 });
  await A.registerPassport(agent.passport);
  agent.mandate = await org.issueMandate({
    sub: agent.did, depth: 1,
    caps: [{ action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 1000 }, currency: { in: ['USD'] } } }],
    budget: { amount: 1500, currency: 'USD' },
    cosign: quorum ? { above: cosign.above, quorum } : cosign,
  });
  await A.registerMandate(agent.mandate);
  agent.attestation = await host.attest(agent.did, agent.manifest);
  return { A, org, host, agent };
}

const pay = (agent, amount, extra = {}) => agent.intent({ action: 'payments.send', resource: 'vendor:x', params: { amount, currency: 'USD' }, reason: 'invoice 1', ...extra });

test('policy: pattern containment and attenuation', () => {
  assert.ok(patternWithin('payments.send', 'payments.*'));
  assert.ok(!patternWithin('pay*', 'payments.*'));
  assert.ok(patternWithin('vendor:acme/*', 'vendor:*'));
  const parent = [{ action: 'payments.*', resource: 'vendor:*', limits: { amount: { max: 100 }, to: { in: ['a', 'b'] } } }];
  assert.deepEqual(capsWithin([{ action: 'payments.send', resource: 'vendor:a', limits: { amount: { max: 50 }, to: { in: ['a'] } } }], parent), []);
  assert.equal(capsWithin([{ action: 'payments.send', resource: 'vendor:a', limits: { amount: { max: 500 }, to: { in: ['a'] } } }], parent).length, 1);
  assert.equal(capsWithin([{ action: 'payments.send', resource: 'vendor:a', limits: { amount: { max: 50 } } }], parent).length, 1, 'dropping a limit widens');
  assert.equal(authorize(parent, 'payments.send', 'vendor:a', { amount: 10 }).stage, 'limits', 'missing param fails closed');
});

test('allows an in-policy request and issues a verifiable receipt', async () => {
  const { A, agent } = await setup();
  const r = await A.verifyIntent(await pay(agent, 200));
  assert.equal(r.decision, 'allow', JSON.stringify(r.checks));
  assert.ok(r.checks.every((c) => c.status === 'pass'));
  assert.ok((await verifyReceipt(r.receipt, A.did)).ok);
  const tampered = { ...r.receipt, params: { amount: 9999 } };
  assert.ok(!(await verifyReceipt(tampered, A.did)).ok);
});

test('blocks replay, forgery, and expired intents', async () => {
  const { A, agent } = await setup();
  const intent = await pay(agent, 100);
  assert.equal((await A.verifyIntent(intent)).decision, 'allow');
  const replay = await A.verifyIntent(intent);
  assert.equal(replay.failedAt, 'freshness');

  const thief = await Signer.generate();
  const { proof, ...body } = await pay(agent, 100);
  const forged = await thief.seal(body);
  forged.proof.kid = agent.did;
  assert.equal((await A.verifyIntent(forged)).failedAt, 'signature');

  const mutated = { ...(await pay(agent, 100)), params: { amount: 999, currency: 'USD' } };
  assert.equal((await A.verifyIntent(mutated)).failedAt, 'signature', 'changing a signed field breaks the proof');
});

test('detects a changed runtime', async () => {
  const { A, host, agent } = await setup();
  agent.manifest = { ...agent.manifest, tools: ['pay', 'shell.exec'] };
  agent.attestation = await host.attest(agent.did, agent.manifest);
  assert.equal((await A.verifyIntent(await pay(agent, 50))).failedAt, 'runtime');
});

test('rejects an untrusted attestor', async () => {
  const { A, agent } = await setup();
  const rogue = await Attestor.create('rogue');
  agent.attestation = await rogue.attest(agent.did, agent.manifest);
  assert.equal((await A.verifyIntent(await pay(agent, 50))).failedAt, 'runtime');
});

test('enforces limits, scope and cumulative budget', async () => {
  const { A, agent } = await setup({ cosign: null });
  assert.equal((await A.verifyIntent(await pay(agent, 5000))).failedAt, 'limits');
  assert.equal((await A.verifyIntent(await agent.intent({ action: 'payroll.run', resource: 'hr:all', reason: 'x' }))).failedAt, 'scope');
  assert.equal((await A.verifyIntent(await pay(agent, 900))).decision, 'allow');
  const over = await A.verifyIntent(await pay(agent, 700));
  assert.equal(over.failedAt, 'budget');
});

test('sub-agent delegation narrows authority and shares the parent budget', async () => {
  const { A, org, agent } = await setup({ cosign: null });
  const sub = await AgentRuntime.create({ name: 'Sub', purpose: 'p', model: 'm2', manifest: { model: 'm2', tools: [] } });
  sub.passport = await agent.issuePassport(sub);
  await A.registerPassport(sub.passport);

  const wide = await agent.delegate({ sub: sub.did, caps: [{ action: 'payments.*', resource: '*' }], budget: { amount: 100, currency: 'USD' } });
  await assert.rejects(A.registerMandate(wide), /widens scope/);
  const rich = await agent.delegate({ sub: sub.did, caps: [{ action: 'payments.send', resource: 'vendor:x', limits: { amount: { max: 500 }, currency: { in: ['USD'] } } }], budget: { amount: 9000, currency: 'USD' } });
  await assert.rejects(A.registerMandate(rich), /budget/);

  sub.mandate = await agent.delegate({ sub: sub.did, caps: [{ action: 'payments.send', resource: 'vendor:x', limits: { amount: { max: 800 }, currency: { in: ['USD'] } } }], budget: { amount: 1500, currency: 'USD' } });
  await A.registerMandate(sub.mandate);
  const host = await Attestor.create('h2');
  await A.endorseAttestor(await org.endorseAttestor(host));
  sub.attestation = await host.attest(sub.did, sub.manifest);

  assert.equal((await A.verifyIntent(await pay(agent, 800))).decision, 'allow');
  assert.equal((await A.verifyIntent(await pay(sub, 600))).decision, 'allow');
  const r = await A.verifyIntent(await pay(sub, 200));
  assert.equal(r.failedAt, 'budget', 'parent budget is consumed by sub-agent spend');
});

test('co-sign: hold, approve with principal key, receipt carries cosigner', async () => {
  const { A, org, agent } = await setup();
  const r = await A.verifyIntent(await pay(agent, 700));
  assert.equal(r.decision, 'step_up');
  const ap = A.s.approvals[r.approvalId];
  assert.equal(A.s.spend[agent.mandate.id].reserved, 700);
  const stranger = await Principal.create({ name: 'Stranger' });
  await assert.rejects(A.resolveApproval(await stranger.cosign(ap)), /not allowed/);
  const done = await A.resolveApproval(await org.cosign(ap));
  assert.equal(done.status, 'approved');
  assert.equal(done.decision.decision, 'allow');
  assert.deepEqual(done.decision.receipt.cosigners, [org.did]);
  assert.equal(A.s.spend[agent.mandate.id].spent, 700);
  assert.equal(A.s.spend[agent.mandate.id].reserved, 0);
});

test('co-sign: guardian quorum of 2 of 3', async () => {
  const guardians = await Promise.all([1, 2, 3].map(() => Principal.create({ name: 'g' })));
  const { A, agent } = await setup({ quorum: { k: 2, of: guardians.map((g) => g.did) } });
  const r = await A.verifyIntent(await pay(agent, 600));
  const ap = A.s.approvals[r.approvalId];
  assert.equal((await A.resolveApproval(await guardians[0].cosign(ap))).status, 'pending');
  assert.equal((await A.resolveApproval(await guardians[2].cosign(ap))).status, 'approved');
});

test('revocation cascades to sub-agents and pending approvals', async () => {
  const { A, org, agent, host } = await setup();
  const sub = await AgentRuntime.create({ name: 'Sub', purpose: 'p', model: 'm2', manifest: { model: 'm2', tools: [] } });
  sub.passport = await agent.issuePassport(sub);
  await A.registerPassport(sub.passport);
  sub.mandate = await agent.delegate({ sub: sub.did, caps: [{ action: 'payments.send', resource: 'vendor:x', limits: { amount: { max: 100 }, currency: { in: ['USD'] } } }], budget: { amount: 100, currency: 'USD' } });
  await A.registerMandate(sub.mandate);
  sub.attestation = await host.attest(sub.did, sub.manifest);

  const held = await A.verifyIntent(await pay(agent, 900));
  assert.equal(held.decision, 'step_up');
  const res = await A.revoke(await org.revoke(agent.did, 'key compromise'));
  assert.equal(res.agents.length, 2);
  assert.equal(A.s.approvals[held.approvalId].status, 'declined');
  assert.equal((await A.verifyIntent(await pay(sub, 50))).failedAt, 'identity');
  const outsider = await Principal.create({ name: 'x' });
  await assert.rejects(A.revoke(await outsider.revoke(sub.did)), /issuer/);
});

test('ledger: chain verifies, and any edit is detected', async () => {
  const { A, agent } = await setup();
  await A.verifyIntent(await pay(agent, 10));
  await A.verifyIntent(await pay(agent, 20));
  const ok = await A.verifyLedger();
  assert.ok(ok.ok);
  const copy = structuredClone(A.ledger.entries);
  copy[3].data.amount = 1;
  const bad = await verifyChain(copy, A.did);
  assert.equal(bad.ok, false);
  assert.equal(bad.brokenAt, 3);
});

test('authority state survives export and restore', async () => {
  const { A, agent } = await setup();
  await A.verifyIntent(await pay(agent, 10));
  const B = await Authority.restore(JSON.parse(JSON.stringify(A.export())));
  assert.equal(B.did, A.did);
  assert.ok((await B.verifyLedger()).ok);
  assert.equal((await B.verifyIntent(await pay(agent, 10))).decision, 'allow');
});

test('demo world: every scripted attack lands where the console says it will', async () => {
  const w = await DemoWorld.create();
  for (let i = 0; i < 12; i++) await w.tick();
  const expected = { cosign: ['step_up', 'cosign'], replay: ['deny', 'freshness'], forged: ['deny', 'signature'], injection: ['deny', 'limits'], subtle: ['step_up', 'cosign'], tamper: ['deny', 'runtime'], escalate: ['deny', 'scope'], runaway: ['deny', 'budget'] };
  for (const a of ATTACKS) {
    const r = await w.attack(a.id);
    assert.deepEqual([r.decision, r.failedAt], expected[a.id], `${a.id}: ${JSON.stringify(r.checks.filter((c) => c.status !== 'pass'))}`);
  }
  const pending = w.snapshot().approvals.filter((x) => x.status === 'pending');
  assert.equal(pending.length, 2);
  const res = await w.approve(pending[0].id);
  assert.equal(res.status, 'approved');
  const wide = await w.delegate({ caps: [{ action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 5000 }, currency: { in: ['USD'] } } }] });
  assert.equal(wide.ok, false);
  const rev = await w.revoke('ledgerline', 'test');
  assert.equal(rev.agents.length, 2);
  assert.ok((await w.verifyLedger()).ok);
  const restored = await DemoWorld.restore(JSON.parse(JSON.stringify(w.export())));
  assert.equal(restored.statusOfAgent('quill'), 'revoked');
});
