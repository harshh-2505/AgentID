import test from 'node:test';
import assert from 'node:assert/strict';
import { Authority, Principal, Attestor, AgentRuntime, verifyReceipt } from '../core/index.js';
import { withAgentID, guardTool, AgentIDDenied, AgentIDTimeout } from '../sdk/adapters.js';

async function setup() {
  const A = await Authority.create();
  const org = await Principal.create({ name: 'Acme' });
  const host = await Attestor.create('Acme host');
  await A.registerPrincipal(await org.registration());
  await A.endorseAttestor(await org.endorseAttestor(host));
  const agent = await AgentRuntime.create({ name: 'Payer', purpose: 'pays', model: 'm1', manifest: { model: 'm1', tools: ['pay'] } });
  agent.passport = await org.issuePassport(agent);
  await A.registerPassport(agent.passport);
  agent.mandate = await org.issueMandate({
    sub: agent.did,
    caps: [{ action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 1000 }, currency: { in: ['USD'] } } }],
    budget: { amount: 5000, currency: 'USD' }, cosign: { above: 500 },
  });
  await A.registerMandate(agent.mandate);
  agent.attestation = await host.attest(agent.did, agent.manifest);

  const calls = [];
  const sendPayment = async (args, ctx) => { calls.push({ args, ctx }); return `paid ${args.amount} to ${args.vendor}`; };
  const opts = {
    client: A, agent, action: 'payments.send', aud: 'payments', authority: A.did, pollMs: 5,
    resource: (a) => 'vendor:' + a.vendor,
    params: (a) => ({ amount: a.amount, currency: 'USD' }),
    reason: (a) => `invoice ${a.invoice}`,
  };
  return { A, org, calls, sendPayment, opts };
}

test('adapter: allowed call runs the tool with a verifiable receipt', async () => {
  const { A, calls, sendPayment, opts } = await setup();
  const pay = withAgentID(sendPayment, opts);
  assert.equal(await pay({ vendor: 'acme', amount: 200, invoice: 'I-1' }), 'paid 200 to acme');
  const { ctx } = calls[0];
  assert.equal(ctx.decision.decision, 'allow');
  assert.equal(ctx.receipt.resource, 'vendor:acme');
  assert.deepEqual(ctx.receipt.params, { amount: 200, currency: 'USD' });
  assert.ok((await verifyReceipt(ctx.receipt, A.did, { aud: 'payments' })).ok);
});

test('adapter: denied call throws AgentIDDenied and never runs the tool', async () => {
  const { calls, sendPayment, opts } = await setup();
  const pay = guardTool(opts)(sendPayment);
  await assert.rejects(pay({ vendor: 'acme', amount: 5000, invoice: 'I-2' }), (e) => {
    assert.ok(e instanceof AgentIDDenied);
    assert.equal(e.failedAt, 'limits');
    assert.equal(e.decision.decision, 'deny');
    return true;
  });
  await assert.rejects(withAgentID(sendPayment, { ...opts, action: 'payments.refund' })({ vendor: 'acme', amount: 5 }), (e) => e.failedAt === 'scope');
  assert.equal(calls.length, 0);
});

test('adapter: step_up waits for the co-sign, then runs the tool', async () => {
  const { A, org, calls, sendPayment, opts } = await setup();
  let held = null;
  const pay = withAgentID(sendPayment, {
    ...opts,
    onHold: (d) => {
      held = d;
      setTimeout(async () => A.resolveApproval(await org.cosign(await A.approval(d.approvalId), 'approve')), 20);
    },
  });
  assert.equal(await pay({ vendor: 'acme', amount: 700, invoice: 'I-3' }), 'paid 700 to acme');
  assert.equal(held.decision, 'step_up');
  assert.equal(calls[0].ctx.receipt.params.amount, 700);
  assert.deepEqual(calls[0].ctx.receipt.cosigners, [org.did]);
});

test('adapter: a declined or unanswered co-sign throws', async () => {
  const { A, org, calls, sendPayment, opts } = await setup();
  const declined = withAgentID(sendPayment, {
    ...opts,
    onHold: (d) => setTimeout(async () => A.resolveApproval(await org.cosign(await A.approval(d.approvalId), 'decline')), 10),
  });
  await assert.rejects(declined({ vendor: 'acme', amount: 600, invoice: 'I-4' }), (e) => e instanceof AgentIDDenied && !(e instanceof AgentIDTimeout) && e.failedAt === 'cosign');
  const ignored = withAgentID(sendPayment, { ...opts, timeoutMs: 40 });
  await assert.rejects(ignored({ vendor: 'acme', amount: 600, invoice: 'I-5' }), AgentIDTimeout);
  assert.equal(calls.length, 0);
});
