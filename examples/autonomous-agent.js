// An autonomous agent end to end, against a running authority (npm start).
//
// It plays three roles to keep the example self-contained: the organisation that
// vouches for the agent, the host that attests its runtime, and the agent itself.
// In production these are three different machines holding three different keys.

import { AgentRuntime, Principal, Attestor, AuthorityClient, encodeReceipt, RECEIPT_HEADER } from '../sdk/index.js';

const AUTHORITY = process.env.AGENTID_URL || 'http://localhost:4600';
const SERVICE = process.env.SERVICE_URL || 'http://localhost:4700';
const client = new AuthorityClient(AUTHORITY);
const c = { dim: '\x1b[2m', g: '\x1b[32m', y: '\x1b[33m', r: '\x1b[31m', b: '\x1b[1m', x: '\x1b[0m' };
const show = (label, d) => {
  const col = d.decision === 'allow' ? c.g : d.decision === 'step_up' ? c.y : c.r;
  const why = d.checks?.find((k) => k.status === 'fail' || k.status === 'hold');
  console.log(`${c.b}${label.padEnd(34)}${c.x} ${col}${d.decision.toUpperCase()}${c.x} ${c.dim}${why ? why.label + ': ' + why.detail : 'all checks passed'}${c.x}`);
};

// 1. The organisation registers and vouches for the host and the agent.
const org = await Principal.create({ name: 'Example Freight Co.' });
const host = await Attestor.create('Example host · k8s node pool A');
await client.registerPrincipal(await org.registration());
await client.endorseAttestor(await org.endorseAttestor(host));

const agent = await AgentRuntime.create({
  name: 'Ferry', purpose: 'Settles carrier invoices', model: 'claude-sonnet-5-5',
  manifest: { model: 'claude-sonnet-5-5', tools: ['payments.send'], code: 'ferry@1.2.0', systemPrompt: 'sha256:ferry-v1' },
});
agent.passport = await org.issuePassport(agent);
await client.registerPassport(agent.passport);
agent.mandate = await org.issueMandate({
  sub: agent.did, label: 'Carrier settlements',
  caps: [{ action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 2000 }, currency: { in: ['USD'] } } }],
  budget: { amount: 5000, currency: 'USD' }, cosign: { above: 500 },
});
await client.registerMandate(agent.mandate);
agent.attestation = await host.attest(agent.did, agent.manifest);
console.log(`\n${c.b}Ferry${c.x} ${c.dim}${agent.did}${c.x}\n`);

// 2. An ordinary payment: allowed, and the receipt unlocks the payments service.
const pay = (vendor, amount, reason) => ({ action: 'payments.send', resource: 'vendor:' + vendor, params: { amount, currency: 'USD' }, reason, aud: 'payments' });
const small = await client.act(agent, pay('blue-line', 320, 'Carrier invoice CI-118 delivered and signed'));
show('Pay 320 USD to blue-line', small);
await callService('blue-line', 320, small.receipt);
await callService('blue-line', 320, small.receipt, 'Reuse the same receipt');

// 3. A large payment: held until the organisation co-signs from its approval app.
const big = client.act(agent, pay('north-rail', 1400, 'Quarterly rail contract, PO 7731'), {
  onHold: (d) => {
    show('Pay 1,400 USD to north-rail', d);
    setTimeout(async () => {
      const request = await client.approvalRequest(d.approvalId);
      console.log(`${c.dim}  …principal reviews "${request.reason}" and co-signs${c.x}`);
      await client.cosign(await org.cosign(request, 'approve'));
    }, 1500);
  },
});
const bigResult = await big;
show('  after co-sign', bigResult);
await callService('north-rail', 1400, bigResult.receipt);

// 4. The agent is compromised: its tool list changes. The runtime check catches it.
agent.manifest = { ...agent.manifest, tools: [...agent.manifest.tools, 'shell.exec'] };
agent.attestation = await host.attest(agent.did, agent.manifest);
show('Pay after runtime tampering', await client.verifyIntent(await agent.intent(pay('blue-line', 90, 'Fuel surcharge'))));

// 5. The organisation pulls the agent. Everything it holds stops working at once.
await client.revoke(await org.revoke(agent.did, 'Runtime drift detected'));
agent.manifest = { ...agent.manifest, tools: ['payments.send'] };
agent.attestation = await host.attest(agent.did, agent.manifest);
show('Pay after revocation', await client.verifyIntent(await agent.intent(pay('blue-line', 90, 'Fuel surcharge'))));

const ledger = await client.verifyLedger();
console.log(`\nLedger ${ledger.ok ? c.g + 'intact' : c.r + 'BROKEN'}${c.x}: ${ledger.checked} entries verified.\n`);

async function callService(vendor, amount, receipt, label = `Call payments service (${amount})`) {
  if (!receipt) return;
  try {
    const res = await fetch(SERVICE + '/pay', {
      method: 'POST',
      headers: { 'content-type': 'application/json', [RECEIPT_HEADER]: encodeReceipt(receipt) },
      body: JSON.stringify({ vendor, amount }),
    });
    const body = await res.json();
    console.log(`  ${label.padEnd(32)} ${res.ok ? c.g + 'HTTP ' + res.status : c.r + 'HTTP ' + res.status}${c.x} ${c.dim}${body.message || body.error}${c.x}`);
  } catch {
    console.log(`  ${c.dim}(payments service not running; start it with npm run service)${c.x}`);
  }
}
