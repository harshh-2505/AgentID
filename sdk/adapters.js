// Wrap any agent tool so it runs only with an AgentID receipt.
//
//   const pay = withAgentID(sendPayment, {
//     client, agent, action: 'payments.send',
//     resource: (a) => 'vendor:' + a.vendor,
//     params: (a) => ({ amount: a.amount, currency: 'USD' }),
//   });
//   await pay({ vendor: 'acme', amount: 120 });   // sendPayment(args, { receipt, decision })
//
// `client` is an AuthorityClient or anything with verifyIntent(intent) and approval(id),
// such as an in-process core Authority.

import { verifyReceipt } from '../core/authority.js';

export class AgentIDDenied extends Error {
  constructor(decision) {
    const check = decision.checks?.find((c) => c.status === 'fail' || c.status === 'hold');
    const detail = decision.note || check?.detail || '';
    super(`AgentID denied ${decision.action} on ${decision.resource}` + (decision.failedAt ? ` at ${decision.failedAt}` : '') + (detail ? `: ${detail}` : ''));
    this.name = 'AgentIDDenied';
    this.decision = decision;
    this.failedAt = decision.failedAt ?? null;
    this.detail = detail;
  }
}

// The request needed a co-sign and nobody answered in time.
export class AgentIDTimeout extends AgentIDDenied {
  constructor(decision) {
    super(decision);
    this.name = 'AgentIDTimeout';
  }
}

// The HTTP API returns { status, decision, receipt }; a core Authority returns the raw
// approval record, whose decision is only referenced by id. Both settle the same way.
async function settle(client, first, { timeoutMs = 120_000, pollMs = 1000, onHold } = {}) {
  if (first.decision !== 'step_up') return first;
  await onHold?.(first);
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, Math.min(pollMs, Math.max(0, until - Date.now()))));
    const ap = (await client.approval(first.approvalId)) || {};
    // An approval can read as approved a moment before its decision and receipt land.
    if (ap.status === 'pending' || (ap.status === 'approved' && !ap.receipt)) continue;
    if (ap.decision) return { ...ap.decision, receipt: ap.receipt };
    if (ap.status === 'approved' && ap.receipt) return { ...first, decision: 'allow', failedAt: null, receipt: ap.receipt };
    return { ...first, decision: 'deny', failedAt: 'cosign', note: ap.note || ap.status };
  }
  return { ...first, decision: 'deny', failedAt: 'cosign', timedOut: true };
}

// Sends one intent, waits out a step_up, and resolves to the allow decision or throws.
// Pass `authority` (its did) to also check the receipt before trusting it.
export async function authorize(client, agent, req, { authority, ...wait } = {}) {
  const d = await settle(client, await client.verifyIntent(await agent.intent(req)), wait);
  if (d.decision !== 'allow') throw new (d.timedOut ? AgentIDTimeout : AgentIDDenied)(d);
  if (authority) {
    const v = await verifyReceipt(d.receipt, authority, { aud: req.aud });
    if (!v.ok) throw new AgentIDDenied({ ...d, decision: 'deny', failedAt: 'receipt', note: v.reason });
  }
  return d;
}

const at = (v, args) => (typeof v === 'function' ? v(args) : v);

// `resource`, `params` and `reason` are values or functions of the tool's first argument.
// The tool is called as toolFn(args, { receipt, decision }, ...rest).
export function withAgentID(toolFn, { client, agent, action, resource, params = (a) => a ?? {}, reason = '', aud = 'any', ttlSec, timeoutMs, pollMs, onHold, authority }) {
  return async function guarded(args, ...rest) {
    const req = { action, resource: at(resource, args), params: at(params, args), reason: at(reason, args), aud, ttlSec };
    const decision = await authorize(client, agent, req, { timeoutMs, pollMs, onHold, authority });
    return toolFn.call(this, args, { receipt: decision.receipt, decision }, ...rest);
  };
}

// Same wrapper, options first: guardTool({ client, agent, action, ... })(toolFn).
export const guardTool = (opts) => (toolFn) => withAgentID(toolFn, opts);
