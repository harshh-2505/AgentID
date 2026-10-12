// AgentID SDK: what an agent, a principal's approval app, or a relying service imports.
//
//   import { AgentRuntime, Principal, AuthorityClient, requireReceipt } from 'agentid/sdk';

export { AgentRuntime, Principal, Attestor, measure } from '../core/actors.js';
export { verifyReceipt } from '../core/authority.js';
export { Signer, shortDid } from '../core/keys.js';
export { b64u, unb64u, utf8 } from '../core/encoding.js';

import { verifyReceipt } from '../core/authority.js';
import { b64u, unb64u, utf8 } from '../core/encoding.js';

export class AuthorityClient {
  constructor(baseUrl = 'http://localhost:4600') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async #call(method, path, body) {
    const res = await fetch(this.baseUrl + path, {
      method,
      headers: body ? { 'content-type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  discover() { return this.#call('GET', '/.well-known/agentid'); }
  registerPrincipal(reg) { return this.#call('POST', '/v1/principals', reg); }
  endorseAttestor(end) { return this.#call('POST', '/v1/attestors', end); }
  registerPassport(pp) { return this.#call('POST', '/v1/passports', pp); }
  registerMandate(m) { return this.#call('POST', '/v1/mandates', m); }
  verifyIntent(intent) { return this.#call('POST', '/v1/intents', intent); }
  approval(id) { return this.#call('GET', `/v1/approvals/${encodeURIComponent(id)}`); }
  approvalRequest(id) { return this.#call('GET', `/v1/approvals/${encodeURIComponent(id)}/request`); }
  cosign(c) { return this.#call('POST', `/v1/approvals/${encodeURIComponent(c.approval)}/cosign`, c); }
  revoke(r) { return this.#call('POST', '/v1/revocations', r); }
  ledger(from = 0) { return this.#call('GET', `/v1/ledger?from=${from}`); }
  verifyLedger() { return this.#call('GET', '/v1/ledger/verify'); }

  // Submits an intent and, when the authority holds it for a co-sign, waits for
  // the outcome. Agents never block on a human directly; they block on this.
  async act(agent, req, { timeoutMs = 120_000, pollMs = 1000, onHold } = {}) {
    const first = await this.verifyIntent(await agent.intent(req));
    if (first.decision !== 'step_up') return first;
    onHold?.(first);
    const until = Date.now() + timeoutMs;
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, pollMs));
      const ap = await this.approval(first.approvalId);
      if (ap.status !== 'pending') return ap.decision ? { ...ap.decision, receipt: ap.receipt } : { ...first, decision: 'deny', failedAt: 'cosign', note: ap.status };
    }
    return { ...first, decision: 'deny', failedAt: 'cosign', timedOut: true };
  }
}

// Receipts travel to the relying service in one header.
export const RECEIPT_HEADER = 'agentid-receipt';
export const encodeReceipt = (receipt) => b64u(utf8(JSON.stringify(receipt)));
export const decodeReceipt = (value) => JSON.parse(new TextDecoder().decode(unb64u(value)));

// Node http / Express style guard. `expect(req, receipt)` returns an error string
// when the receipt does not cover this specific request, or nothing when it does.
export function requireReceipt({ authority, aud, expect }) {
  const seen = new Map();
  return async (req, res, next) => {
    const reject = (status, error) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error }));
    };
    try {
      const raw = req.headers[RECEIPT_HEADER];
      if (!raw) return reject(401, 'missing AgentID receipt');
      const receipt = decodeReceipt(raw);
      const v = await verifyReceipt(receipt, authority, { aud });
      if (!v.ok) return reject(401, v.reason);
      if (seen.has(receipt.intent)) return reject(409, 'receipt already used');
      const problem = expect ? await expect(req, receipt) : null;
      if (problem) return reject(403, problem);
      seen.set(receipt.intent, Date.now());
      for (const [k, t] of seen) if (Date.now() - t > 600_000) seen.delete(k);
      req.agent = { did: receipt.agent, receipt };
      return next();
    } catch (e) {
      return reject(400, 'unreadable receipt: ' + e.message);
    }
  };
}
