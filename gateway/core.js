// MCP gateway: every tools/call an MCP client makes becomes a signed AgentID intent.
//
// The gateway sits between an MCP client and an MCP server. It holds the agent's key
// (the model never sees it), asks the authority about each tool call, and forwards
// only what the authority allows, with the signed receipt attached so the server can
// check it too. Everything that is not a tool call passes through untouched.

import { authorize } from '../core/policy.js';

export const INTENT_META = 'agentid/intent';
export const RECEIPT_META = 'agentid/receipt';
export const INTENT_HEADER = 'x-agentid-intent';
export const DENIED = -32001;
export const STEP_UP = -32002;

const header = (headers, name) => {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() === name) return Array.isArray(v) ? v[0] : v;
  return undefined;
};

const rpcError = (id, code, message, data) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message, data } });
const summary = (checks = []) => checks.map(({ key, status, detail }) => ({ key, status, detail }));

// options:
//   verify          async (intent) => decision; Authority#verifyIntent or AuthorityClient#verifyIntent
//   agent           AgentRuntime (anything with intent() and, for tool filtering, mandate.caps)
//   server          the upstream server's name, used in the default action and resource
//   mapCall         (tool, args) => ({ action, resource, params }) to map tools onto your own vocabulary
//   aud             audience written into each intent (defaults to the resource)
//   approval        async (id) => approval record ({ status, receipt }); needed for waitForApproval
//   waitForApproval { timeoutMs, pollMs } hold a step_up call until the co-sign resolves
//   filterTools     hide tools the mandate cannot reach from tools/list responses
//   onDecision      (decision, call) => void, for logging
export function createGateway({ verify, agent, server, mapCall, aud, approval, waitForApproval, filterTools = false, onDecision } = {}) {
  if (typeof verify !== 'function') throw new Error('createGateway needs a verify function');
  if (!agent?.intent) throw new Error('createGateway needs an agent that can sign intents');
  if (!server) throw new Error('createGateway needs a server name');
  if (waitForApproval && typeof approval !== 'function') throw new Error('waitForApproval needs an approval(id) lookup');
  const map = mapCall || ((tool, args) => ({ action: `mcp.tool:${server}/${tool}`, resource: `mcp:${server}/${tool}`, params: args }));
  // tools/list request ids awaiting a response; responses are filtered against the mandate.
  const listIds = new Set();

  async function settle(first) {
    const { timeoutMs = 120_000, pollMs = 1000 } = waitForApproval === true ? {} : waitForApproval;
    const until = Date.now() + timeoutMs;
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, pollMs));
      const ap = await approval(first.approvalId);
      if (!ap || ap.status === 'pending') continue;
      if (ap.status === 'approved' && ap.receipt) return { ...first, decision: 'allow', failedAt: null, receipt: ap.receipt };
      return { ...first, decision: 'deny', failedAt: 'cosign', note: ap.status };
    }
    return { ...first, decision: 'deny', failedAt: 'cosign', note: 'timed out waiting for co-sign' };
  }

  async function handleMessage(msg, headers = {}) {
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return { forward: msg };
    if (msg.method === 'tools/list' && filterTools && msg.id !== undefined) listIds.add(msg.id);
    if (msg.method !== 'tools/call') return { forward: msg };

    const tool = msg.params?.name;
    if (typeof tool !== 'string') return { respond: rpcError(msg.id, -32602, 'tools/call needs a tool name') };
    const args = msg.params.arguments ?? {};
    const reason = msg.params._meta?.[INTENT_META] ?? header(headers, INTENT_HEADER) ?? '';
    let decision;
    try {
      const { action, resource, params } = map(tool, args);
      decision = await verify(await agent.intent({ action, resource, params: params ?? {}, reason: String(reason), aud: aud ?? resource }));
      if (decision.decision === 'step_up' && waitForApproval) decision = await settle(decision);
    } catch (e) {
      // Fail closed: no answer from the authority is never an allow.
      return { respond: rpcError(msg.id, DENIED, `AgentID could not verify this call: ${e.message}`, { decision: 'deny', failedAt: 'authority' }) };
    }
    onDecision?.(decision, { tool, args });

    if (decision.decision === 'allow') {
      const params = { ...msg.params, _meta: { ...msg.params._meta, [RECEIPT_META]: decision.receipt } };
      return { forward: { ...msg, params }, decision };
    }
    const failed = decision.checks?.find((c) => c.key === decision.failedAt);
    const data = { decision: decision.decision, failedAt: decision.failedAt, decisionId: decision.id, checks: summary(decision.checks) };
    if (decision.decision === 'step_up') {
      return { respond: rpcError(msg.id, STEP_UP, `AgentID is holding ${tool} for a co-sign: ${failed?.detail || 'approval required'}`, { ...data, approvalId: decision.approvalId }), decision };
    }
    return { respond: rpcError(msg.id, DENIED, `AgentID denied ${tool}: ${failed?.detail || decision.note || 'not allowed'}`, data), decision };
  }

  // A tool is visible when some capability covers its action and resource; limits are
  // left to call time because they depend on the arguments.
  function canReach(tool) {
    const { action, resource } = map(tool, {});
    const caps = agent.mandate?.caps || [];
    return authorize(caps, action, resource, {}).stage !== 'scope';
  }

  // Rewrites a server → client message. Only tools/list results we asked to filter change.
  function filterResponse(msg) {
    if (!filterTools || !msg || typeof msg !== 'object' || Array.isArray(msg) || !listIds.has(msg.id)) return msg;
    listIds.delete(msg.id);
    if (!Array.isArray(msg.result?.tools)) return msg;
    return { ...msg, result: { ...msg.result, tools: msg.result.tools.filter((t) => canReach(t.name)) } };
  }

  return { handleMessage, filterResponse, canReach };
}
