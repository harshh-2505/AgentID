// ILLUSTRATIVE ONLY: not executed by the test suite.
// Needs `npm i @anthropic-ai/claude-agent-sdk zod` and an ANTHROPIC_API_KEY.
//
// Claude Agent SDK: an in-process MCP tool whose handler runs only with an AgentID receipt.

import { readFile } from 'node:fs/promises';
import { query, tool, createSdkMcpServer } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';
// package.json exports only 'agentid' and 'agentid/sdk', so the adapters are imported by path.
import { AgentRuntime, AuthorityClient, encodeReceipt, RECEIPT_HEADER } from '../../sdk/index.js';
import { withAgentID, AgentIDDenied } from '../../sdk/adapters.js';

const agent = await AgentRuntime.restore(JSON.parse(await readFile('agent.json', 'utf8')));
const client = new AuthorityClient('http://localhost:4600');

const pay = withAgentID(async ({ vendor, amount }: { vendor: string; amount: number }, { receipt }) => {
  const res = await fetch('http://localhost:4700/pay', {
    method: 'POST',
    headers: { 'content-type': 'application/json', [RECEIPT_HEADER]: encodeReceipt(receipt) },
    body: JSON.stringify({ vendor, amount }),
  });
  return (await res.json()).message;
}, {
  client, agent, action: 'payments.send', aud: 'payments', timeoutMs: 300_000,
  resource: (a) => 'vendor:' + a.vendor,
  params: (a) => ({ amount: a.amount, currency: 'USD' }),
  reason: (a) => `Claude agent paying ${a.vendor}`,
});

const payments = createSdkMcpServer({
  name: 'payments', version: '1.0.0',
  tools: [tool('pay_vendor', 'Pay a carrier invoice in USD', { vendor: z.string(), amount: z.number() }, async (args) => {
    try {
      return { content: [{ type: 'text', text: await pay(args) }] };
    } catch (e) {
      if (!(e instanceof AgentIDDenied)) throw e;
      return { content: [{ type: 'text', text: 'Not authorized: ' + e.message }], isError: true };
    }
  })],
});

for await (const msg of query({
  prompt: 'Pay blue-line 320 USD for invoice CI-118.',
  options: { model: 'claude-opus-5-5', mcpServers: { payments }, allowedTools: ['mcp__payments__pay_vendor'] },
})) {
  if (msg.type === 'result' && msg.subtype === 'success') console.log(msg.result);
}
