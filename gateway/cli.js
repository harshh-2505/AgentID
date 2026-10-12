#!/usr/bin/env node
// AgentID MCP gateway.
//
//   node gateway/cli.js --agent agent.json --upstream http://localhost:3000/mcp [--port 4710]
//   node gateway/cli.js --agent agent.json --stdio "npx some-mcp-server --flag"
//
// Options: --authority URL (default http://localhost:4600), --server NAME (default
// derived from the upstream), --wait (hold step_up calls until co-signed), --filter-tools.
// agent.json is AgentRuntime.export(): the key stays in this process, never in the model.

import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { AgentRuntime, AuthorityClient } from '../sdk/index.js';
import { createGateway } from './core.js';
import { createHttpProxy } from './http.js';
import { runStdio } from './stdio.js';

const { values: o } = parseArgs({
  options: {
    agent: { type: 'string' }, authority: { type: 'string', default: 'http://localhost:4600' },
    upstream: { type: 'string' }, stdio: { type: 'string' }, server: { type: 'string' },
    port: { type: 'string', default: '4710' }, wait: { type: 'boolean' }, 'filter-tools': { type: 'boolean' },
  },
});
const die = (msg) => { process.stderr.write(msg + '\n'); process.exit(64); };
if (!o.agent || !!o.upstream === !!o.stdio) die('usage: cli.js --agent agent.json (--upstream URL | --stdio "cmd args") [--authority URL] [--server name] [--port n] [--wait] [--filter-tools]');

const words = (s) => (s.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((w) => w.replace(/^(["'])(.*)\1$/, '$2'));
const command = o.stdio ? words(o.stdio) : null;
const server = o.server || (o.upstream ? new URL(o.upstream).hostname : command[command.length - 1].split('/').pop()).replace(/[^\w.-]/g, '_');

const agent = await AgentRuntime.restore(JSON.parse(await readFile(o.agent, 'utf8')));
const client = new AuthorityClient(o.authority);
// Logs go to stderr: in stdio mode stdout belongs to the MCP protocol.
const log = (d, { tool }) => process.stderr.write(`[agentid] ${d.decision.toUpperCase()} ${server}/${tool}${d.failedAt ? ' at ' + d.failedAt : ''}\n`);
const gateway = createGateway({
  verify: (intent) => client.verifyIntent(intent), approval: (id) => client.approval(id),
  agent, server, waitForApproval: o.wait ? {} : null, filterTools: o['filter-tools'], onDecision: log,
});

if (o.upstream) {
  createHttpProxy({ gateway, upstream: o.upstream }).listen(Number(o.port), () => process.stderr.write(`[agentid] gateway for ${server} on http://localhost:${o.port}/mcp → ${o.upstream}\n`));
} else {
  const { done } = runStdio({ gateway, command: command[0], args: command.slice(1) });
  done.then(({ code }) => process.exit(code ?? 1));
}
