import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { writeFile, rm } from 'node:fs/promises';
import { PassThrough } from 'node:stream';
import { Authority, Principal, Attestor, AgentRuntime, verifyReceipt } from '../core/index.js';
import { createGateway, RECEIPT_META, INTENT_META, DENIED, STEP_UP } from '../gateway/core.js';
import { createHttpProxy } from '../gateway/http.js';
import { runStdio } from '../gateway/stdio.js';

async function setup() {
  const A = await Authority.create();
  const org = await Principal.create({ name: 'Acme' });
  const host = await Attestor.create('Acme host');
  await A.registerPrincipal(await org.registration());
  await A.endorseAttestor(await org.endorseAttestor(host));
  const agent = await AgentRuntime.create({ name: 'Reader', purpose: 'reads files', model: 'm1', manifest: { model: 'm1', tools: ['files'] } });
  agent.passport = await org.issuePassport(agent);
  await A.registerPassport(agent.passport);
  agent.mandate = await org.issueMandate({
    sub: agent.did,
    caps: [{ action: 'mcp.tool:files/read_*', resource: 'mcp:files/*', limits: { path: { match: ['/srv/*'] } } }],
    cosign: { actions: ['mcp.tool:files/read_secret*'] },
  });
  await A.registerMandate(agent.mandate);
  agent.attestation = await host.attest(agent.did, agent.manifest);
  return { A, org, agent };
}

const call = (id, name, args, reason = 'summarise the report') => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args, _meta: { [INTENT_META]: reason } } });
const TOOLS = [{ name: 'read_file' }, { name: 'read_secret' }, { name: 'write_file' }];

async function listen(server) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${server.address().port}/mcp`;
}

test('gateway: allow forwards the call with a verifiable receipt', async () => {
  const { A, agent } = await setup();
  const gw = createGateway({ verify: (i) => A.verifyIntent(i), agent, server: 'files' });
  const r = await gw.handleMessage(call(1, 'read_file', { path: '/srv/report.txt' }));
  assert.ok(r.forward, JSON.stringify(r.respond));
  const receipt = r.forward.params._meta[RECEIPT_META];
  assert.equal(receipt.action, 'mcp.tool:files/read_file');
  assert.equal(receipt.resource, 'mcp:files/read_file');
  assert.deepEqual(receipt.params, { path: '/srv/report.txt' });
  assert.ok((await verifyReceipt(receipt, A.did, { aud: 'mcp:files/read_file' })).ok);
  assert.equal(r.forward.params.arguments.path, '/srv/report.txt', 'arguments are forwarded untouched');
});

test('gateway: the stated reason comes from _meta, else the header', async () => {
  const { A, agent } = await setup();
  const seen = [];
  const gw = createGateway({ verify: (i) => { seen.push(i.reason); return A.verifyIntent(i); }, agent, server: 'files' });
  await gw.handleMessage(call(1, 'read_file', { path: '/srv/a' }, 'from meta'), { 'x-agentid-intent': 'from header' });
  const { _meta, ...params } = call(2, 'read_file', { path: '/srv/b' }).params;
  await gw.handleMessage({ jsonrpc: '2.0', id: 2, method: 'tools/call', params }, { 'X-AgentID-Intent': 'from header' });
  assert.deepEqual(seen, ['from meta', 'from header']);
});

test('gateway: deny out of scope or over limits with -32001 and the trace', async () => {
  const { A, agent } = await setup();
  const gw = createGateway({ verify: (i) => A.verifyIntent(i), agent, server: 'files' });
  const scope = await gw.handleMessage(call(7, 'write_file', { path: '/srv/x' }));
  assert.equal(scope.respond.id, 7);
  assert.equal(scope.respond.error.code, DENIED);
  assert.equal(scope.respond.error.data.failedAt, 'scope');
  assert.equal(scope.respond.error.data.checks.length, 10);
  const limits = await gw.handleMessage(call(8, 'read_file', { path: '/etc/passwd' }));
  assert.equal(limits.respond.error.data.failedAt, 'limits');
});

test('gateway: step_up answers -32002, or waits for the co-sign when asked', async () => {
  const { A, org, agent } = await setup();
  const gw = createGateway({ verify: (i) => A.verifyIntent(i), agent, server: 'files' });
  const held = await gw.handleMessage(call(3, 'read_secret', { path: '/srv/keys' }));
  assert.equal(held.respond.error.code, STEP_UP);
  assert.ok(held.respond.error.data.approvalId);

  const waiting = createGateway({ verify: (i) => A.verifyIntent(i), agent, server: 'files', approval: (id) => A.approval(id), waitForApproval: { pollMs: 10, timeoutMs: 5000 } });
  const pending = waiting.handleMessage(call(4, 'read_secret', { path: '/srv/keys' }));
  const ap = await findPending(A, held.respond.error.data.approvalId);
  await A.resolveApproval(await org.cosign(ap));
  const r = await pending;
  assert.ok(r.forward, JSON.stringify(r.respond));
  assert.deepEqual(r.forward.params._meta[RECEIPT_META].cosigners, [org.did]);
});

// Finds the newest pending approval other than `skip`, via the store.
async function findPending(A, skip) {
  for (let i = 0; i < 500; i++) {
    const all = await A.store.read((tx) => tx.list('approval'));
    const ap = all.find((a) => a.status === 'pending' && a.id !== skip);
    if (ap) return ap;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('no pending approval appeared');
}

test('gateway: non tool calls pass through; tools/list can be filtered to the mandate', async () => {
  const { agent } = await setup();
  const gw = createGateway({ verify: () => assert.fail('must not verify'), agent, server: 'files', filterTools: true });
  for (const msg of [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  ]) assert.deepEqual((await gw.handleMessage(msg)).forward, msg);
  const filtered = gw.filterResponse({ jsonrpc: '2.0', id: 2, result: { tools: TOOLS } });
  assert.deepEqual(filtered.result.tools.map((t) => t.name), ['read_file', 'read_secret']);
  const other = { jsonrpc: '2.0', id: 9, result: { tools: TOOLS } };
  assert.equal(gw.filterResponse(other), other, 'only responses to tools/list requests are touched');
});

test('gateway: fails closed when the authority is unreachable', async () => {
  const { agent } = await setup();
  const gw = createGateway({ verify: async () => { throw new Error('ECONNREFUSED'); }, agent, server: 'files' });
  const r = await gw.handleMessage(call(1, 'read_file', { path: '/srv/a' }));
  assert.equal(r.respond.error.code, DENIED);
  assert.equal(r.respond.error.data.failedAt, 'authority');
});

test('gateway/http: end to end through a Streamable HTTP upstream (JSON, SSE, batch, session id)', async (t) => {
  const { A, agent } = await setup();
  const received = [];
  const upstream = http.createServer(async (req, res) => {
    let body = '';
    for await (const c of req) body += c;
    const parsed = JSON.parse(body);
    received.push(parsed);
    const msgs = Array.isArray(parsed) ? parsed : [parsed];
    const answer = (m) => (m.method === 'tools/list' ? { jsonrpc: '2.0', id: m.id, result: { tools: TOOLS } }
      : { jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: `ran ${m.params?.name ?? m.method}` }], sawReceipt: !!m.params?._meta?.[RECEIPT_META] } });
    const replies = msgs.filter((m) => m.id !== undefined).map(answer);
    if (!replies.length) { res.writeHead(202); return res.end(); }
    if (msgs.some((m) => m.method === 'tools/call')) {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'mcp-session-id': 'sess-1' });
      // Split events across writes to exercise partial-event buffering.
      for (const r of replies) { const s = `event: message\ndata: ${JSON.stringify(r)}\n\n`; res.write(s.slice(0, 10)); res.write(s.slice(10)); }
      return res.end();
    }
    res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': 'sess-1' });
    res.end(JSON.stringify(Array.isArray(parsed) ? replies : replies[0]));
  });
  const upUrl = await listen(upstream);
  const gw = createGateway({ verify: (i) => A.verifyIntent(i), agent, server: 'files', filterTools: true });
  const proxy = createHttpProxy({ gateway: gw, upstream: upUrl });
  const url = await listen(proxy);
  t.after(() => { upstream.close(); proxy.close(); });
  const post = (body, headers = {}) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers }, body: JSON.stringify(body) });
  const events = (text) => text.split('\n').filter((l) => l.startsWith('data:')).map((l) => JSON.parse(l.slice(5)));

  const list = await post({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.equal(list.headers.get('mcp-session-id'), 'sess-1');
  assert.deepEqual((await list.json()).result.tools.map((t) => t.name), ['read_file', 'read_secret']);

  const ok = await post(call(2, 'read_file', { path: '/srv/a' }), { 'mcp-session-id': 'sess-1' });
  assert.match(ok.headers.get('content-type'), /text\/event-stream/);
  const [okMsg] = events(await ok.text());
  assert.equal(okMsg.result.sawReceipt, true);

  const before = received.length;
  const denied = await (await post(call(3, 'write_file', { path: '/srv/a' }))).json();
  assert.equal(denied.error.code, DENIED);
  assert.equal(received.length, before, 'a denied call never reaches the upstream');

  const batch = await post([call(4, 'read_file', { path: '/srv/b' }), call(5, 'write_file', { path: '/srv/b' }), { jsonrpc: '2.0', method: 'notifications/progress' }]);
  const out = events(await batch.text());
  assert.deepEqual(out.map((m) => m.id).sort(), [4, 5]);
  assert.equal(out.find((m) => m.id === 5).error.code, DENIED);
  assert.deepEqual(received.at(-1).map((m) => m.id ?? m.method), [4, 'notifications/progress']);

  const note = await post({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(note.status, 202);
});

const FAKE_SERVER = `
import readline from 'node:readline';
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  const m = JSON.parse(line);
  if (m.id === undefined) return;
  const result = m.method === 'tools/list'
    ? { tools: ${JSON.stringify(TOOLS)} }
    : { content: [{ type: 'text', text: 'ran ' + (m.params?.name ?? m.method) }], sawReceipt: !!m.params?._meta?.['${RECEIPT_META}'] };
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result }) + '\\n');
});
`;

test('gateway/stdio: wraps a stdio MCP server', async (t) => {
  const { A, agent } = await setup();
  const script = path.join(os.tmpdir(), `agentid-fake-mcp-${process.pid}-${Date.now()}.mjs`);
  await writeFile(script, FAKE_SERVER);
  t.after(() => rm(script, { force: true }));

  const input = new PassThrough();
  const output = new PassThrough();
  const gw = createGateway({ verify: (i) => A.verifyIntent(i), agent, server: 'files', filterTools: true });
  const { done } = runStdio({ gateway: gw, command: process.execPath, args: [script], input, output });

  const replies = new Map();
  let buf = '';
  output.on('data', (c) => {
    buf += c;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); replies.set(m.id, m); }
  });
  const send = (m) => input.write(JSON.stringify(m) + '\n');
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  send(call(3, 'read_file', { path: '/srv/a' }));
  send(call(4, 'write_file', { path: '/srv/a' }));
  send(call(5, 'read_secret', { path: '/srv/k' }));
  input.end();
  const { code } = await done;
  assert.equal(code, 0);

  assert.ok(replies.get(1).result, 'initialize passes through');
  assert.deepEqual(replies.get(2).result.tools.map((t) => t.name), ['read_file', 'read_secret']);
  assert.equal(replies.get(3).result.sawReceipt, true);
  assert.equal(replies.get(4).error.code, DENIED);
  assert.equal(replies.get(5).error.code, STEP_UP);
});
