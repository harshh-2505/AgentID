import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHmac } from 'node:crypto';
import { DemoWorld } from '../core/demo-world.js';
import * as slack from '../server/integrations/slack.js';
import * as teams from '../server/integrations/teams.js';
import { attachSiem } from '../server/integrations/siem.js';

const SECRET = '8f742231b10e8888abcd99yyyzzz85a5';

// Shared world: building one takes a moment, and each test only adds its own requests.
const world = await DemoWorld.create();
const A = world.authority;

function route(table, method, pattern) {
  const r = table.find(([m, p]) => m === method && p === pattern);
  assert.ok(r, `route ${method} ${pattern}`);
  return r[2];
}

function slackRequest(payload, { ts = Math.floor(Date.now() / 1000), secret = SECRET, sig } = {}) {
  const raw = 'payload=' + encodeURIComponent(JSON.stringify(payload));
  const signature = sig ?? 'v0=' + createHmac('sha256', secret).update(`v0:${ts}:${raw}`).digest('hex');
  return {
    body: Object.fromEntries(new URLSearchParams(raw)),
    req: { rawBody: Buffer.from(raw), headers: { 'x-slack-request-timestamp': String(ts), 'x-slack-signature': signature } },
  };
}

const click = (approvalId, user, actionId = 'agentid_approve') => ({
  type: 'block_actions', user: { id: user }, response_url: 'https://hooks.slack.test/actions/T1/123/abc',
  actions: [{ action_id: actionId, block_id: 'agentid_cosign', value: approvalId, type: 'button' }],
});

async function pendingApproval() {
  const r = await world.attack('cosign');
  assert.equal(r.decision, 'step_up', JSON.stringify(r.checks?.find((c) => c.status === 'fail')));
  return r.approvalId;
}

function slackCtx(extra = {}) {
  const posted = [];
  const post = async (url, opts) => { posted.push({ url, ...opts, json: JSON.parse(opts.body) }); return { ok: true, status: 200, text: '{"ok":true}' }; };
  const config = { slack: { signingSecret: SECRET, approvers: { U123: { key: 'approver' } }, post, ...extra } };
  const ctx = { authority: () => A, world: () => world, config, issuer: 'https://agentid.test' };
  return { ctx, posted, handler: route(slack.routes(ctx), 'POST', '/integrations/slack/actions') };
}

// ---------------------------------------------------------------- Slack

test('slack: signature valid, invalid, stale', () => {
  const raw = Buffer.from('payload=%7B%7D');
  const ts = Math.floor(Date.now() / 1000);
  const good = 'v0=' + createHmac('sha256', SECRET).update(`v0:${ts}:${raw}`).digest('hex');
  assert.ok(slack.verifySlackSignature({ signingSecret: SECRET, timestamp: ts, signature: good, rawBody: raw }).ok);
  assert.equal(slack.verifySlackSignature({ signingSecret: SECRET, timestamp: ts, signature: good.replace(/.$/, (c) => (c === '0' ? '1' : '0')), rawBody: raw }).reason, 'bad Slack signature');
  assert.equal(slack.verifySlackSignature({ signingSecret: 'other', timestamp: ts, signature: good, rawBody: raw }).reason, 'bad Slack signature');
  assert.equal(slack.verifySlackSignature({ signingSecret: SECRET, timestamp: ts, signature: 'v0=short', rawBody: raw }).reason, 'bad Slack signature');
  assert.equal(slack.verifySlackSignature({ signingSecret: SECRET, timestamp: ts, signature: good, rawBody: Buffer.from('payload=%7B%7D&x=1') }).reason, 'bad Slack signature');
  const old = ts - 301;
  const oldSig = 'v0=' + createHmac('sha256', SECRET).update(`v0:${old}:${raw}`).digest('hex');
  assert.equal(slack.verifySlackSignature({ signingSecret: SECRET, timestamp: old, signature: oldSig, rawBody: raw }).reason, 'stale Slack request');
  assert.ok(!slack.verifySlackSignature({ signingSecret: SECRET, timestamp: ts, rawBody: raw }).ok);
});

test('slack: the route rejects unsigned, mis-signed and replayed-late requests', async () => {
  const { handler } = slackCtx();
  const id = 'ap_doesnotmatter';
  const bad = slackRequest(click(id, 'U123'), { secret: 'wrong' });
  await assert.rejects(handler(bad.body, {}, {}, bad.req), (e) => e.status === 401 && /bad Slack signature/.test(e.message));
  const stale = slackRequest(click(id, 'U123'), { ts: Math.floor(Date.now() / 1000) - 600 });
  await assert.rejects(handler(stale.body, {}, {}, stale.req), (e) => e.status === 401 && /stale/.test(e.message));
  const { handler: noSecret } = slackCtx({ signingSecret: undefined });
  const ok = slackRequest(click(id, 'U123'));
  await assert.rejects(noSecret(ok.body, {}, {}, ok.req), (e) => e.status === 401);
});

test('slack: Approve click co-signs through the demo world and replaces the message', async () => {
  const id = await pendingApproval();
  const { handler, posted } = slackCtx();

  const stranger = slackRequest(click(id, 'U999'));
  const denied = await handler(stranger.body, {}, {}, stranger.req);
  assert.equal(denied.response_type, 'ephemeral');
  assert.equal(denied.replace_original, false);
  assert.equal((await A.approval(id)).status, 'pending', 'an unknown Slack user changes nothing');

  const { body, req } = slackRequest(click(id, 'U123'));
  const msg = await handler(body, {}, {}, req);
  assert.equal(msg.replace_original, true);
  assert.match(msg.text, /Approved by <@U123>/);
  assert.ok(!msg.blocks.some((b) => b.type === 'actions'), 'buttons are gone once decided');
  assert.ok(msg.blocks.some((b) => /Approved\* by <@U123>/.test(b.text?.text || '')));
  const ap = await A.approval(id);
  assert.equal(ap.status, 'approved');
  assert.equal(ap.signatures[0].kid, world.principal.keys.approver.did, 'signed with the mapped approver key');
  assert.equal(ap.receipt.type, 'Receipt');
  assert.equal(posted.at(-1).url, 'https://hooks.slack.test/actions/T1/123/abc', 'update also sent to response_url');
  assert.equal(posted.at(-1).json.replace_original, true);

  // A second click on the stale message shows the final state instead of an error loop.
  const again = slackRequest(click(id, 'U123'));
  const after = await handler(again.body, {}, {}, again.req);
  assert.equal(after.replace_original, true);
  assert.match(after.text, /already approved/);
});

test('slack: Decline click and the production cosign callback', async () => {
  const id = await pendingApproval();
  const calls = [];
  const { handler } = slackCtx({
    approvers: { U777: { key: 'operational', principalKeyRef: 'kms://op' } },
    cosign: async (approvalId, decision, approver, meta) => {
      calls.push({ approvalId, decision, approver, user: meta.slackUser });
      return world.approve(approvalId, decision, { key: approver.key });
    },
  });
  const { body, req } = slackRequest(click(id, 'U777', 'agentid_decline'));
  const msg = await handler(body, {}, {}, req);
  assert.match(msg.text, /Declined by <@U777>/);
  assert.deepEqual(calls, [{ approvalId: id, decision: 'decline', approver: { key: 'operational', principalKeyRef: 'kms://op' }, user: 'U777' }]);
  assert.equal((await A.approval(id)).status, 'declined');
});

test('slack: attachSlack posts one Block Kit message per new approval', async () => {
  const sent = [];
  const post = async (url, opts) => { sent.push({ url, opts, json: JSON.parse(opts.body) }); return { ok: true, status: 200, text: '{"ok":true,"ts":"1.2"}' }; };
  const off = slack.attachSlack(A, { slack: { botToken: 'xoxb-test', channel: 'C42', post, consoleUrl: 'https://agentid.test' } });
  try {
    const id = await pendingApproval();
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(sent.length, 1);
    const { url, opts, json } = sent[0];
    assert.equal(url, 'https://slack.com/api/chat.postMessage');
    assert.equal(opts.headers.authorization, 'Bearer xoxb-test');
    assert.equal(json.channel, 'C42');
    assert.match(json.text, /Co-sign needed: Ledgerline/);
    const actions = json.blocks.find((b) => b.type === 'actions');
    assert.deepEqual(actions.elements.map((e) => [e.action_id, e.value]), [['agentid_approve', id], ['agentid_decline', id]]);
    assert.ok(json.blocks.some((b) => b.type === 'section' && b.fields?.some((f) => /payments\.send/.test(f.text))));
    assert.ok(json.blocks.some((b) => b.type === 'section' && /amount above 750/.test(b.text?.text || '')), 'shows why it was held');
  } finally {
    off();
  }
});

test('slack: agent text is escaped in Block Kit', () => {
  const blocks = slack.approvalBlocks({ id: 'ap_1', agentName: 'X', action: 'a', resource: 'r', reason: '<!channel> click <https://evil|here> & pay', reasons: ['r'], risk: { score: 1, factors: [] } });
  const text = JSON.stringify(blocks);
  assert.ok(!text.includes('<!channel>'));
  assert.ok(text.includes('&lt;!channel&gt;'));
  assert.ok(text.includes('&amp; pay'));
});

// ---------------------------------------------------------------- Teams

test('teams: Adaptive Card shape and webhook message', async () => {
  const id = await pendingApproval();
  const ap = await A.approval(id);
  const card = teams.approvalCard(ap, { consoleUrl: 'https://agentid.test' });
  assert.equal(card.type, 'AdaptiveCard');
  assert.equal(card.version, '1.5');
  assert.ok(card.body.some((b) => b.type === 'FactSet' && b.facts.some((f) => f.title === 'Action' && f.value === 'payments.send')));
  const [approve, decline, open] = card.actions;
  assert.deepEqual([approve.type, approve.verb, approve.data], ['Action.Execute', 'agentid_approve', { approvalId: id, decision: 'approve' }]);
  assert.deepEqual([decline.type, decline.verb, decline.data.decision], ['Action.Execute', 'agentid_decline', 'decline']);
  assert.equal(open.type, 'Action.OpenUrl');
  const submit = teams.approvalCard(ap, { action: 'Submit' });
  assert.equal(submit.actions[0].type, 'Action.Submit');
  assert.equal(submit.actions[0].data.approvalId, id);

  const sent = [];
  await teams.postTeamsApproval(ap, { webhookUrl: 'https://teams.test/hook', post: async (url, o) => { sent.push(JSON.parse(o.body)); return { ok: true, status: 200 }; } });
  assert.equal(sent[0].type, 'message');
  assert.equal(sent[0].attachments[0].contentType, 'application/vnd.microsoft.card.adaptive');
  assert.equal(sent[0].attachments[0].content.type, 'AdaptiveCard');
});

test('teams: Action.Execute invoke needs the shared secret and an approver', async () => {
  const id = await pendingApproval();
  const ctx = { authority: () => A, world: () => world, config: { teams: { sharedSecret: 's3cret', approvers: { 'aad-1': { key: 'approver' } } } }, issuer: 'https://agentid.test' };
  const handler = route(teams.routes(ctx), 'POST', '/integrations/teams/actions');
  const invoke = (from) => ({ type: 'invoke', name: 'adaptiveCard/action', from, value: { action: { type: 'Action.Execute', verb: 'agentid_approve', data: { approvalId: id, decision: 'approve' } } } });
  await assert.rejects(handler(invoke({ aadObjectId: 'aad-1' }), {}, {}, { headers: {} }), (e) => e.status === 401);
  await assert.rejects(handler(invoke({ aadObjectId: 'aad-1' }), {}, {}, { headers: { 'x-agentid-teams-secret': 's3cret!' } }), (e) => e.status === 401);
  const h = { headers: { 'x-agentid-teams-secret': 's3cret' } };
  const nope = await handler(invoke({ aadObjectId: 'aad-2' }), {}, {}, h);
  assert.equal(nope.type, 'application/vnd.microsoft.activity.message');
  assert.equal((await A.approval(id)).status, 'pending');
  const res = await handler(invoke({ aadObjectId: 'aad-1', name: 'Okafor' }), {}, {}, h);
  assert.equal(res.statusCode, 200);
  assert.equal(res.type, 'application/vnd.microsoft.card.adaptive');
  assert.ok(res.value.body.some((b) => b.text === 'Approved by Okafor'));
  assert.ok(!res.value.actions.some((a) => a.type === 'Action.Execute'));
  assert.equal((await A.approval(id)).status, 'approved');
});

// ---------------------------------------------------------------- SIEM

async function sink(respond = () => 200) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const entry = { url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') };
    requests.push(entry);
    res.writeHead(respond(entry, requests.length));
    res.end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { requests, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

const parseConcatenated = (s) => s.trim().split('\n').map((l) => JSON.parse(l));

test('siem: webhook ships JSON lines in batches', async () => {
  const s = await sink();
  const siem = attachSiem(A, { kind: 'webhook', url: s.url + '/ingest', token: 'tok', batchMs: 60_000 });
  try {
    await world.act('quill', { action: 'invoices.read', resource: 'erp:northwind/inbox/INV-1', reason: 'extract line items', aud: 'erp' });
    await world.attack('escalate');
    await siem.flush();
    assert.equal(s.requests.length, 1, 'one batch');
    const r = s.requests[0];
    assert.equal(r.url, '/ingest');
    assert.equal(r.headers['content-type'], 'application/x-ndjson');
    assert.equal(r.headers.authorization, 'Bearer tok');
    const lines = parseConcatenated(r.body);
    const decisions = lines.filter((l) => l.type === 'decision');
    assert.deepEqual(decisions.map((d) => d.decision), ['allow', 'deny']);
    assert.equal(decisions[1].failedAt, 'scope');
    assert.ok(decisions[1].failedDetail);
    assert.equal(typeof decisions[0].ledgerSeq, 'number');
    assert.equal(decisions[0].authority, A.did);
    assert.ok(!('checks' in decisions[0]) && decisions[0].receipt === true, 'compact: no trace, no receipt body');
    assert.equal(siem.stats.sent, lines.length);
  } finally {
    await siem.stop();
    await s.close();
  }
});

test('siem: Splunk HEC format and auth header', async () => {
  const s = await sink();
  const siem = attachSiem(A, { kind: 'splunk-hec', url: s.url + '/services/collector/event', token: 'hec-token', batchMs: 60_000, host: 'authority-1' });
  try {
    await world.attack('forged');
    await siem.flush();
    const r = s.requests[0];
    assert.equal(r.headers.authorization, 'Splunk hec-token');
    const events = parseConcatenated(r.body);
    const ev = events.find((e) => e.sourcetype === 'agentid:decision');
    assert.ok(ev);
    assert.equal(ev.source, 'agentid');
    assert.equal(ev.host, 'authority-1');
    assert.equal(typeof ev.time, 'number');
    assert.ok(Math.abs(ev.time - Date.now() / 1000) < 60, 'time is epoch seconds');
    assert.equal(ev.event.decision, 'deny');
    assert.equal(ev.event.failedAt, 'signature');
  } finally {
    await siem.stop();
    await s.close();
  }
});

test('siem: OTLP/HTTP JSON logs', async () => {
  const s = await sink();
  const siem = attachSiem(A, { kind: 'otlp', url: s.url + '/v1/logs', batchMs: 60_000 });
  try {
    const id = await pendingApproval();
    await world.approve(id, 'approve');
    await siem.flush();
    const all = s.requests.flatMap((r) => JSON.parse(r.body).resourceLogs);
    assert.equal(s.requests[0].url, '/v1/logs');
    assert.equal(s.requests[0].headers['content-type'], 'application/json');
    const rl = all[0];
    assert.ok(rl.resource.attributes.some((a) => a.key === 'service.name' && a.value.stringValue === 'agentid'));
    const records = all.flatMap((x) => x.scopeLogs.flatMap((sl) => sl.logRecords));
    const attr = (lr, k) => lr.attributes.find((a) => a.key === 'agentid.' + k)?.value;
    const decisions = records.filter((lr) => attr(lr, 'type')?.stringValue === 'decision');
    assert.deepEqual(decisions.map((lr) => lr.severityText), ['WARN', 'INFO'], 'step_up then allow');
    assert.deepEqual(decisions.map((lr) => lr.severityNumber), [13, 9]);
    const lr = decisions[1];
    assert.match(lr.timeUnixNano, /^\d{19}$/);
    assert.match(lr.body.stringValue, /^allow payments\.send on vendor:harbor-cloud/);
    assert.equal(attr(lr, 'via').stringValue, 'cosign');
    assert.match(attr(lr, 'ledgerSeq').intValue, /^\d+$/, 'int64 as string');
    assert.equal(attr(lr, 'params').kvlistValue.values.find((v) => v.key === 'amount').value.intValue, '1180');
    assert.ok(records.some((x) => attr(x, 'type')?.stringValue === 'approval' && attr(x, 'status')?.stringValue === 'approved'));
  } finally {
    await siem.stop();
    await s.close();
  }
});

test('siem: retries with backoff, then bounded queue drops oldest', async () => {
  const s = await sink((_e, n) => (n === 1 ? 503 : 200));
  const siem = attachSiem(A, { kind: 'webhook', url: s.url, batchMs: 60_000, backoffMs: 5 });
  try {
    await world.act('quill', { action: 'invoices.read', resource: 'erp:northwind/inbox/INV-2', reason: 'extract', aud: 'erp' });
    await siem.flush();
    assert.equal(s.requests.length, 2, 'first attempt failed, second delivered');
    assert.equal(s.requests[0].body, s.requests[1].body);
    assert.equal(siem.stats.retried, 1);
    assert.equal(siem.pending, 0);
  } finally {
    await siem.stop();
    await s.close();
  }

  let attempts = 0;
  const errors = [];
  const down = attachSiem(A, { kind: 'webhook', url: 'http://sink.invalid', batchMs: 60_000, maxQueue: 3, maxBatch: 100, retries: 1, backoffMs: 1, post: async () => { attempts++; throw new Error('ECONNREFUSED'); }, onError: (e) => errors.push(e.message) });
  try {
    for (let i = 0; i < 5; i++) await world.act('quill', { action: 'invoices.read', resource: `erp:northwind/inbox/INV-${i}`, reason: 'extract', aud: 'erp' });
    assert.equal(down.pending, 3);
    assert.equal(down.stats.dropped, 2, 'five decisions into a queue of three: the two oldest are dropped');
    await down.flush();
    assert.equal(attempts, 2, 'one try plus one retry');
    assert.equal(down.pending, 3, 'failed batch is kept for the next flush');
    assert.match(errors[0], /unreachable/);
  } finally {
    await down.stop({ drain: false });
  }
});
