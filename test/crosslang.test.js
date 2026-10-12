// The Python SDK (sdk-python) must sign and canonicalise exactly like core/.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawnSync, execFile } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Authority, Principal, Attestor, AgentRuntime, Signer, verifySealed, verifyReceipt, canonical } from '../core/index.js';

const SDK = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'sdk-python');
const env = { ...process.env, PYTHONPATH: SDK + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : '') };
const probe = spawnSync('python3', ['-c', 'import cryptography'], { env });
const skip = probe.error || probe.status !== 0 ? 'python3 with the cryptography module is not available' : false;

const PY = `
import json, sys
import agentid as a
job = json.load(open(sys.argv[1], encoding='utf-8'))
mode = job['mode']
if mode == 'seal':
    out = a.Agent.restore(job['agent']).intent(**job['req'])
elif mode == 'verify':
    out = [a.verify_sealed(o['obj'], o.get('kid')) for o in job['objs']]
elif mode == 'canonical':
    out = [a.canonical(v) for v in json.loads(job['text'])]
elif mode == 'receipt':
    out = a.verify_receipt(job['receipt'], job['authority'], aud=job.get('aud'))
elif mode == 'act':
    out = a.AuthorityClient(job['url']).act(a.Agent.restore(job['agent']), poll=0.05, timeout=10, **job['req'])
print(json.dumps(out))
`;

const dir = skip ? null : mkdtempSync(path.join(os.tmpdir(), 'agentid-crosslang-'));
let jobs = 0;
async function py(job) {
  const file = path.join(dir, `job-${jobs++}.json`);
  writeFileSync(file, JSON.stringify(job));
  const { stdout } = await promisify(execFile)('python3', ['-c', PY, file], { env });
  return JSON.parse(stdout);
}

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
  return { A, org, agent };
}

test.after(() => dir && rmSync(dir, { recursive: true, force: true }));

test('crosslang: Python-sealed intent passes JS verification and the authority', { skip }, async () => {
  const { A, agent } = await setup();
  // 200.0 and the non-ASCII reason exercise number and string canonicalisation on the Python side.
  const req = { action: 'payments.send', resource: 'vendor:blåbær', params: { amount: 200.0, currency: 'USD', memo: 'Rechnung № 7 ✓ 😀' }, reason: 'invoice “I-1” für Müller', aud: 'payments' };
  const intent = await py({ mode: 'seal', agent: agent.export(), req });
  assert.equal(intent.type, 'Intent');
  assert.match(intent.id, /^in_[A-Za-z0-9_-]{12}$/);
  assert.match(intent.nonce, /^n_[A-Za-z0-9_-]{12}$/);
  assert.equal(intent.exp - intent.iat, 60);
  assert.deepEqual(Object.keys(intent).sort(), Object.keys(await agent.intent(req)).sort());
  assert.ok(await verifySealed(intent, agent.did));
  assert.ok(!(await verifySealed({ ...intent, reason: 'x' }, agent.did)));

  const r = await A.verifyIntent(intent);
  assert.equal(r.decision, 'allow', JSON.stringify(r.checks));
  assert.ok((await verifyReceipt(r.receipt, A.did, { aud: 'payments' })).ok);
  assert.deepEqual(await py({ mode: 'receipt', receipt: r.receipt, authority: A.did, aud: 'payments' }), { ok: true, receipt: r.receipt });
  const wrong = await py({ mode: 'receipt', receipt: r.receipt, authority: A.did, aud: 'search' });
  assert.equal(wrong.reason, 'receipt is for a different service');
});

test('crosslang: JS-sealed objects verify in Python', { skip }, async () => {
  const s = await Signer.generate();
  const other = await Signer.generate();
  const body = { type: 'Thing', n: 5, f: 0.1, big: 2 ** 60, list: [null, true, { 'ü': '日本', '😀': ' ' }], s: 'ctl\u0001\n"q"', drop: undefined };
  const sealed = await s.seal(body);
  const res = await py({ mode: 'verify', objs: [
    { obj: sealed, kid: s.did },
    { obj: sealed },
    { obj: sealed, kid: other.did },
    { obj: { ...sealed, n: 6 }, kid: s.did },
    { obj: { ...sealed, proof: { ...sealed.proof, kid: other.did } } },
  ] });
  assert.deepEqual(res, [true, true, false, false, false]);
});

test('crosslang: canonical() is identical on tricky values', { skip }, async () => {
  // Written as JSON text so Python sees 5.0 as a float, as a JSON producer would send it.
  const text = String.raw`[5.0, 5, -5.0, 0.1, 0.30000000000000004, 1e21, 1e20, 1e16, 1.5e-7, 1e-7, 0.000001, 5e-324,
    1.7976931348623157e308, 9007199254740993, 18446744073709551616, 123456789012345678901234,
    "héllo ✓ 日本 😀", "  ", "\u0000\u001f\u007f\b\f\n\r\t\"\\/", "\ud800 lone",
    {"b": 1, "a": [1, {"z": null, "y": true}], "😀": 1, "￿": 2, "é": 3, "A": 4, "10": 5, "9": 6},
    [], {}, null, false, ""]`;
  const js = JSON.parse(text).map(canonical);
  assert.deepEqual(await py({ mode: 'canonical', text }), js);
});

test('crosslang: Python AuthorityClient.act waits out a co-sign over HTTP', { skip }, async () => {
  const { A, org, agent } = await setup();
  const decisions = new Map();
  A.on(({ type, data }) => {
    if (type === 'decision') decisions.set(data.id, data);
    if (type === 'approval' && data.status === 'pending') {
      setTimeout(async () => A.resolveApproval(await org.cosign(await A.approval(data.id), 'approve')), 100);
    }
  });
  // The two /v1 routes act() uses, shaped like server/server.js answers them.
  const server = http.createServer(async (req, res) => {
    let raw = '';
    for await (const c of req) raw += c;
    const ap = req.url.match(/^\/v1\/approvals\/([^/]+)$/);
    let status = 200;
    let body;
    if (req.method === 'POST' && req.url === '/v1/intents') body = await A.verifyIntent(JSON.parse(raw));
    else if (req.method === 'GET' && ap) {
      const rec = await A.approval(decodeURIComponent(ap[1]));
      body = { id: rec.id, status: rec.status, reasons: rec.reasons, intentHash: rec.intentHash, decision: rec.result ? decisions.get(rec.result) : null, receipt: rec.receipt ?? null };
    } else [status, body] = [404, { error: 'no such endpoint' }];
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    const r = await py({ mode: 'act', url, agent: agent.export(), req: { action: 'payments.send', resource: 'vendor:acme', params: { amount: 700, currency: 'USD' }, reason: 'PO 7731', aud: 'payments' } });
    assert.equal(r.decision, 'allow', JSON.stringify(r.checks?.find((c) => c.status !== 'pass')) + ' ' + r.note);
    assert.equal(r.via, 'cosign');
    assert.ok((await verifyReceipt(r.receipt, A.did, { aud: 'payments' })).ok);
    assert.deepEqual(r.receipt.cosigners, [org.did]);
  } finally {
    server.close();
  }
});
