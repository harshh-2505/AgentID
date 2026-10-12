import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse, format, lint, diff, formatDiff, PolicyError } from '../policy/dsl.js';
import { Authority, Principal, Attestor, AgentRuntime, verifySealed } from '../core/index.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const NORTHWIND = path.join(root, 'policy/examples/northwind.agentid');
const run = promisify(execFile);

const AP = `
# accounts payable
mandate "Accounts payable" for ledgerline
  allow payments.send on vendor:* where amount <= 1500 and currency in [USD]
  allow invoices.* on erp:northwind/*
  budget 250_000 USD
  rate 120 per 60s
  cosign above 750
  cosign always for payroll.*, treasury.*
  cosign quorum 2 of [did:agentid:a, did:agentid:b, did:agentid:c]
  passkey required
  delegate depth 1
  expires in 30d
`;

const errorOf = (text) => {
  try { parse(text); } catch (e) { assert.ok(e instanceof PolicyError, e.stack); return e; }
  assert.fail('expected a parse error');
};

test('dsl: parses the full syntax into a mandate spec', () => {
  const [m] = parse(AP);
  assert.deepEqual(m, {
    label: 'Accounts payable', subject: 'ledgerline',
    caps: [
      { action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 1500 }, currency: { in: ['USD'] } } },
      { action: 'invoices.*', resource: 'erp:northwind/*' },
    ],
    budget: { amount: 250000, currency: 'USD' },
    rate: { max: 120, windowSec: 60 },
    cosign: { above: 750, actions: ['payroll.*', 'treasury.*'], quorum: { k: 2, of: ['did:agentid:a', 'did:agentid:b', 'did:agentid:c'] }, passkey: true },
    depth: 1, ttlSec: 30 * 86400,
  });
});

test('dsl: where clauses map to max, min, in and match; quoting and numbers', () => {
  const [m] = parse(`mandate "x" for "did:agentid:abc"
  allow "files.read" on "share:my docs/*" where size >= 1 and size <= 10 and tier in [1, "2", gold] and to matches [*@a.example, "*@b example"]`);
  assert.equal(m.subject, 'did:agentid:abc');
  assert.equal(m.caps[0].resource, 'share:my docs/*');
  assert.deepEqual(m.caps[0].limits, { size: { min: 1, max: 10 }, tier: { in: [1, '2', 'gold'] }, to: { match: ['*@a.example', '*@b example'] } });
  assert.equal(m.depth, 0);
  assert.equal(m.ttlSec, null);
  assert.equal(m.cosign, null);
});

test('dsl: several mandates per file, comments anywhere', () => {
  const specs = parse('# top\nmandate "a" for x # trailing\n  allow a.b on r:1\n\n# between\nmandate "b" for y\n  allow c.d on r:2 # why\n');
  assert.deepEqual(specs.map((s) => [s.label, s.subject, s.caps.length]), [['a', 'x', 1], ['b', 'y', 1]]);
});

test('dsl: errors carry line:col and say what was expected', () => {
  const cases = [
    ['allow a on b', 1, 1, /must come after a mandate line/],
    ['mandate "m" for x\n  allow a.b r:1', 2, 13, /expected "on", found "r:1"/],
    ['mandate "m" for x\n  allow a.b on r where amount < 5', 2, 31, /unsupported operator "<"/],
    ['mandate "m" for x\n  allow a.b on r where amount <= lots', 2, 34, /expected the max for amount \(a number\), found "lots"/],
    ['mandate "m" for x\n  allow a.b on r where amount <= 5 and amount <= 6', 2, 40, /amount already has a max limit/],
    ['mandate "m" for x\n  allow a.b on r where n in [a, b', 2, 34, /expected , or ] but the line ended/],
    ['mandate "m" for x\n  allow a on b\n  budget 10 dollars', 3, 13, /3-letter code/],
    ['mandate "m" for x\n  allow a on b\n  rate 5 per fortnight', 3, 14, /like 60s/],
    ['mandate "m" for x\n  allow a on b\n  cosign quorum 3 of [g1, g2]', 3, 10, /never be met/],
    ['mandate "m" for x\n  allow a on b\n  budget 1 USD\n  budget 2 USD', 4, 10, /budget is already set/],
    ['mandate "m" for x\n  allow a on b\n  frobnicate', 3, 3, /unknown statement "frobnicate"/],
    ['mandate "m" for x\n  allow a on b extra', 2, 16, /unexpected "extra"/],
    ['mandate m for x', 1, 9, /double quotes/],
    ['mandate "m" for x\n  budget 1 USD', 1, 1, /grants nothing/],
    ['mandate "m" for x\n  allow a on "b', 2, 14, /unterminated string/],
    ['mandate "m" for x\n  allow a on b where n >= 5 and n <= 1', 2, 33, /min 5 is above its max 1/],
  ];
  for (const [text, line, col, re] of cases) {
    const e = errorOf(text);
    assert.match(e.message, re, text);
    assert.deepEqual([e.line, e.col], [line, col], `${text}\n→ ${e.message}`);
    assert.ok(e.message.startsWith(`${line}:${col}: `));
  }
});

test('dsl: format round-trips, including the Northwind example', async () => {
  for (const text of [AP, await readFile(NORTHWIND, 'utf8'), 'mandate "odd \\"name\\"" for x\n  allow "a b" on "where" where "in" in ["1", 2, "x,y", ""]\n  rate 3 per 90m\n']) {
    const specs = parse(text);
    const out = format(specs);
    assert.deepEqual(parse(out), specs, out);
    assert.equal(format(parse(out)), out, 'format is a fixed point');
  }
});

test('dsl: the Northwind example matches the demo world mandates', async () => {
  const specs = parse(await readFile(NORTHWIND, 'utf8'));
  const ap = specs.find((s) => s.subject === 'ledgerline');
  assert.deepEqual(ap.caps[0], { action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 1500 }, currency: { in: ['USD'] } } });
  assert.deepEqual([ap.budget, ap.rate, ap.cosign, ap.depth], [{ amount: 250000, currency: 'USD' }, { max: 120, windowSec: 60 }, { above: 750 }, 1]);
  assert.deepEqual(specs.find((s) => s.subject === 'courier').caps[0].limits.cabin, { in: ['economy', 'premium'] });
  assert.deepEqual(specs.find((s) => s.subject === 'scout').caps[2].limits, { to: { match: ['*@northwind.example'] } });
});

test('lint: flags risky policy', () => {
  const codes = (text) => lint(parse(text)).map((w) => w.code).sort();
  assert.deepEqual(codes('mandate "a" for x\n  allow payments.send on vendor:acme where currency in [USD]\n  budget 10 USD'), ['unbounded-amount']);
  assert.deepEqual(codes('mandate "a" for x\n  allow payments.send on vendor:acme where amount <= 5 and currency in [USD]'), ['no-budget']);
  assert.deepEqual(codes('mandate "a" for x\n  allow files.delete on *'), ['wildcard-write']);
  assert.deepEqual(codes('mandate "a" for x\n  allow * on db:prod/x'), ['every-action']);
  assert.deepEqual(codes('mandate "a" for x\n  allow payments.send on vendor:acme where amount <= 500 and currency in [USD]\n  budget 1000 USD\n  cosign above 750'), ['unreachable-cosign']);
  assert.deepEqual(codes('mandate "a" for x\n  allow payments.send on vendor:acme where amount <= 500 and currency in [USD]\n  budget 1000 USD\n  cosign above 499'), []);
  assert.deepEqual(codes('mandate "a" for x\n  allow web.fetch on https://*\n  allow files.read on share:*'), []);
});

test('diff: widened / narrowed / changed / unchanged, judged with capsWithin', () => {
  const base = parse(AP);
  const same = diff(base, parse(format(base)));
  assert.equal(same.widened, false);
  assert.equal(same.mandates[0].status, 'unchanged');

  const wider = diff(base, parse(AP.replace('amount <= 1500', 'amount <= 5000').replace('passkey required\n', '')));
  assert.equal(wider.widened, true);
  assert.equal(wider.mandates[0].status, 'widened');
  assert.ok(wider.mandates[0].changes.some((c) => c.widens && /amount .*1500.*5000/.test(c.detail)));
  assert.ok(wider.mandates[0].changes.some((c) => c.widens && /passkey no longer required/.test(c.detail)));
  assert.match(formatDiff(wider), /!! WIDENS AUTHORITY/);

  const narrower = diff(base, parse(AP.replace('vendor:*', 'vendor:acme').replace('rate 120', 'rate 60').replace(', treasury.*', ', treasury.*, hr.*')));
  assert.equal(narrower.widened, false);
  assert.equal(narrower.mandates[0].status, 'narrowed');
  assert.deepEqual(narrower.mandates[0].capsAdded.map((c) => c.resource), ['vendor:acme']);
  assert.deepEqual(narrower.mandates[0].capsRemoved.map((c) => c.resource), ['vendor:*']);

  // Dropping a limit is a widening even though the cap list "only changed".
  const dropped = diff(base, parse(AP.replace(' and currency in [USD]', '')));
  assert.equal(dropped.mandates[0].status, 'widened');

  const mixed = diff(base, parse(AP.replace('budget 250_000', 'budget 900_000').replace('delegate depth 1', 'delegate depth 0')));
  assert.equal(mixed.mandates[0].status, 'changed');
  assert.equal(mixed.widened, true);

  const broader = diff(base, parse(AP.replace('allow invoices.* on erp:northwind/*', 'allow invoices.* on erp:*')));
  assert.ok(broader.mandates[0].changes.some((c) => c.widens && /grants more: invoices\.\* on erp:\*/.test(c.detail)));

  const added = diff(base, [...base, ...parse('mandate "new" for y\n  allow a.b on c')]);
  assert.deepEqual(added.mandates.map((m) => m.status), ['unchanged', 'added']);
  assert.equal(added.widened, true);
  assert.deepEqual(diff([...base, ...parse('mandate "new" for y\n  allow a.b on c')], base).mandates.map((m) => m.status), ['unchanged', 'removed']);
});

test('issued DSL mandates are accepted by the authority and enforced', async () => {
  const A = await Authority.create();
  const org = await Principal.create({ name: 'Northwind' });
  const host = await Attestor.create('host');
  await A.registerPrincipal(await org.registration());
  await A.endorseAttestor(await org.endorseAttestor(host));
  const agent = await AgentRuntime.create({ name: 'Ledgerline', purpose: 'pays', model: 'm', manifest: { model: 'm', tools: [] } });
  agent.passport = await org.issuePassport(agent, { depth: 1 });
  await A.registerPassport(agent.passport);
  const [spec] = parse(await readFile(NORTHWIND, 'utf8'));
  const { subject, ttlSec, ...rest } = spec;
  agent.mandate = await org.issueMandate({ ...rest, sub: agent.did, ...(ttlSec ? { ttlSec } : {}) });
  await A.registerMandate(agent.mandate);
  agent.attestation = await host.attest(agent.did, agent.manifest);
  const pay = (amount) => agent.intent({ action: 'payments.send', resource: 'vendor:x', params: { amount, currency: 'USD' }, reason: 'invoice 7' });
  assert.equal((await A.verifyIntent(await pay(100))).decision, 'allow');
  assert.equal((await A.verifyIntent(await pay(900))).decision, 'step_up');
  assert.equal((await A.verifyIntent(await pay(2000))).failedAt, 'limits');
});

test('cli: check, fmt, diff exit codes, issue', async (t) => {
  const cli = path.join(root, 'policy/cli.js');
  const tmp = path.join(os.tmpdir(), `agentid-policy-${process.pid}-${Date.now()}`);
  const files = { wide: tmp + '-wide.agentid', bad: tmp + '-bad.agentid', key: tmp + '-key.json', agents: tmp + '-agents.json' };
  t.after(() => Promise.all(Object.values(files).map((f) => rm(f, { force: true }))));
  const text = await readFile(NORTHWIND, 'utf8');
  await writeFile(files.wide, text.replace('amount <= 1500', 'amount <= 9000'));
  await writeFile(files.bad, 'mandate "x" for y\n  allow a.b on\n');

  const check = await run(process.execPath, [cli, 'check', NORTHWIND]);
  assert.match(check.stdout, /3 mandate\(s\)/);
  await assert.rejects(run(process.execPath, [cli, 'check', files.bad]), (e) => e.code === 1 && /bad\.agentid:2:15: expected a resource pattern/.test(e.stderr));

  const fmt = await run(process.execPath, [cli, 'fmt', NORTHWIND]);
  assert.deepEqual(parse(fmt.stdout), parse(text));

  const same = await run(process.execPath, [cli, 'diff', NORTHWIND, NORTHWIND]);
  assert.match(same.stdout, /No mandate gains authority/);
  await assert.rejects(run(process.execPath, [cli, 'diff', NORTHWIND, files.wide]), (e) => e.code === 2 && /WIDENS/.test(e.stdout));
  const back = await run(process.execPath, [cli, 'diff', files.wide, NORTHWIND]);
  assert.match(back.stdout, /NARROWED/);

  const org = await Principal.create({ name: 'Northwind' });
  const names = ['ledgerline', 'courier', 'scout'];
  const dids = Object.fromEntries(await Promise.all(names.map(async (n) => [n, (await AgentRuntime.create({ name: n })).did])));
  await writeFile(files.key, JSON.stringify(org.export()));
  await writeFile(files.agents, JSON.stringify(dids));
  const issued = JSON.parse((await run(process.execPath, [cli, 'issue', NORTHWIND, '--principal', files.key, '--agents', files.agents])).stdout);
  assert.equal(issued.length, 3);
  for (const m of issued) assert.ok(await verifySealed(m, org.did));
  assert.deepEqual(issued.map((m) => m.sub), names.map((n) => dids[n]));
  assert.equal(issued[0].label, 'Accounts payable');
});
