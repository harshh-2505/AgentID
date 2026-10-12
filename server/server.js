// AgentID authority server. No required dependencies: Node 20+ only.
//
//   /v1/*          the protocol API that agents, principals and services call
//   /oauth, /.well-known/*   bridges to OAuth, SPIFFE and W3C credentials
//   /integrations/*          Slack and Teams co-sign callbacks
//   /api/*         the console API (demo organisation, live events, ledger)
//   /              the console itself
//
// Two modes (see docs/DEPLOY.md):
//   demo        (default) a self-contained demo organisation, state in data/world.json
//   production  AGENTID_MODE=production: no demo org, sign-up gate on, key from a key
//               provider, state in Postgres when AGENTID_DATABASE_URL is set

import http from 'node:http';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Authority } from '../core/authority.js';
import { DemoWorld } from '../core/demo-world.js';
import { loadConfig } from './config.js';
import { buildAuthorityOptions, moduleRoutes, attachIntegrations } from './modules.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA = path.join(ROOT, 'data', 'world.json');
const STATIC = { '/core/': path.join(ROOT, 'core'), '/': path.join(ROOT, 'web') };
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png' };

const config = loadConfig(process.env);
const demo = config.mode === 'demo';
const options = await buildAuthorityOptions(config);
const clients = new Set();
let saveTimer = null;
let world = null;
let authority = null;

if (demo) {
  world = await loadWorld();
  authority = world.authority;
} else {
  authority = new Authority(options.signer, options);
}
wire(authority);
const detach = { current: await attachIntegrations(authority, config, () => world) };

function wire(a) {
  a.on((ev) => {
    const line = `event: ${ev.type}\ndata: ${JSON.stringify(ev.data)}\n\n`;
    for (const res of clients) res.write(line);
    if (demo) { clearTimeout(saveTimer); saveTimer = setTimeout(save, 400); }
  });
}

async function loadWorld() {
  const { signer, ...authorityOptions } = options;
  if (existsSync(DATA)) {
    try {
      const w = await DemoWorld.restore(JSON.parse(await readFile(DATA, 'utf8')), authorityOptions);
      console.log('Restored demo state from data/world.json');
      return w;
    } catch (e) {
      console.warn('Could not restore saved state, starting fresh:', e.message);
    }
  }
  return DemoWorld.create({ authorityOptions });
}

async function save() {
  await mkdir(path.dirname(DATA), { recursive: true });
  await writeFile(DATA, JSON.stringify(world.export()));
}

const A = () => authority;
const W = () => {
  if (!world) throw httpError(404, 'the demo organisation is disabled in production mode');
  return world;
};
const int = (q, k, d) => Number(q.get(k) ?? d);

// Route table: [method, pattern, handler(body, params, query, req)]
const routes = [
  ['GET', '/.well-known/agentid', () => ({
    authority: A().did, protocol: 'agentid/1', endpoints: '/v1', mode: config.mode,
    passkeys: !!A().webauthn, attestation: Object.keys(A().verifiers), admission: config.admissionMode,
  })],

  ['POST', '/v1/principals', (b) => A().registerPrincipal(b.registration || b, b.evidence ?? null)],
  ['GET', '/v1/principals/:did', async (_, p) => {
    const rec = await A().principal(p.did);
    if (!rec) throw httpError(404, 'principal not found');
    return { ...rec, passkeys: rec.passkeys.map(({ jwk, ...k }) => k) };
  }],
  ['POST', '/v1/principals/:did/keys', (b) => A().updateKeys(b)],
  ['POST', '/v1/principals/:did/freeze', (b) => A().setFreeze(b)],
  ['POST', '/v1/principals/:did/passkeys', (b) => A().enrollPasskey(b)],
  ['POST', '/v1/attestors', (b) => A().endorseAttestor(b)],
  ['POST', '/v1/publishers', (b) => A().endorsePublisher(b)],
  ['POST', '/v1/passports', (b) => A().registerPassport(b)],
  ['POST', '/v1/mandates', (b) => A().registerMandate(b)],
  ['POST', '/v1/intents', (b) => A().verifyIntent(b)],
  ['GET', '/v1/approvals/:id', async (_, p) => {
    const ap = await A().approval(p.id);
    if (!ap) throw httpError(404, 'approval not found');
    return { id: ap.id, status: ap.status, reasons: ap.reasons, intentHash: ap.intentHash, passkey: ap.passkey, decision: ap.result ? await A().decision(ap.result) : null, receipt: ap.receipt ?? null };
  }],
  ['GET', '/v1/approvals/:id/request', async (_, p) => {
    const ap = await A().approval(p.id);
    if (!ap) throw httpError(404, 'approval not found');
    return ap;
  }],
  ['POST', '/v1/approvals/:id/cosign', (b) => A().resolveApproval(b)],
  ['POST', '/v1/revocations', (b) => A().revoke(b)],
  ['POST', '/v1/federation', (b) => A().federate(b)],
  ['POST', '/v1/federation/receipts', (b) => A().acceptForeignReceipt(b.receipt || b, { aud: b.aud })],
  ['GET', '/v1/trust-bundle', () => A().trustBundle({ name: config.name, endpoints: { api: config.issuer + '/v1' } })],
  ['GET', '/v1/ledger', (_, __, q) => A().ledgerEntries({ from: int(q, 'from', 0), limit: Math.min(500, int(q, 'limit', 200)) })],
  ['GET', '/v1/ledger/verify', () => A().verifyLedger()],
  ['GET', '/v1/checkpoint', () => A().checkpoint()],
  ['GET', '/v1/proofs/inclusion', (_, __, q) => A().inclusionProof(int(q, 'seq', 0), q.has('size') ? int(q, 'size') : undefined)],
  ['GET', '/v1/proofs/consistency', (_, __, q) => A().consistencyProof(int(q, 'first', 1), q.has('second') ? int(q, 'second') : undefined)],
  ['POST', '/v1/witness', (b) => A().recordWitness(b)],

  ['GET', '/api/health', () => ({ ok: true, mode: demo ? 'server' : 'production', authority: A().did })],
  ['GET', '/api/snapshot', () => (world ? world.snapshot() : A().snapshot())],
  ['GET', '/api/ledger', (_, __, q) => A().ledgerEntries({ from: int(q, 'from', 0), limit: Math.min(500, int(q, 'limit', 200)) })],
  ['GET', '/api/ledger/verify', () => A().verifyLedger()],
  ['GET', '/api/checkpoint', async () => {
    const cp = await A().checkpoint();
    return { checkpoint: cp, inclusion: cp.size ? await A().inclusionProof(cp.size - 1) : null };
  }],
  ['POST', '/api/demo/tick', () => W().tick()],
  ['POST', '/api/demo/attack', (b) => W().attack(b.kind)],
  ['POST', '/api/demo/approve', (b) => W().approve(b.id, b.decision, { key: b.key })],
  ['POST', '/api/demo/revoke', (b) => W().revoke(b.target, b.reason)],
  ['POST', '/api/demo/delegate', (b) => W().delegate(b)],
  ['POST', '/api/demo/freeze', (b) => W().freeze(!!b.frozen, b.reason)],
  ['POST', '/api/demo/rotate-agent', (b) => W().rotateAgent(b.agent)],
  ['POST', '/api/demo/rotate-key', () => W().rotateOperationalKey()],
  ['POST', '/api/demo/recover-root', () => W().recoverRoot()],
  ['POST', '/api/demo/passkey/challenge', () => W().passkeyChallenge()],
  ['POST', '/api/demo/passkey/enroll', (b) => W().enrollPasskey(b)],
  ['POST', '/api/demo/passkey/approval-challenge', (b) => W().passkeyApprovalChallenge(b.id, b.decision)],
  ['POST', '/api/demo/passkey/approve', (b) => W().approveWithPasskey(b.id, b.decision, b.assertion)],
  ['POST', '/api/demo/federation', (b) => W().federation(b.kind)],
  ['POST', '/api/demo/reset', async () => {
    world = await DemoWorld.create({ authorityOptions: (({ signer, ...o }) => o)(options) });
    authority = world.authority;
    wire(authority);
    detach.current?.();
    detach.current = await attachIntegrations(authority, config, () => world);
    await save();
    for (const res of clients) res.write('event: reset\ndata: {}\n\n');
    return { ok: true };
  }],
  ...(await moduleRoutes({ authority: A, world: () => world, config, issuer: config.issuer })),
];

function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

function match(method, url) {
  for (const [m, pattern, handler] of routes) {
    if (m !== method) continue;
    const pp = pattern.split('/');
    const up = url.split('/');
    if (pp.length !== up.length) continue;
    const params = {};
    if (pp.every((seg, i) => (seg.startsWith(':') ? (params[seg.slice(1)] = decodeURIComponent(up[i])) : seg === up[i]))) return { handler, params };
  }
  return null;
}

async function readBody(req) {
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > 1_000_000) throw httpError(413, 'body too large');
    chunks.push(c);
  }
  req.rawBody = Buffer.concat(chunks);
  if (!chunks.length) return {};
  const text = req.rawBody.toString('utf8');
  if ((req.headers['content-type'] || '').includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(text));
  try { return JSON.parse(text); } catch { throw httpError(400, 'body is not valid JSON'); }
}

const CORS = { 'access-control-allow-origin': '*' };

function send(res, status, body) {
  if (body && body.__raw) {
    const { status: s = 200, headers = {}, body: b = '' } = body.__raw;
    res.writeHead(s, { ...CORS, ...headers });
    return res.end(typeof b === 'string' || Buffer.isBuffer(b) ? b : JSON.stringify(b));
  }
  res.writeHead(status, { 'content-type': 'application/json', ...CORS });
  res.end(JSON.stringify(body ?? null));
}

async function serveStatic(res, pathname) {
  for (const [prefix, dir] of Object.entries(STATIC)) {
    if (!pathname.startsWith(prefix)) continue;
    const rel = pathname.slice(prefix.length) || 'index.html';
    const file = path.join(dir, rel);
    if (!file.startsWith(dir)) break;
    try {
      const st = await stat(file);
      const target = st.isDirectory() ? path.join(file, 'index.html') : file;
      let body = await readFile(target);
      // The console's index.html is written as an artifact page body; give it a document shell here.
      if (target.endsWith('.html') && !/^\s*<!doctype/i.test(body.toString('utf8', 0, 30))) {
        body = Buffer.from('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>AgentID</title></head><body>' + body.toString('utf8') + '</body></html>');
      }
      res.writeHead(200, { 'content-type': TYPES[path.extname(target)] || 'application/octet-stream', 'cache-control': 'no-cache' });
      return res.end(body);
    } catch { /* fall through to 404 */ }
  }
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
}

const API = /^\/(v1|api|oauth|integrations|\.well-known)(\/|$)/;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { ...CORS, 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type, authorization' });
    return res.end();
  }
  if (url.pathname === '/api/events') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', ...CORS });
    res.write('retry: 2000\n\n');
    clients.add(res);
    const ping = setInterval(() => res.write(': ping\n\n'), 20_000);
    req.on('close', () => { clients.delete(res); clearInterval(ping); });
    return;
  }
  const route = match(req.method, url.pathname);
  if (!route) {
    if (req.method === 'GET' && demo && !API.test(url.pathname)) return serveStatic(res, url.pathname);
    return send(res, 404, { error: 'no such endpoint' });
  }
  try {
    const body = req.method === 'POST' ? await readBody(req) : null;
    send(res, 200, await route.handler(body, route.params, url.searchParams, req));
  } catch (e) {
    send(res, e.status || 400, { error: e.message });
  }
});

server.listen(config.port, () => {
  console.log(`AgentID authority  ${A().did}  (${config.mode} mode, ${config.storeKind} store, ${config.keyProvider} key)`);
  if (demo) console.log(`Console            http://localhost:${config.port}`);
  console.log(`Protocol API       http://localhost:${config.port}/v1`);
});
