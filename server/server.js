// AgentID authority server. Zero dependencies: Node 20+ only.
//
//   /v1/*          the protocol API that real agents, principals and services call
//   /api/*         the console API (demo organisation, live events, ledger)
//   /              the console itself
//
// State is kept in data/world.json so a restart keeps keys, passports and the ledger.

import http from 'node:http';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DemoWorld } from '../core/demo-world.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA = path.join(ROOT, 'data', 'world.json');
const PORT = Number(process.env.PORT || 4600);
const STATIC = { '/core/': path.join(ROOT, 'core'), '/': path.join(ROOT, 'web') };
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png' };

let world = await load();
const clients = new Set();
let saveTimer = null;

function wire(w) {
  w.on((ev) => {
    const line = `event: ${ev.type}\ndata: ${JSON.stringify(ev.data)}\n\n`;
    for (const res of clients) res.write(line);
    clearTimeout(saveTimer);
    saveTimer = setTimeout(save, 400);
  });
}
wire(world);

async function load() {
  if (existsSync(DATA)) {
    try {
      const w = await DemoWorld.restore(JSON.parse(await readFile(DATA, 'utf8')));
      console.log('Restored authority state from data/world.json');
      return w;
    } catch (e) {
      console.warn('Could not restore saved state, starting fresh:', e.message);
    }
  }
  return DemoWorld.create();
}

async function save() {
  await mkdir(path.dirname(DATA), { recursive: true });
  await writeFile(DATA, JSON.stringify(world.export()));
}

const A = () => world.authority;

// Route table: [method, pattern, handler(body, params, query)]
const routes = [
  ['GET', '/.well-known/agentid', () => ({ authority: A().did, protocol: 'agentid/1', endpoints: '/v1' })],

  ['POST', '/v1/principals', (b) => A().registerPrincipal(b)],
  ['POST', '/v1/attestors', (b) => A().endorseAttestor(b)],
  ['POST', '/v1/passports', (b) => A().registerPassport(b)],
  ['POST', '/v1/mandates', (b) => A().registerMandate(b)],
  ['POST', '/v1/intents', (b) => A().verifyIntent(b)],
  ['GET', '/v1/approvals/:id', (_, p) => {
    const ap = A().s.approvals[p.id];
    if (!ap) throw httpError(404, 'approval not found');
    return { id: ap.id, status: ap.status, reasons: ap.reasons, intentHash: ap.intentHash, decision: ap.result ? A().s.decisions.find((d) => d.id === ap.result) : null, receipt: ap.receipt ?? null };
  }],
  ['GET', '/v1/approvals/:id/request', (_, p) => {
    const ap = A().s.approvals[p.id];
    if (!ap) throw httpError(404, 'approval not found');
    return ap;
  }],
  ['POST', '/v1/approvals/:id/cosign', (b) => A().resolveApproval(b)],
  ['POST', '/v1/revocations', (b) => A().revoke(b)],
  ['GET', '/v1/ledger', (_, __, q) => A().ledgerEntries({ from: Number(q.get('from') || 0), limit: Math.min(500, Number(q.get('limit') || 200)) })],
  ['GET', '/v1/ledger/verify', () => A().verifyLedger()],

  ['GET', '/api/health', () => ({ ok: true, mode: 'server', authority: A().did })],
  ['GET', '/api/snapshot', () => world.snapshot()],
  ['GET', '/api/ledger', (_, __, q) => world.ledger({ from: Number(q.get('from') || 0), limit: Math.min(500, Number(q.get('limit') || 200)) })],
  ['GET', '/api/ledger/verify', () => world.verifyLedger()],
  ['POST', '/api/demo/tick', () => world.tick()],
  ['POST', '/api/demo/attack', (b) => world.attack(b.kind)],
  ['POST', '/api/demo/approve', (b) => world.approve(b.id, b.decision)],
  ['POST', '/api/demo/revoke', (b) => world.revoke(b.target, b.reason)],
  ['POST', '/api/demo/delegate', (b) => world.delegate(b)],
  ['POST', '/api/demo/reset', async () => {
    world = await DemoWorld.create();
    wire(world);
    await save();
    for (const res of clients) res.write('event: reset\ndata: {}\n\n');
    return { ok: true };
  }],
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
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw httpError(400, 'body is not valid JSON'); }
}

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
  res.end(JSON.stringify(body));
}

async function serveStatic(res, pathname) {
  for (const [prefix, dir] of Object.entries(STATIC)) {
    if (!pathname.startsWith(prefix)) continue;
    let rel = pathname.slice(prefix.length) || 'index.html';
    const file = path.join(dir, rel);
    if (!file.startsWith(dir)) break;
    try {
      const st = await stat(file);
      const target = st.isDirectory() ? path.join(file, 'index.html') : file;
      let body = await readFile(target);
      // The console's index.html is written as an artifact page body; give it a document shell here.
      if (target.endsWith('.html') && !/^\s*<!doctype/i.test(body.toString('utf8', 0, 30))) {
        body = Buffer.from('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>' + body.toString('utf8') + '</body></html>');
      }
      res.writeHead(200, { 'content-type': TYPES[path.extname(target)] || 'application/octet-stream', 'cache-control': 'no-cache' });
      return res.end(body);
    } catch { /* fall through to 404 */ }
  }
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type' });
    return res.end();
  }
  if (url.pathname === '/api/events') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', 'access-control-allow-origin': '*' });
    res.write('retry: 2000\n\n');
    clients.add(res);
    const ping = setInterval(() => res.write(': ping\n\n'), 20_000);
    req.on('close', () => { clients.delete(res); clearInterval(ping); });
    return;
  }
  const route = match(req.method, url.pathname);
  if (!route) {
    if (req.method === 'GET' && !url.pathname.startsWith('/v1') && !url.pathname.startsWith('/api')) return serveStatic(res, url.pathname);
    return send(res, 404, { error: 'no such endpoint' });
  }
  try {
    const body = req.method === 'POST' ? await readBody(req) : null;
    send(res, 200, await route.handler(body, route.params, url.searchParams));
  } catch (e) {
    send(res, e.status || 400, { error: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`AgentID authority  ${A().did}`);
  console.log(`Console            http://localhost:${PORT}`);
  console.log(`Protocol API       http://localhost:${PORT}/v1`);
});
