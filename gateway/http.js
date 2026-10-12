// Streamable HTTP proxy for the MCP gateway.
//
// POST /mcp bodies (single messages or batches) go through the gateway; what it allows
// is forwarded upstream and the upstream answer is streamed back as is, JSON or SSE.
// Denials are answered locally and never reach the upstream server. Other methods on
// /mcp (GET for the server's SSE stream, DELETE to end a session) are proxied unchanged.

import http from 'node:http';

const FORWARD_REQ = ['content-type', 'accept', 'authorization', 'mcp-session-id', 'mcp-protocol-version', 'last-event-id'];
const FORWARD_RES = ['content-type', 'mcp-session-id', 'cache-control'];

const pick = (headers, names) => Object.fromEntries(names.filter((n) => headers[n] !== undefined).map((n) => [n, headers[n]]));

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

const sseEvent = (msg) => `event: message\ndata: ${JSON.stringify(msg)}\n\n`;

// Rewrites each SSE event's JSON data through `fn`, holding back partial events.
function sseRewriter(fn) {
  let buf = '';
  const rewrite = (event) => {
    const lines = event.split(/\r?\n/);
    const data = lines.filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
    if (!data) return event;
    let msg;
    try { msg = JSON.parse(data); } catch { return event; }
    const out = Array.isArray(msg) ? msg.map(fn) : fn(msg);
    return [...lines.filter((l) => !l.startsWith('data:')), `data: ${JSON.stringify(out)}`].join('\n');
  };
  return {
    push(text) {
      buf += text;
      const parts = buf.split(/\r?\n\r?\n/);
      buf = parts.pop();
      return parts.map((p) => rewrite(p) + '\n\n').join('');
    },
    end() { const rest = buf; buf = ''; return rest ? rewrite(rest) : ''; },
  };
}

export function createHttpProxy({ gateway, upstream, path = '/mcp' }) {
  return http.createServer(async (req, res) => {
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers });
      res.end(body === undefined ? undefined : JSON.stringify(body));
    };
    try {
      if (new URL(req.url, 'http://x').pathname !== path) return send(404, { error: 'not found' });
      const headers = pick(req.headers, FORWARD_REQ);

      let local = [];
      let body;
      let batch = false;
      if (req.method === 'POST') {
        let parsed;
        try { parsed = JSON.parse(await readBody(req)); } catch {
          return send(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
        }
        batch = Array.isArray(parsed);
        const forward = [];
        for (const msg of batch ? parsed : [parsed]) {
          const r = await gateway.handleMessage(msg, req.headers);
          if (r.respond) local.push(r.respond);
          else forward.push(r.forward);
        }
        // Everything was answered here: the upstream never hears about it.
        if (!forward.length) return send(200, batch ? local : local[0]);
        body = JSON.stringify(batch ? forward : forward[0]);
      } else if (req.method !== 'GET' && req.method !== 'DELETE') {
        return send(405, { error: 'method not allowed' });
      }

      const up = await fetch(upstream, { method: req.method, headers, body });
      const type = up.headers.get('content-type') || '';
      const outHeaders = {};
      for (const n of FORWARD_RES) if (up.headers.get(n)) outHeaders[n] = up.headers.get(n);

      // Only notifications went upstream (202, no body) but some calls were denied here.
      if (local.length && (up.status === 202 || !up.body)) return send(200, batch ? local : local[0], { 'mcp-session-id': outHeaders['mcp-session-id'] });

      if (type.includes('application/json')) {
        const text = await up.text();
        let out = text;
        try {
          const msg = JSON.parse(text);
          const filtered = Array.isArray(msg) ? msg.map(gateway.filterResponse) : gateway.filterResponse(msg);
          out = JSON.stringify(local.length ? [...local, ...(Array.isArray(filtered) ? filtered : [filtered])] : filtered);
        } catch { /* not JSON after all: pass through */ }
        res.writeHead(up.status, outHeaders);
        return res.end(out);
      }

      res.writeHead(up.status, outHeaders);
      if (!up.body) return res.end();
      const sse = type.includes('text/event-stream') ? sseRewriter(gateway.filterResponse) : null;
      // Calls denied in a mixed batch are answered first on the same stream.
      if (sse) for (const m of local) res.write(sseEvent(m));
      const decoder = new TextDecoder();
      const abort = () => up.body.cancel().catch(() => {});
      res.on('close', abort);
      for await (const chunk of up.body) {
        res.write(sse ? sse.push(decoder.decode(chunk, { stream: true })) : chunk);
      }
      if (sse) res.write(sse.end());
      res.end();
    } catch (e) {
      if (!res.headersSent) send(502, { jsonrpc: '2.0', id: null, error: { code: -32603, message: `gateway upstream error: ${e.message}` } });
      else res.end();
    }
  });
}
