// stdio wrapper for the MCP gateway.
//
// The MCP client launches us instead of the real server; we launch the real server as
// a child. Client → server lines are filtered through the gateway (allowed ones go to
// the child, denials are answered on our stdout); server → client lines are copied back,
// with tools/list results filtered when the gateway asks for it.

import { spawn } from 'node:child_process';
import readline from 'node:readline';

export function runStdio({ gateway, command, args = [], input = process.stdin, output = process.stdout, env = process.env, stderr = 'inherit' }) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', stderr], env });
  const write = (msg) => output.write(JSON.stringify(msg) + '\n');

  // Lines are handled strictly in order, so a slow verify never reorders the stream.
  let queue = Promise.resolve();
  const fromClient = readline.createInterface({ input, crlfDelay: Infinity });
  fromClient.on('line', (line) => {
    queue = queue.then(async () => {
      if (!line.trim()) return;
      let parsed;
      try { parsed = JSON.parse(line); } catch {
        return write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
      }
      const batch = Array.isArray(parsed);
      const forward = [];
      for (const msg of batch ? parsed : [parsed]) {
        const r = await gateway.handleMessage(msg, {});
        if (r.respond) write(r.respond);
        else forward.push(r.forward);
      }
      if (forward.length && child.stdin.writable) child.stdin.write(JSON.stringify(batch ? forward : forward[0]) + '\n');
    }).catch((e) => process.emitWarning(`agentid gateway: ${e.message}`));
  });
  fromClient.on('close', () => queue.then(() => child.stdin.end()));

  const fromServer = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  fromServer.on('line', (line) => {
    let msg;
    try { msg = JSON.parse(line); } catch { return output.write(line + '\n'); }
    write(Array.isArray(msg) ? msg.map(gateway.filterResponse) : gateway.filterResponse(msg));
  });

  const done = new Promise((resolve) => child.on('close', (code, signal) => resolve({ code, signal })));
  return { child, done };
}
