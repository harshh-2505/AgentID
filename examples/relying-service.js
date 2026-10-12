// A payments API that only serves agents carrying a valid AgentID receipt.
// It never calls the authority: the receipt is checked offline against the
// authority's public identifier, fetched once at start-up.
//
//   npm start            (authority on :4600)
//   npm run service      (this service on :4700)
//   npm run agent        (an agent that calls both)

import http from 'node:http';
import { AuthorityClient, requireReceipt } from '../sdk/index.js';

const AUTHORITY = process.env.AGENTID_URL || 'http://localhost:4600';
const PORT = Number(process.env.SERVICE_PORT || 4700);
const { authority } = await new AuthorityClient(AUTHORITY).discover();

const guard = requireReceipt({
  authority,
  aud: 'payments',
  // The receipt must cover *this* request, not merely some request.
  expect: (req, r) => {
    if (r.action !== 'payments.send') return `receipt is for ${r.action}, not payments.send`;
    if (r.resource !== 'vendor:' + req.body.vendor) return 'receipt names a different vendor';
    if (r.params.amount !== req.body.amount) return 'receipt names a different amount';
    return null;
  },
});

http.createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/pay') { res.writeHead(404); return res.end(); }
  let raw = '';
  for await (const c of req) raw += c;
  req.body = JSON.parse(raw || '{}');
  await guard(req, res, () => {
    const msg = `paid ${req.body.amount} USD to ${req.body.vendor} for agent ${req.agent.did.slice(12, 20)}… (ledger #${req.agent.receipt.ledgerSeq})`;
    console.log('✓', msg);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, message: msg }));
  });
}).listen(PORT, () => console.log(`Payments service on http://localhost:${PORT}, trusting authority ${authority.slice(0, 28)}…`));
