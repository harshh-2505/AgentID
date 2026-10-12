// VII. Stack: AgentID next to the tools teams already run. Every card runs for real:
// the MCP gateway, OAuth token exchange, W3C credentials, federation, Slack co-sign,
// SIEM export, policy-as-code and the SDKs.

import { h, fill, gsap, reducedMotion, money, short, toast, clock } from '../dom.js';
import { sigil } from '../sigil.js';
import * as dsl from '../../policy/dsl.js';

const json = (v) => JSON.stringify(v, null, 2);

const SNIPPETS = {
  TypeScript: `import { AuthorityClient } from 'agentid/sdk';
import { withAgentID } from 'agentid/sdk/adapters';

const client = new AuthorityClient('https://agentid.northwind.example');

// Any tool function becomes a governed tool: a signed intent goes to
// the authority first, held requests wait for a co-sign, denials throw.
export const payInvoice = withAgentID(rawPayInvoice, {
  client, agent: ledgerline,
  action: 'payments.send',
  resource: (a) => 'vendor:' + a.vendor,
  params: (a) => ({ amount: a.amount, currency: 'USD', invoice: a.id }),
  reason: (a) => \`\${a.id} matched to PO and approved\`,
  aud: 'payments',
});`,
  Python: `from agentid import Agent, AuthorityClient
from agentid.adapters import guard

client = AuthorityClient("https://agentid.northwind.example")
scout = Agent.restore(json.load(open("scout.json")))

@guard(client=client, agent=scout,
       action="email.send", resource="mail:outbound",
       params=lambda to, subject, **_: {"to": to, "subject": subject},
       reason=lambda **kw: "Send the requested brief")
def send_email(to: str, subject: str, body: str) -> str:
    ...  # runs only with a receipt in hand`,
  'MCP gateway': `# Put any MCP server behind AgentID. The model never sees the key.
node gateway/cli.js \\
  --agent scout.json \\
  --authority https://agentid.northwind.example \\
  --stdio "npx -y @modelcontextprotocol/server-github"

# or proxy a Streamable HTTP server
node gateway/cli.js --agent scout.json --upstream https://mcp.example/mcp`,
  'LangGraph': `from langgraph.prebuilt import create_react_agent
from agentid.adapters import guard

@tool
@guard(client=client, agent=scout, action="web.fetch",
       resource=lambda url: url, reason=lambda url: f"Research: {url}")
def fetch(url: str) -> str:
    return httpx.get(url).text

graph = create_react_agent(model, tools=[fetch])`,
  'OpenAI Agents': `from agents import Agent, function_tool
from agentid.adapters import guard

@function_tool
@guard(client=client, agent=courier, action="travel.book",
       resource=lambda route, **_: f"travel:airline/{route}",
       params=lambda amount, cabin, **_: {"amount": amount, "currency": "USD", "cabin": cabin})
def book_flight(route: str, amount: float, cabin: str) -> str: ...

agent = Agent(name="Courier", tools=[book_flight])`,
  'Claude Agent SDK': `import { tool, createSdkMcpServer } from '@anthropic-ai/claude-agent-sdk';
import { withAgentID } from 'agentid/sdk/adapters';

const send = withAgentID(sendPayment, { client, agent: ledgerline,
  action: 'payments.send', resource: (a) => 'vendor:' + a.vendor,
  params: (a) => ({ amount: a.amount, currency: 'USD' }) });

const server = createSdkMcpServer({ name: 'payments',
  tools: [tool('send_payment', 'Pay an approved invoice', schema, send)] });`,
  CrewAI: `from crewai.tools import tool
from agentid.adapters import guard

@tool("Query the warehouse")
@guard(client=client, agent=scout, action="data.read",
       resource=lambda table, **_: f"warehouse:{table}",
       params=lambda classification, **_: {"classification": classification})
def query(table: str, classification: str) -> str: ...`,
};

export function render(ctx) {
  const { app } = ctx;
  const siemLines = [];
  let siemEl;

  const card = (cls, label, title, blurb, ...body) => h('section.sheet.int-card.' + cls,
    h('span.label', {}, label), h('h2', {}, title), h('p.note', {}, blurb), ...body);

  const btn = (text, fn, ghost) => {
    const b = h('button.btn' + (ghost ? '.ghost' : '') + '.small', { type: 'button' }, text);
    b.addEventListener('click', async () => {
      b.disabled = true;
      try { await fn(); } catch (e) { toast(e.message); } finally { b.disabled = false; }
    });
    return b;
  };

  const out = (el, ...nodes) => {
    fill(el, ...nodes);
    if (gsap && !reducedMotion()) gsap.from(el.children, { y: 8, opacity: 0, duration: 0.35, stagger: 0.05, ease: 'power2.out' });
  };

  // ------------------------------------------------------------ MCP

  const mcpOut = h('div.int-out');
  const flow = h('div.flow',
    h('div.flow-node', { 'data-n': 'agent' }, h('b', {}, 'Scout'), h('span', {}, 'MCP client')),
    h('div.flow-wire', h('i.packet')),
    h('div.flow-node.gw', { 'data-n': 'gw' }, h('b', {}, 'AgentID gateway'), h('span', {}, 'signs · checks')),
    h('div.flow-wire.second', h('i.packet')),
    h('div.flow-node', { 'data-n': 'up' }, h('b', {}, 'GitHub'), h('span', {}, 'MCP server')),
  );
  async function runMcp(kind) {
    const r = await ctx.run((b) => b.mcp(kind));
    const ok = !!r.forwarded;
    animateFlow(ok);
    out(mcpOut,
      h('div.io', h('span.label', {}, 'tools/call from the model'), h('pre', {}, json({ name: r.request.params.name, arguments: r.request.params.arguments, _meta: r.request.params._meta }))),
      h('div.io', h('span.label', {}, ok ? 'Forwarded upstream, receipt attached' : 'Answered by the gateway'),
        h('pre.' + (ok ? 'ok' : 'bad'), {}, ok
          ? json({ name: r.forwarded.params.name, _meta: { 'agentid/receipt': { action: r.forwarded.params._meta['agentid/receipt'].action, ledgerSeq: r.forwarded.params._meta['agentid/receipt'].ledgerSeq, proof: '…' } } })
          : json({ error: { code: r.response.error.code, message: r.response.error.message, data: { failedAt: r.response.error.data?.failedAt } } }))),
    );
  }
  function animateFlow(ok) {
    if (!gsap || reducedMotion()) return;
    const [p1, p2] = flow.querySelectorAll('.packet');
    const gw = flow.querySelector('.gw');
    gsap.set([p1, p2], { left: '0%', opacity: 0, backgroundColor: 'var(--intaglio)' });
    const tl = gsap.timeline();
    tl.to(p1, { opacity: 1, duration: 0.1 }).to(p1, { left: '100%', duration: 0.5, ease: 'power1.in' }).to(p1, { opacity: 0, duration: 0.1 })
      .to(gw, { scale: 1.06, duration: 0.15, yoyo: true, repeat: 1 });
    if (ok) tl.set(p2, { backgroundColor: 'var(--ok)' }).to(p2, { opacity: 1, duration: 0.1 }).to(p2, { left: '100%', duration: 0.5, ease: 'power1.out' }).to(p2, { opacity: 0, duration: 0.1 });
    else tl.to(gw, { borderColor: 'var(--deny)', duration: 0.1 }).to(gw, { x: 4, duration: 0.05, yoyo: true, repeat: 5 }).to(gw, { borderColor: '', x: 0, duration: 0.3, clearProps: 'all' });
  }

  // ------------------------------------------------------------ OAuth

  const oauthOut = h('div.int-out');
  async function runOauth(svid) {
    const r = await ctx.run((b) => b.oauth(svid));
    const [hd, pl, sg] = r.response.access_token.split('.');
    out(oauthOut,
      h('div.jwt', h('span.j-h', {}, hd), '.', h('span.j-p', {}, pl.slice(0, 120) + '…'), '.', h('span.j-s', {}, sg)),
      h('div.io-row',
        h('div.io', h('span.label', {}, 'Header'), h('pre', {}, json(r.header))),
        h('div.io', h('span.label', {}, svid ? 'SPIFFE JWT-SVID claims' : 'RFC 9068 access-token claims'), h('pre', {}, json(r.payload))),
      ),
      h('p.dim', {}, `Exchanged a receipt for ${r.receipt.action} via RFC 8693 token exchange. Any OAuth resource server verifies it against /.well-known/jwks.json; no AgentID code needed. Each receipt can be exchanged once.`),
    );
  }

  // ------------------------------------------------------------ VC

  const vcOut = h('div.int-out');
  const vcSelect = h('select.int-select', { 'aria-label': 'Agent' });
  async function runVc() {
    const r = await ctx.run((b) => b.credential(vcSelect.value));
    const c = r.credential;
    out(vcOut,
      h('div.vc-badge.' + (r.verified.ok ? 'ok' : 'bad'), {}, r.verified.ok ? 'Proof verifies · eddsa-jcs-2022' : 'Proof does not verify'),
      h('pre', {}, json({ '@context': c['@context'], type: c.type, issuer: c.issuer, validUntil: c.validUntil, credentialSubject: { ...c.credentialSubject, runtime: '…' }, proof: { type: c.proof.type, cryptosuite: c.proof.cryptosuite, proofValue: c.proof.proofValue.slice(0, 32) + '…' } })),
    );
  }

  // ------------------------------------------------------------ Federation

  const fedOut = h('div.int-out');
  const fedStage = h('div.fed-stage');
  function drawFed() {
    const w = app.snap.world;
    fill(fedStage, 
      h('div.fed-side', sigil(w.partner.did, 54), h('b', {}, w.partner.authority), h('span.dim', {}, `${w.partner.agent} lives here`)),
      h('div.fed-lane', h('i.fed-token'), h('span.dim', {}, 'receipt')),
      h('div.fed-side', sigil(app.snap.authority.did, 54), h('b', {}, 'Northwind authority'), h('span.dim', {}, `trusts: ${(app.snap.federation?.[0]?.actions || []).join(', ') || '—'}`)),
    );
  }
  async function runFed(kind) {
    const r = await ctx.run((b) => b.federation(kind));
    const ok = r.here.ok;
    if (gsap && !reducedMotion()) {
      const tok = fedStage.querySelector('.fed-token');
      gsap.fromTo(tok, { left: '0%', opacity: 1, backgroundColor: 'var(--intaglio)' }, { left: ok ? '100%' : '62%', duration: 0.8, ease: ok ? 'power2.inOut' : 'power2.out', onComplete: () => gsap.to(tok, { backgroundColor: ok ? 'var(--ok)' : 'var(--deny)', opacity: ok ? 1 : 0, y: ok ? 0 : 20, duration: 0.4 }) });
    }
    out(fedOut,
      h('div.fed-result.' + (ok ? 'ok' : 'bad'),
        h('span.verdict.v-' + (ok ? 'allow' : 'deny'), {}, ok ? 'Accepted' : 'Rejected'),
        h('span', {}, ok
          ? `${r.partner?.agent || 'Contoso Dispatch'} updated a Northwind shipment with a receipt from ${r.here.via}. Northwind never saw its keys or mandate; it trusts Contoso for shipments only.`
          : `Contoso’s own authority cleared the request, but Northwind only agreed to trust Contoso for shipments and invoices: ${r.here.reason}.`),
      ),
    );
  }

  // ------------------------------------------------------------ Slack

  const slackEl = h('div.slack');
  function drawSlack() {
    const ap = app.snap.approvals.find((a) => a.status === 'pending');
    if (!ap) {
      fill(slackEl, h('div.sl-empty', {}, 'No request is waiting. ', btn('Stage a large payment', async () => { await ctx.run((b) => b.attack('cosign')); await ctx.refresh(); drawSlack(); }, true)));
      return;
    }
    const approve = btn('Approve', async () => decide(ap, 'approve'));
    const decline = btn('Decline', async () => decide(ap, 'decline'), true);
    fill(slackEl, 
      h('div.sl-msg',
        h('div.sl-avatar', {}, 'ID'),
        h('div.sl-body',
          h('div.sl-head', h('b', {}, 'AgentID'), h('span.sl-app', {}, 'APP'), h('span.dim', {}, clock(ap.createdAt))),
          h('div.sl-text', h('b', {}, `${ap.agentName} needs a co-sign`), h('br'), h('code', {}, `${ap.action} → ${ap.resource}`), ap.amount ? ` · ${money(ap.amount)}` : ''),
          ap.reason ? h('div.sl-quote', {}, ap.reason) : null,
          h('div.sl-fields', h('span', {}, h('b', {}, 'Held because '), ap.reasons.join('; ')), h('span', {}, h('b', {}, 'Risk '), String(ap.risk?.score ?? 0))),
          h('div.sl-actions', approve, decline),
        ),
      ),
    );
  }
  async function decide(ap, decision) {
    const r = await ctx.run((b) => b.approve(ap.id, decision));
    await ctx.refresh();
    toast(r.status === 'approved' ? `Approved from Slack with Okafor’s approver key. ${ap.agentName} got its receipt.` : 'Declined from Slack.');
    drawSlack();
  }

  // ------------------------------------------------------------ SIEM

  function siemRecord(d) {
    const sev = { allow: 'INFO', step_up: 'WARN', deny: 'ERROR' }[d.decision] || 'INFO';
    return { timeUnixNano: String(d.ts * 1e6), severityText: sev, body: { stringValue: `${d.agentName} ${d.action} → ${d.decision}` }, attributes: [
      { key: 'agentid.agent', value: { stringValue: short(d.agent) } },
      { key: 'agentid.decision', value: { stringValue: d.decision } },
      ...(d.failedAt ? [{ key: 'agentid.failed_at', value: { stringValue: d.failedAt } }] : []),
      { key: 'agentid.ledger_seq', value: { intValue: String(d.ledgerSeq) } },
    ] };
  }
  function pushSiem(d) {
    siemLines.unshift(siemRecord(d));
    siemLines.length = Math.min(siemLines.length, 6);
    if (!siemEl) return;
    const line = h('pre.siem-line.' + (d.decision === 'allow' ? 'ok' : d.decision === 'deny' ? 'bad' : 'hold'), {}, JSON.stringify(siemLines[0]));
    siemEl.prepend(line);
    while (siemEl.children.length > 6) siemEl.lastElementChild.remove();
    if (gsap && !reducedMotion()) gsap.from(line, { height: 0, opacity: 0, duration: 0.3 });
  }
  siemEl = h('div.siem');
  for (const d of app.decisions.slice(-5)) pushSiem(d);
  const off = ctx.onDecision(pushSiem);

  // ------------------------------------------------------------ Policy as code

  const editor = h('textarea.policy-editor', { spellcheck: 'false', 'aria-label': 'Policy source' });
  const policyOut = h('div.policy-out');
  let baseline = null;
  function policyFromSnapshot() {
    const agents = app.snap.world.agents;
    const roots = app.snap.mandates.filter((m) => !m.parent && m.status === 'active');
    const specs = roots.map((m) => ({
      label: m.label, subject: agents.find((a) => a.did === m.sub)?.key || m.sub,
      caps: m.caps, budget: m.budget, rate: m.rate, cosign: m.cosign, depth: m.depth, ttlSec: null,
    }));
    return dsl.format(specs);
  }
  function checkPolicy() {
    try {
      const specs = dsl.parse(editor.value);
      const warns = dsl.lint(specs);
      const d = baseline ? dsl.diff(baseline, specs) : null;
      fill(policyOut, 
        h('div.p-status.ok', {}, `Parses · ${specs.length} mandates · ${warns.length} lint warning${warns.length === 1 ? '' : 's'}`),
        d?.widened ? h('div.p-status.bad', {}, '!! This change widens authority. CI would block it (exit 2).') : d && d.mandates.some((m) => m.status !== 'unchanged') ? h('div.p-status.ok', {}, 'Change only narrows authority.') : null,
        d && d.mandates.some((m) => m.status !== 'unchanged') ? h('pre.p-diff', {}, dsl.formatDiff(d).split('\n').filter((l) => !/^UNCHANGED/.test(l)).join('\n')) : null,
        warns.length ? h('ul.p-warn', warns.slice(0, 4).map((w) => h('li', {}, h('code', {}, w.code), ' ', w.message))) : null,
      );
    } catch (e) {
      fill(policyOut, h('div.p-status.bad', {}, e.message));
    }
  }
  editor.addEventListener('input', checkPolicy);

  // ------------------------------------------------------------ SDK tabs

  const code = h('pre.code');
  const tabs = h('div.tabs', { role: 'tablist' }, Object.keys(SNIPPETS).map((name, i) => {
    const t = h('button.tab', { type: 'button', role: 'tab', 'aria-selected': String(i === 0) }, name);
    t.addEventListener('click', () => {
      for (const x of tabs.children) x.setAttribute('aria-selected', String(x === t));
      code.textContent = SNIPPETS[name];
      if (gsap && !reducedMotion()) gsap.from(code, { opacity: 0, y: 6, duration: 0.25 });
    });
    return t;
  }));
  code.textContent = SNIPPETS.TypeScript;

  const root = h('div.integrations',
    h('div.section-head',
      h('div',
        h('span.label.kicker', {}, 'Fits your stack'),
        h('h1', {}, 'Works with what you ', h('em', {}, 'already run.')),
      ),
      h('p', {}, 'Agents don’t need a new protocol stack to adopt this. Tool calls go through an MCP gateway, receipts become ordinary OAuth tokens, passports export as W3C credentials, approvals land in Slack and decisions stream to your SIEM. Each card below runs against the live authority.'),
    ),
    h('div.int-grid',
      card('mcp', 'Model Context Protocol', 'Every tool call, checked.', 'The gateway sits between the model and any MCP server. It holds the agent’s key, turns each tools/call into a signed intent, and forwards only what the mandate allows, with the receipt attached.',
        flow, h('div.row-actions', btn('Search issues (in mandate)', () => runMcp('allowed')), btn('Delete repository (not in mandate)', () => runMcp('blocked'), true)), mcpOut),
      card('oauth', 'OAuth 2.0 · SPIFFE', 'Receipts become standard tokens.', 'Existing APIs already accept OAuth bearer tokens. The authority exchanges a receipt for a short-lived EdDSA JWT (RFC 8693 / RFC 9068) or a SPIFFE JWT-SVID for service meshes.',
        h('div.row-actions', btn('Exchange for an access token', () => runOauth(false)), btn('Issue a JWT-SVID', () => runOauth(true), true)), oauthOut),
      card('vc', 'W3C Verifiable Credentials', 'Passports anyone can verify.', 'Export a passport as a VC 2.0 credential with a Data Integrity proof (eddsa-jcs-2022) and did:key identifiers, so wallets and verifiers outside AgentID can check it.',
        h('div.row-actions', vcSelect, btn('Export credential', runVc)), vcOut),
      card('fed', 'Federation', 'Partners’ agents, on your terms.', 'Contoso Freight runs its own authority. Northwind signed an agreement to accept Contoso receipts for shipments and invoices only, so a Contoso agent can update a delivery but can never collect a payment here.',
        fedStage, h('div.row-actions', btn('Update a shipment', () => runFed('allowed')), btn('Collect a payment', () => runFed('overreach'), true)), fedOut),
      card('slack', 'Slack · Teams', 'Approve where people already are.', 'Held requests are posted with Approve and Decline buttons. Clicks are verified with Slack’s signing secret and mapped to an approver key, so a Slack account alone can’t approve more than that key allows.',
        slackEl),
      card('siem', 'SIEM export', 'Every decision in your SIEM.', 'Decisions, approvals, revocations and freezes stream as OTLP logs, Splunk HEC events or plain webhooks, batched with retries. These are the OTLP records for the live traffic.',
        siemEl),
      card('policy', 'Policy as code', 'Mandates in review, like code.', 'Mandates can be written in a small language, linted, and diffed in CI. Try raising Ledgerline’s amount limit: the diff flags that authority widens.',
        editor, policyOut),
      card('sdk', 'SDKs', 'Two lines around any tool.', 'JavaScript and Python SDKs with the same signatures and canonical JSON (tested against each other), plus wrappers for popular agent frameworks.',
        tabs, code),
    ),
  );

  root.mounted = () => {
    fill(vcSelect, ...app.snap.world.agents.map((a) => h('option', { value: a.key }, a.name)));
    drawFed();
    drawSlack();
    editor.value = policyFromSnapshot();
    try { baseline = dsl.parse(editor.value); } catch { baseline = null; }
    checkPolicy();
    if (gsap && !reducedMotion()) gsap.from(root.querySelectorAll('.int-card'), { y: 22, opacity: 0, duration: 0.5, stagger: 0.05, ease: 'power3.out', clearProps: 'all' });
  };
  let lastAp = '';
  root.refresh = (snap) => {
    const sig = snap.approvals.filter((a) => a.status === 'pending').map((a) => a.id).join();
    if (sig !== lastAp) { lastAp = sig; drawSlack(); }
  };
  root.destroy = () => off();
  return root;
}
