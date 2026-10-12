// VI. Reasoning: why the product is shaped this way. Static content.

import { h, gsap, reducedMotion } from '../dom.js';

const ESSAY = `
<h2>The problem with <em>borrowed identity</em></h2>
<p>Most agents today act with a person’s credentials: an API key pasted into an environment variable, an OAuth token minted for a human, a browser session cookie. That works while a person watches every step. It breaks once agents run on their own, for four reasons.</p>
<ul>
  <li><b>No attribution.</b> The logs say the person did it. When an agent misbehaves you cannot tell which agent, which version, or on whose instruction.</li>
  <li><b>No scoping.</b> The token carries everything the person can do, so an agent hired to pay one invoice can also wire money anywhere.</li>
  <li><b>No clean revocation.</b> Pulling a misbehaving agent means rotating the person’s own credentials and breaking everything else they use.</li>
  <li><b>No delegation.</b> Agents spawn sub-agents. Shared secrets get copied down the tree and nobody can say who holds what.</li>
</ul>

<h2>Why 2FA does not <em>translate</em></h2>
<p>Second factors assume a human who can read a code from a separate device. An agent that can read the code can be told to read it out by a poisoned web page, an email or a tool result. The second factor collapses into the first. Agents need factors that the model itself never sees and cannot be talked into revealing.</p>
<div class="table-wrap"><table class="compare">
  <thead><tr><th class="label">Human factor</th><th class="label">What AgentID uses instead</th></tr></thead>
  <tbody>
    <tr><td>Something you know</td><td><b>Nothing.</b> Secrets leak through prompts. No password or bearer token ever enters the model’s context.</td></tr>
    <tr><td>Something you have</td><td><b>Proof of key.</b> A per-agent Ed25519 key held by the runtime, outside the model. Every request is signed, single-use and expires within minutes, so a captured request is worthless.</td></tr>
    <tr><td>Something you are</td><td><b>Proof of runtime.</b> The host measures the model, system prompt, tool list and code, and signs that measurement. If any of it changes, the passport no longer matches.</td></tr>
    <tr><td>Permission</td><td><b>Proof of mandate.</b> A signed chain of grants from a principal. Each link can only narrow scope, limits, budget, rate and lifetime.</td></tr>
    <tr><td>Push approval</td><td><b>Co-sign.</b> Policy or a risk signal holds the request. A principal (or k of n guardian agents) signs the hash of that exact request. The agent receives a receipt only afterwards.</td></tr>
  </tbody>
</table></div>

<h2>What the product <em>is</em></h2>
<p>I considered a browser extension, a desktop wallet and a pure SDK. An extension only covers agents that live in a browser. A wallet puts keys on a person’s machine when the agents run in the cloud. A bare SDK has no shared place to revoke, to co-sign or to audit. So AgentID is three pieces:</p>
<ul>
  <li><b>The authority</b>, a small self-hostable service. It registers principals, passports and mandates, verifies every intent through ten checks, holds risky ones for co-sign, keeps the revocation list and writes a signed, hash-chained ledger. It holds exactly one private key: its own.</li>
  <li><b>The SDK</b>, for three audiences. Agents use it to sign intents and wait for co-signs. Principals use it to issue passports, mandates and revocations. Services use it to check receipts offline against the authority’s public identifier, with one middleware call.</li>
  <li><b>The console</b> you are looking at, where people see live traffic, inspect passports, delegate, co-sign and audit.</li>
</ul>

<h2>Design decisions</h2>
<ul>
  <li><b>Self-certifying identifiers.</b> <code>did:agentid:&lt;public key&gt;</code> means anyone can check a signature without a lookup.</li>
  <li><b>Attenuation only.</b> Like macaroons and Biscuit tokens, a delegated mandate can never exceed its parent. The authority checks every link, not just the leaf.</li>
  <li><b>Cumulative budgets.</b> A sub-agent’s spend counts against every mandate above it, so splitting work across sub-agents cannot multiply a budget.</li>
  <li><b>Fail closed.</b> A limit that names a parameter the request omits is a refusal, not a pass.</li>
  <li><b>Explainable risk.</b> Risk is a list of named signals with points (first contact, bursts, unusual amounts, instruction-override language), so a person can see why something was held.</li>
  <li><b>Receipts, not sessions.</b> A cleared request yields a receipt signed by the authority, bound to that request. Services verify it offline and reject reuse.</li>
  <li><b>Cascading revocation.</b> Revoking an agent voids every sub-agent and mandate below it on the next request, and declines anything it had waiting.</li>
</ul>

<h2>What is real in this build, and what is <em>simulated</em></h2>
<p><b>Real:</b> Ed25519 keys and signatures through WebCrypto, passport and mandate chain verification, attenuation, limits, budgets, rate limits, replay protection, co-sign with principal keys and guardian quorums, receipts, cascading revocation and the signed hash chain. The same code runs in the Node server and, for this hosted demo, inside your browser tab.</p>
<p><b>Simulated:</b> the runtime host measures a manifest object rather than producing a hardware attestation quote; the principal’s key lives in memory rather than in a passkey or secure enclave; the risk model is a transparent heuristic.</p>

<h2>Where it goes <em>next</em></h2>
<ul>
  <li>Passkey-backed co-sign, so approving a held request is a Face ID tap that produces a WebAuthn signature.</li>
  <li>Hardware attestation from confidential computing hosts (AWS Nitro Enclaves, Azure and Google confidential VMs, NVIDIA confidential GPUs).</li>
  <li>An MCP gateway that requires a receipt before any tool call, so every MCP server gets agent identity for free.</li>
  <li>Bridges to existing standards: OAuth 2.0 token exchange (RFC 8693) for legacy APIs, SPIFFE for workload identity, W3C verifiable credentials for passports.</li>
  <li>Federation between authorities, so one company’s agent can be recognised by another company’s services.</li>
</ul>
`;

export function render() {
  const root = h('div.reasoning',
    h('div.section-head',
      h('div',
        h('span.label.kicker', {}, 'Reasoning'),
        h('h1', {}, 'Identity for agents is ', h('em', {}, 'not'), ' identity for people.'),
      ),
      h('p', {}, 'How I approached the problem, what the product is, and why it is shaped this way.'),
    ),
  );
  const essay = h('article.essay');
  essay.innerHTML = ESSAY;
  root.append(essay);
  root.mounted = () => {
    if (!gsap || reducedMotion()) return;
    gsap.from(essay.children, { y: 12, opacity: 0, duration: 0.5, stagger: 0.04, ease: 'power2.out', clearProps: 'all' });
  };
  return root;
}
