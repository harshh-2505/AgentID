# AgentID

Identity, authorization and co-sign for autonomous AI agents.

Agents today borrow a person's credentials. That gives no attribution, no scoping, no clean revocation and no safe delegation to sub-agents, and human 2FA does not help, because anything an agent can read an injected prompt can read too. AgentID gives every agent its own passport and checks every request it makes against three machine factors plus an optional human co-sign:

| Factor | What it proves | How |
| --- | --- | --- |
| Proof of key | This exact request came from this agent | Per-agent Ed25519 key held by the runtime, never in the model context. Every intent is signed, single-use and short-lived. |
| Proof of runtime | The agent is running the code it was passported for | The host attests a hash of model + system prompt + tools + code. Any change breaks the match. |
| Proof of mandate | Someone accountable allowed this | A signed chain of grants from a principal. Each link can only narrow scope, limits, budget, rate and lifetime. |
| Co-sign | A person (or k-of-n guardian agents) agreed to this specific request | Policy or risk holds the request; the principal signs its hash. Only then does the agent get a receipt. |

The full reasoning is in [docs/THESIS.md](docs/THESIS.md) and in the console's *Reasoning* tab.

## What's in the box

```
core/       the protocol, zero dependencies, runs in Node 20+ and in browsers
  keys.js         Ed25519 via WebCrypto, self-certifying did:agentid identifiers
  policy.js       capabilities, limits, attenuation checks
  actors.js       Principal, Attestor (runtime host), AgentRuntime
  authority.js    registry, 10-step verifier, risk, co-sign, revocation, receipts
  ledger.js       signed hash-chained decision log + verifier
  demo-world.js   a sample organisation, background traffic and 8 attacks
server/     the authority as an HTTP service (zero dependencies)
sdk/        what agents, approval apps and services import
examples/   an autonomous agent and a payments service that requires receipts
web/        the console (vanilla JS + GSAP)
test/       node:test suite
```

## Run it

Requires Node 20 or newer. There is nothing to install.

```bash
npm test          # 13 tests: crypto, attenuation, budgets, co-sign, quorum, revocation, ledger, every attack
npm start         # authority + console on http://localhost:4600
```

Then, in two more terminals, see a real agent and a real relying service talk to it:

```bash
npm run service   # payments API on :4700 that only accepts AgentID receipts
npm run agent     # registers an org and an agent, pays, gets held, is co-signed, is tampered with, is revoked
```

Expected agent output:

```
Pay 320 USD to blue-line           ALLOW   all checks passed
  Call payments service (320)      HTTP 200 paid 320 USD to blue-line …
  Reuse the same receipt           HTTP 409 receipt already used
Pay 1,400 USD to north-rail        STEP_UP Co-sign: amount above 500
  …principal reviews "Quarterly rail contract, PO 7731" and co-signs
  after co-sign                    ALLOW   all checks passed
  Call payments service (1400)     HTTP 200 paid 1400 USD to north-rail …
Pay after runtime tampering        DENY    Proof of runtime: runtime changed since the passport was issued …
Pay after revocation               DENY    Passport chain: Ferry was revoked: Runtime drift detected
Ledger intact: 20 entries verified.
```

State is saved to `data/world.json` (demo keys included, so keep it out of version control; `.gitignore` already does). Delete it to start fresh, or use *Reset demo organisation* in the console.

The console also runs with no server at all: open it from any static host (or add `?local` to the URL) and the same authority code runs inside the tab. That is how the hosted demo works.

## The console

| Tab | What you can do |
| --- | --- |
| Checkpoint | Watch live traffic go through the ten checks, then run any of the eight attacks: large payment, replay, stolen identity, prompt-injected exfiltration, subtle injection, tampered runtime, sub-agent escalation, runaway loop. |
| Passports | The trust graph and each agent's passport, with a key-derived guilloche face and an ICAO-style machine readable zone. Revoke an agent and watch the cascade. |
| Mandates | Every grant, with live budget meters. Try a delegation from Ledgerline to its sub-agent; the authority refuses anything wider than the parent. |
| Co-sign | Held requests with the reasons and risk signals. Co-signing produces a real Ed25519 signature over the request hash. |
| Ledger | The signed hash chain. Edit an entry in your view and the verifier names the exact entry where it breaks. |
| Reasoning | Why the product is shaped this way. |

*UV light* switches to the dark theme, styled as the passport under UV inspection.

## Protocol API

All bodies are signed JSON objects (`proof: { alg: "Ed25519", kid: <did>, sig }` over canonical JSON).

| Method | Path | Body |
| --- | --- | --- |
| GET | `/.well-known/agentid` | — returns the authority identifier |
| POST | `/v1/principals` | `PrincipalRegistration`, self-signed |
| POST | `/v1/attestors` | `AttestorEndorsement`, signed by a principal |
| POST | `/v1/passports` | `AgentPassport`, signed by a principal or a parent agent |
| POST | `/v1/mandates` | `Mandate`, signed by a principal or by the holder of the parent mandate |
| POST | `/v1/intents` | `Intent`, signed by the agent; returns the decision, the trace and, when cleared, a `Receipt` |
| GET | `/v1/approvals/:id` | status of a held request (and its receipt once co-signed) |
| GET | `/v1/approvals/:id/request` | the full held request, for an approval app |
| POST | `/v1/approvals/:id/cosign` | `CoSign`, signed by the principal or a guardian |
| POST | `/v1/revocations` | `Revocation`, signed by an issuer up the chain |
| GET | `/v1/ledger`, `/v1/ledger/verify` | entries, and a full recomputation |

SDK in one screen:

```js
import { AgentRuntime, Principal, Attestor, AuthorityClient, requireReceipt } from './sdk/index.js';

const client = new AuthorityClient('http://localhost:4600');
const org = await Principal.create({ name: 'Acme' });
await client.registerPrincipal(await org.registration());

const agent = await AgentRuntime.create({ name: 'Ferry', purpose: '…', model: '…', manifest });
agent.passport = await org.issuePassport(agent);
agent.mandate  = await org.issueMandate({ sub: agent.did, caps: [...], budget: {...}, cosign: { above: 500 } });
await client.registerPassport(agent.passport);
await client.registerMandate(agent.mandate);

const result = await client.act(agent, { action: 'payments.send', resource: 'vendor:x', params: { amount: 90, currency: 'USD' }, reason: '…' });
// result.decision: allow | step_up | deny; result.receipt goes to the service

// In the service:
app.use(requireReceipt({ authority: authorityDid, aud: 'payments', expect: (req, r) => … }));
```

## What is real and what is simulated

Real: Ed25519 signatures through WebCrypto, passport and mandate chain verification, attenuation, limits, cumulative budgets across sub-agents, rate limits, replay protection, co-sign by principal or guardian quorum, offline-verifiable receipts, cascading revocation, and the signed hash chain.

Simulated: the runtime host measures a manifest object instead of producing a hardware attestation quote; principal keys live in memory instead of a passkey or secure enclave; the risk model is a transparent heuristic; principal registration is open (in production it sits behind the organisation's SSO).

## Next steps

Passkey-backed co-sign (WebAuthn), confidential-computing attestation (Nitro Enclaves, confidential VMs and GPUs), an MCP gateway that requires a receipt per tool call, bridges to OAuth token exchange (RFC 8693), SPIFFE and W3C verifiable credentials, and federation between authorities.

## Credits

Motion by [GSAP](https://github.com/greensock/GSAP) 3.13 (core, ScrambleText, Flip, DrawSVG, SplitText), vendored in `web/vendor/` under GreenSock's standard no-charge license. I also looked at [Motion](https://github.com/motiondivision/motion), [anime.js](https://github.com/juliangarnier/anime) and [Lenis](https://github.com/darkroomengineering/lenis); GSAP was chosen because its timelines and text plugins carry the inspection sequence, and the console needs one library, not four. Fonts: Bodoni Moda, Archivo and IBM Plex Mono from Google Fonts.
