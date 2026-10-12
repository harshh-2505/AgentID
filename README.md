<div align="center">

# Agent<i>ID</i>

### Passport control for software that acts on its own.

Identity, authorization and a real second factor for autonomous AI agents.<br>
Every agent gets its own keys, its own passport and signed limits, and every action it takes is checked before it runs.

[![Live demo](https://img.shields.io/badge/live_demo-open_the_console-1f4e79?style=for-the-badge)](https://agentid-pi.vercel.app)
[![Guided tour](https://img.shields.io/badge/guided_tour-18_stops_·_3_min-15803d?style=for-the-badge)](https://agentid-pi.vercel.app/?tour)

[![CI](https://github.com/harshh-2505/AgentID/actions/workflows/ci.yml/badge.svg)](https://github.com/harshh-2505/AgentID/actions/workflows/ci.yml)
![Node 20+](https://img.shields.io/badge/node-20%2B-339933?logo=node.js&logoColor=white)
![Python SDK](https://img.shields.io/badge/python_SDK-3.9%2B-3776AB?logo=python&logoColor=white)
![Zero runtime deps](https://img.shields.io/badge/core-zero_dependencies-555)
![License MIT](https://img.shields.io/badge/license-MIT-blue)

<br>

<img src="docs/screenshots/tour.gif" alt="The guided tour: real attacks being stopped at the exact check that catches them" width="880">

<sub>The guided tour runs real attacks against a real authority in your browser and spotlights the check that stops each one.</sub>

</div>

---

## The problem

AI agents now pay invoices, send email, open pull requests and call each other. Almost all of them do it with **a borrowed human identity**: someone's API key, OAuth token or session cookie pasted into the agent's environment.

That breaks everything identity is supposed to give you:

- **No attribution.** The logs say *Priya* paid the invoice. Which of her five agents did it, running which prompt?
- **No scoping.** The agent can do anything the human can, so one prompt injection can do anything the human can.
- **No clean revocation.** Killing a misbehaving agent means rotating a human's credentials and breaking everything else.
- **No safe delegation.** Sub-agents inherit the whole key.
- **Human 2FA doesn't help.** Anything an agent can read (an SMS code, an email link), an injected prompt can read too.

## The idea

AgentID treats an agent like a traveller at a border. It carries a **passport** (who it is, vouched for by an accountable organisation), a **visa** (a mandate: exactly what it may do, within what limits), and every request crosses a **checkpoint** that verifies all of it before anything executes.

| | What it proves | How |
| --- | --- | --- |
| 🔑 **Proof of key** | This exact request came from this agent | A per-agent Ed25519 key held by the runtime, never in the model's context. Every request is signed, single-use and expires in seconds. |
| 🧬 **Proof of runtime** | The agent runs the code it was approved for | The host attests a hash of model, system prompt, tools and code (or a signed container image, or AWS Nitro PCRs). Change anything and the identity no longer matches. |
| 📜 **Proof of mandate** | Someone accountable allowed this | A signed chain of grants from an organisation. Each link can only **narrow** scope, limits, budget, rate and lifetime, never widen them. |
| ✍️ **Co-sign** | A human agreed to *this specific* request | Risky requests are held. A person signs the hash of that one request with a capped key or a passkey (fingerprint or face). An agent can read a code; it can't press your finger. |

Everything is recorded in a **signed, Merkle-tree ledger** that independent witnesses co-sign, so the authority itself can't quietly rewrite history.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent runtime<br/>(holds its own key)
    participant C as AgentID checkpoint
    participant H as Human approver
    participant S as Target service
    A->>C: signed intent: payments.send $1,180 to harbor-cloud
    Note over C: 1 key · 2 freshness · 3 passport chain · 4 runtime<br/>5 mandate chain · 6 scope · 7 limits · 8 budget & rate<br/>9 behavioural risk · 10 co-sign policy
    C-->>A: held: amount above $750
    C->>H: approve this exact request?
    H->>C: passkey signature over the request hash
    C-->>A: signed receipt (short-lived, single-use)
    A->>S: action + receipt
    S->>S: verify receipt offline against the authority's key
    S-->>A: done
```

## See it in 60 seconds

**Open the [live console](https://agentid-pi.vercel.app) and press _Tour_.** Nothing to install: the whole authority runs inside your browser tab with real Ed25519 signatures. The 18 stops walk through identity, mandates, three real attacks, a passkey approval, the kill switch, guardian recovery of a lost master key, a witnessed checkpoint, and the integrations. Arrow keys move between stops.

Or poke at it yourself:

1. **Checkpoint → _Try to break it_.** Run any of ten attacks (stolen identity, replay, prompt-injected exfiltration, tampered runtime, sub-agent escalation, runaway loop, leaked old key…) and watch the desk stop at the exact check that catches it.
2. **Co-sign.** Approve a held $1,180 payment with the finance lead's capped key, or with a passkey.
3. **Keys.** Lift the cover and freeze every agent with one signature. Then recover the organisation's lost root key with 2 of 3 guardians.
4. **Ledger.** Edit a historical entry in your view; the verifier names the exact entry where the chain breaks.
5. **UV light.** Flip the theme to inspect the passports under ultraviolet.

## Screenshots

<table>
<tr>
<td width="50%"><img src="docs/screenshots/checkpoint.png" alt="Checkpoint"><br><b>Checkpoint.</b> Live agent traffic passing ten checks, each stamped and written to the ledger.</td>
<td width="50%"><img src="docs/screenshots/attack-blocked.png" alt="Prompt injection blocked"><br><b>Prompt injection, refused.</b> Scout really signed it, so identity passes. Its mandate only allows mail to the company domain, so check 07 stops it before anything runs.</td>
</tr>
<tr>
<td><img src="docs/screenshots/tour.png" alt="Guided tour"><br><b>Guided tour.</b> Every stop runs a real action and spotlights the result.</td>
<td><img src="docs/screenshots/cosign.png" alt="Co-sign"><br><b>Co-sign.</b> A second factor for software: the human signs one exact request, with a capped key or a passkey.</td>
</tr>
<tr>
<td><img src="docs/screenshots/registry.png" alt="Passports"><br><b>Passports.</b> The trust graph and each agent's passport, with a guilloche face derived from its key and a machine-readable zone.</td>
<td><img src="docs/screenshots/mandates.png" alt="Mandates"><br><b>Mandates.</b> Every grant with live budget meters. Delegations wider than the parent are refused.</td>
</tr>
<tr>
<td><img src="docs/screenshots/tour-freeze.png" alt="Kill switch"><br><b>Kill switch.</b> One signed Freeze stops every agent and sub-agent instantly and declines anything waiting.</td>
<td><img src="docs/screenshots/keys.png" alt="Keys and trust"><br><b>Keys &amp; trust.</b> Root, operational and approver keys with roles, passkeys, guardian recovery and agent key rotation.</td>
</tr>
<tr>
<td><img src="docs/screenshots/ledger.png" alt="Ledger"><br><b>Ledger.</b> A signed hash chain with Merkle checkpoints. Tamper with it and the verifier points at the break.</td>
<td><img src="docs/screenshots/integrations.png" alt="Stack"><br><b>Stack.</b> MCP gateway, OAuth and SPIFFE tokens, W3C credentials, federation, Slack, SIEM and a policy language, each with a live demo.</td>
</tr>
<tr>
<td><img src="docs/screenshots/uv-dark.png" alt="UV light theme"><br><b>UV light.</b> The dark theme, styled as a passport under ultraviolet inspection.</td>
<td align="center"><img src="docs/screenshots/mobile.png" alt="Mobile" width="260"><br><b>Mobile.</b> The whole console, tour included, works on a phone.</td>
</tr>
</table>

## What attacks it stops

| Attack | Stopped at | Why it fails |
| --- | --- | --- |
| Stolen identity | Proof of key | The identifier *is* the public key; without the private key the signature fails. |
| Replay | Freshness | Every request carries a single-use nonce and expires in seconds. |
| Prompt-injected exfiltration | Limits | The model can be fooled; the signed mandate can't. Mail outside the company domain is out of bounds. |
| Subtle injection | Behavioural risk | Override language in the agent's reasoning raises the risk score and holds the request for a human. |
| Tampered runtime | Proof of runtime | An extra tool changes the runtime measurement, so it no longer matches the passport. |
| Sub-agent escalation | Scope | A read-only sub-agent can't send a payment; delegation only narrows. |
| Runaway loop | Budget & rate | Cumulative budgets and rate limits across the whole delegation tree. |
| Large payment | Co-sign | Held until a human signs that exact request. |
| Leaked old key | Passport chain | Rotation retires the old passport; the old key is worthless. |
| Rogue agent at 3 a.m. | Kill switch | One Freeze signature refuses everything from every agent. |

The full analysis, including what AgentID does **not** defend against, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Run it locally

Requires Node 20 or newer. The authority has no runtime dependencies; `npm install` only adds `pg` (optional, for Postgres) and PGlite (for tests).

```bash
git clone https://github.com/harshh-2505/AgentID && cd AgentID
npm install
npm test          # protocol, attacks, keys, passkeys, Merkle, Postgres, Nitro, OAuth, VC, MCP, policy, fuzzing, Python interop
npm start         # authority + console on http://localhost:4600
```

Then, in two more terminals, watch a real agent and a real relying service talk to it:

```bash
npm run service   # a payments API on :4700 that only accepts AgentID receipts
npm run agent     # registers an org and an agent, pays, gets held, is co-signed, is tampered with, is revoked
```

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

Demo state is saved to `data/world.json` (demo keys included, and git-ignored). Delete it to start fresh, or use *Reset demo organisation* in the console.

### Deploy the console

The console also runs with no server at all: the same authority code runs inside the tab. That's how the live demo is hosted.

```bash
npm run build:static   # writes dist/, deployable to any static host
```

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fharshh-2505%2FAgentID&project-name=agentid)

`vercel.json` already sets the build command and output directory. To run the **authority** as a real service (Postgres, sign-up gate, key in Vault), see [docs/DEPLOY.md](docs/DEPLOY.md).

## What's in the box

```
core/         the protocol, zero dependencies, runs in Node 20+ and in browsers
  keys.js           Ed25519 via WebCrypto, did:agentid identifiers, ExternalSigner for KMS/Vault
  policy.js         capabilities, limits, attenuation checks
  actors.js         Principal (key ring, recovery, freeze), Attestor, AgentRuntime (rotation)
  authority.js      registry, 10-step verifier, risk, co-sign, passkeys, revocation, receipts,
                    key updates, kill switch, Merkle checkpoints, witnesses, federation
  store.js          storage interface + transactional in-memory store
  merkle.js         RFC 9162 Merkle tree: inclusion and consistency proofs
  webauthn.js       passkey registration and assertion verification (CBOR, COSE)
  attestation.js    runtime evidence formats, cosign (Sigstore) image signatures
  federation.js     trust bundles and federated receipt checks
  oauth.js          RFC 8693 token exchange, RFC 9068 JWTs, SPIFFE JWT-SVIDs, JWKS
  vc.js             W3C VC 2.0 export (eddsa-jcs-2022, did:key)
  demo-world.js     the demo organisation, a partner org, traffic and 10 attacks
server/       the authority as an HTTP service
  server.js         routes, demo and production modes
  auth.js           sign-up gate: OIDC ID tokens (JWKS), admin token
  keystore.js       authority key: encrypted file (AES-GCM + scrypt) or Vault transit
  store/postgres.js Postgres store, safe across many authority processes
  attestation/nitro.js  AWS Nitro Enclaves attestation documents
  witness.js, witness-cli.js  independent checkpoint witness
  integrations/     Slack and Teams co-sign, SIEM export (webhook, Splunk HEC, OTLP)
gateway/      MCP gateway: Streamable HTTP proxy and stdio wrapper
policy/       policy-as-code language, linter, semantic diff, CLI
sdk/          JS SDK and tool wrappers (sdk/adapters.js)
sdk-python/   Python SDK and @guard decorator, cross-tested against the JS code
examples/     an autonomous agent, a relying service, framework snippets
web/          the console (vanilla JS + GSAP) with a guided tour
test/         node:test suite (unit, property-based, cross-language, Postgres, Nitro)
docs/         THESIS, THREAT_MODEL, DEPLOY
```

## Adopting it

- **MCP:** `node gateway/cli.js --agent scout.json --authority https://… --stdio "npx -y @modelcontextprotocol/server-github"` puts any MCP server behind the checkpoint; the model never sees the agent's key.
- **Your own tools:** wrap them with `withAgentID` (JS, `sdk/adapters.js`) or `@guard` (Python, `sdk-python`). Snippets for LangGraph, the OpenAI Agents SDK, the Claude Agent SDK and CrewAI are in [`examples/frameworks/`](examples/frameworks/).
- **Existing APIs:** exchange a receipt at `/oauth/token` and send the JWT; the API verifies it with the JWKS like any other OAuth token.
- **Mandates in review:** keep them in `.agentid` files; `node policy/cli.js diff old new` exits 2 when authority widens, which makes a CI gate.

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
| POST | `/v1/approvals/:id/cosign` | `CoSign` signed by a principal key or a guardian, or `PasskeyCoSign` (a WebAuthn assertion) |
| POST | `/v1/revocations` | `Revocation`, signed by an issuer up the chain |
| POST | `/v1/principals/:did/keys` | `KeyUpdate` plus approvals: one root signature, or k recovery-guardian signatures |
| POST | `/v1/principals/:did/freeze` | `Freeze` (kill switch on or off), signed by a root or operational key |
| POST | `/v1/principals/:did/passkeys` | `PasskeyEnrollment`: a WebAuthn registration, signed by the principal |
| POST | `/v1/publishers` | `PublisherEndorsement`: a cosign key allowed to sign the principal's images |
| POST | `/v1/federation` | `Federation`: accept a partner authority's `TrustBundle` for named actions |
| POST | `/v1/federation/receipts` | check a partner's receipt against the agreements |
| GET | `/v1/trust-bundle` | this authority's signed trust bundle |
| GET | `/v1/ledger`, `/v1/ledger/verify` | entries, and a full recomputation |
| GET | `/v1/checkpoint`, `/v1/proofs/inclusion`, `/v1/proofs/consistency` | signed Merkle checkpoint and proofs |
| POST | `/v1/witness` | a witness co-signature on a checkpoint |
| GET | `/v1/passports/:id/credential` | the passport as a W3C Verifiable Credential |
| POST | `/oauth/token` | RFC 8693 token exchange: receipt or intent → access token or JWT-SVID |
| GET | `/.well-known/jwks.json`, `/.well-known/oauth-authorization-server`, `/.well-known/spiffe-bundle` | keys and metadata for OAuth and SPIFFE |
| POST | `/integrations/slack/actions`, `/integrations/teams/actions` | interactive co-sign callbacks |

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

## Running it in production

See [docs/DEPLOY.md](docs/DEPLOY.md). In short: `AGENTID_MODE=production`, a sign-up gate (`AGENTID_OIDC_ISSUER` or `AGENTID_ADMIN_TOKEN`), the authority key in an encrypted file or Vault, and `AGENTID_DATABASE_URL` for Postgres so several authority processes can share one database without double-spending a budget or accepting a replay twice. The security design and its limits are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md); how to report a vulnerability is in [SECURITY.md](SECURITY.md).

## What is real and what is simulated

Real: Ed25519 signatures, passport and mandate chain verification, attenuation, limits, cumulative budgets, rate limits, replay protection, co-sign by principal keys, capped approver keys, passkeys (WebAuthn verification of real authenticators) and guardian quorums, key rotation and guardian recovery, the kill switch, offline-verifiable receipts, cascading revocation, the signed hash chain, Merkle checkpoints with consistency proofs and witnesses, cosign image signatures, Nitro attestation document verification, OIDC admission, the encrypted key file and Vault signer, the Postgres store, OAuth/SPIFFE tokens, W3C credentials, federation, the MCP gateway and the policy language. All of it is covered by tests.

Simulated in the demo: the runtime host attests a manifest hash instead of a hardware quote (the Nitro verifier exists, but the demo has no enclave); in the hosted demo, passkeys fall back to a virtual authenticator when the page can't reach a real one; the risk model is a transparent heuristic; the Slack card in the console is a preview of the real message. No external security audit has been done yet.

## Credits

Motion by [GSAP](https://github.com/greensock/GSAP) 3.13 (core, ScrambleText, Flip, DrawSVG, SplitText), vendored in `web/vendor/` under GreenSock's standard no-charge license. I also looked at [Motion](https://github.com/motiondivision/motion), [anime.js](https://github.com/juliangarnier/anime) and [Lenis](https://github.com/darkroomengineering/lenis); GSAP was chosen because its timelines and text plugins carry the inspection sequence, and the console needs one library, not four. Fonts: Bodoni Moda, Archivo and IBM Plex Mono from Google Fonts.
