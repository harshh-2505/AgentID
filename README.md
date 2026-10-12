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

## Run it

Requires Node 20 or newer. The authority itself has no runtime dependencies; `npm install` only adds `pg` (optional, for Postgres) and PGlite (tests).

```bash
npm install
npm test          # 93 tests: protocol, attacks, keys, passkeys, Merkle, Postgres, Nitro, OAuth, VC, MCP, policy, fuzzing, Python interop
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

Press **Tour** (or open the console with `?tour`) for a guided, 18-stop walk through everything below. Each stop runs a real action against the authority and spotlights the result.

| Tab | What you can do |
| --- | --- |
| Checkpoint | Watch live traffic go through the ten checks, then run any of the ten attacks: large payment, replay, stolen identity, prompt-injected exfiltration, subtle injection, tampered runtime, sub-agent escalation, runaway loop, leaked old key, and the kill switch. |
| Passports | The trust graph and each agent's passport, with a key-derived guilloche face and an ICAO-style machine readable zone. Revoke an agent and watch the cascade. |
| Mandates | Every grant, with live budget meters. Try a delegation from Ledgerline to its sub-agent; the authority refuses anything wider than the parent. |
| Co-sign | Held requests with the reasons and risk signals. Approve with the finance lead's capped approver key or with a passkey. |
| Ledger | The signed hash chain. Edit an entry in your view and the verifier names the exact entry where it breaks. |
| Keys | The kill switch, passkeys, the principal's key ring (root, operational, approver), 2-of-3 guardian recovery, agent key rotation, and Merkle checkpoints co-signed by a witness. |
| Stack | Live demos of the MCP gateway, OAuth token exchange and SPIFFE, W3C credentials, federation with a partner org, Slack co-sign, SIEM records, the policy language with a widening diff, and SDK snippets. |
| Why | Why the product is shaped this way. |

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

## Adopting it

- **MCP:** `node gateway/cli.js --agent scout.json --authority https://… --stdio "npx -y @modelcontextprotocol/server-github"` puts any MCP server behind the checkpoint; the model never sees the agent's key.
- **Your own tools:** wrap them with `withAgentID` (JS, `sdk/adapters.js`) or `@guard` (Python, `sdk-python`). Snippets for LangGraph, the OpenAI Agents SDK, the Claude Agent SDK and CrewAI are in `examples/frameworks/`.
- **Existing APIs:** exchange a receipt at `/oauth/token` and send the JWT; the API verifies it with the JWKS like any other OAuth token.
- **Mandates in review:** keep them in `.agentid` files; `node policy/cli.js diff old new` exits 2 when authority widens, which makes a CI gate.

## Running it in production

See [docs/DEPLOY.md](docs/DEPLOY.md). In short: `AGENTID_MODE=production`, a sign-up gate (`AGENTID_OIDC_ISSUER` or `AGENTID_ADMIN_TOKEN`), the authority key in an encrypted file or Vault, and `AGENTID_DATABASE_URL` for Postgres so several authority processes can share one database without double-spending a budget or accepting a replay twice. The security design and its limits are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md); how to report a vulnerability is in [SECURITY.md](SECURITY.md).

## What is real and what is simulated

Real: Ed25519 signatures, passport and mandate chain verification, attenuation, limits, cumulative budgets, rate limits, replay protection, co-sign by principal keys, capped approver keys, passkeys (WebAuthn verification of real authenticators) and guardian quorums, key rotation and guardian recovery, the kill switch, offline-verifiable receipts, cascading revocation, the signed hash chain, Merkle checkpoints with consistency proofs and witnesses, cosign image signatures, Nitro attestation document verification, OIDC admission, the encrypted key file and Vault signer, the Postgres store, OAuth/SPIFFE tokens, W3C credentials, federation, the MCP gateway and the policy language. All of it is covered by tests.

Simulated in the demo: the runtime host attests a manifest hash instead of a hardware quote (the Nitro verifier exists, but the demo has no enclave); in the hosted demo, passkeys fall back to a virtual authenticator when the page can't reach a real one; the risk model is a transparent heuristic; the Slack card in the console is a preview of the real message. No external security audit has been done yet.

## Credits

Motion by [GSAP](https://github.com/greensock/GSAP) 3.13 (core, ScrambleText, Flip, DrawSVG, SplitText), vendored in `web/vendor/` under GreenSock's standard no-charge license. I also looked at [Motion](https://github.com/motiondivision/motion), [anime.js](https://github.com/juliangarnier/anime) and [Lenis](https://github.com/darkroomengineering/lenis); GSAP was chosen because its timelines and text plugins carry the inspection sequence, and the console needs one library, not four. Fonts: Bodoni Moda, Archivo and IBM Plex Mono from Google Fonts.
