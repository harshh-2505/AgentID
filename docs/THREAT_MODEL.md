# Threat model

What AgentID defends against, what it assumes, and where its limits are. Each defence names the code that implements it and the test that shows it.

## Assets

1. **Authority to act**: the ability to make a service do something on an organisation's behalf (pay, email, read data, call a tool).
2. **Keys**: agent keys, principal keys (root, operational, approver), guardian keys, passkeys, the authority key, witness keys.
3. **The record**: the ledger of decisions, approvals, key changes and freezes.

## Trust assumptions

- The **authority** evaluates requests honestly. It is a single point of policy, so it is also the thing that must be observable: every decision is signed into a Merkle log, and independent **witnesses** co-sign checkpoints only if the log extends what they saw before. A dishonest authority can refuse service, but cannot rewrite or fork history without witnesses holding signed evidence.
- **Relying services** verify receipts (or the OAuth tokens minted from them) and refuse anything without one. A service that skips verification is outside AgentID's protection.
- **Runtime hosts** report what they run truthfully, or are hardware-backed (Nitro) so they cannot lie. A compromised host that signs a false measurement defeats proof of runtime for the agents it hosts, and only those.
- **Principals' root keys** are kept offline. Day-to-day work uses operational keys.

## Adversaries and defences

| Adversary | What they try | Defence | Where |
| --- | --- | --- | --- |
| Prompt injection | Make an agent do something its owner didn't intend | The model never holds a key or token. Each action is checked against a signed mandate's scope and limits, at every link of the delegation chain. Override language raises the risk score and holds the request. | `core/authority.js` steps 6–9; attacks `injection`, `subtle` |
| Credential thief | Use an agent's identifier without its key | Every intent is signed by the agent key; the identifier is the public key. | step 1; attack `forged` |
| Network attacker | Replay a captured request or receipt | Intents are single-use (nonce claimed in the store transaction) and live at most 5 minutes. Receipts are short-lived; the SDK middleware and the OAuth bridge accept each receipt once. | step 2; `test/hardening.test.js` concurrency, `sdk/index.js` |
| Code swap | Run different code, prompt or tools under an approved identity | Passports pin a measurement of model, prompt, tools and code; optionally a container digest with a cosign signature from an endorsed publisher, or Nitro PCRs. | step 4; attack `tamper`; image and Nitro tests |
| Rogue or runaway agent | Spend beyond intent, loop, escalate through sub-agents | Cumulative budgets across the whole delegation tree, rate limits, depth limits, strict attenuation at registration and at every request. | steps 5–8; attacks `escalate`, `runaway`; `test/property.test.js` |
| Leaked agent key | Act after the key was copied | Short-lived agent keys; a new passport `supersedes` the old one and retires it. Revocation cascades to sub-agents and pending approvals. | `registerPassport`, `revoke`; attack `leaked` |
| Stolen operational key | Issue mandates or revoke agents | Keys have roles. A routine rotation retires a key for anything signed afterwards; marking it compromised distrusts everything it ever signed. | `updateKeys`, `#signedBy`; key tests |
| Lost root key | Lock the organisation out, or take it over | Root changes need a root signature or k-of-n recovery guardians over the exact update; the organisation keeps its identifier. | `updateKeys`; recovery test |
| Phished or coerced approver | Approve a payment that shouldn't happen | Approvals sign the hash of one request. Approver keys are capped (`maxAmount`). Mandates can require a passkey with user verification, which an agent or a remote attacker cannot produce. Approvals re-check revocation and freeze before release. | `resolveApproval`; passkey tests |
| Insider at 3 a.m. | Do damage faster than anyone can react | One signed Freeze stops every agent under a principal and declines waiting approvals. | `setFreeze`; attack `frozen` |
| Rogue authority operator | Hide a decision, change history | Signed hash chain, Merkle checkpoints, witness co-signatures with consistency proofs; fork and rollback alarms. | `core/merkle.js`, `server/witness.js` |
| Two authority processes racing | Double-spend a budget or accept a replay twice | All writes run in a transaction under one Postgres advisory lock; nonces are unique rows. | `server/store/postgres.js`; two-instance tests |
| Partner organisation | Use federation to act beyond what was agreed | Federation agreements list the actions trusted from each partner; receipts for anything else are rejected. | `core/federation.js`; federation test |
| Spam sign-ups | Register principals to probe or abuse the authority | Production mode admits principals only with an OIDC ID token bound to the registration, or an admin token. | `server/auth.js` |
| Slack account takeover | Approve via a hijacked chat account | Clicks are verified with Slack's signing secret and mapped to a configured approver key with its own cap; the Slack user alone is not an identity. | `server/integrations/slack.js` |

## Issues found by our own testing

The property-based tests in `test/property.test.js` found three problems, all fixed:

- `*` in capability patterns did not match line breaks, so `payroll.\nrun` slipped past a `cosign always for payroll.*` rule. Patterns now match any character.
- `canonical()` produced invalid JSON for `undefined` inside arrays. It now writes `null`, like `JSON.stringify`.
- A signature string had several accepted spellings (padding, unused tail bits). Signatures must now be exactly 86 canonical base64url characters.

## Known limits

- **No external audit yet.** Treat it as pre-1.0.
- **Retired-key timing.** A key removed without the compromised flag is trusted for records whose `iat` is before removal. `iat` is self-asserted, so if a key may have been copied, mark it compromised (and re-issue what it signed) rather than simply rotating it.
- **Risk scoring** is a transparent heuristic, not a model. It catches obvious override language, bursts and unusual amounts; it is a reason to hold, never a reason to allow.
- **Host attestation without hardware** is as trustworthy as the host that signs it. Use Nitro (or add a verifier for your TEE) where that matters.
- **Single lock per database** serialises writes. Shard by principal to scale beyond one database.
- **Freeze and revocation** take effect at the authority. A service that caches receipts must honour their short lifetime.
- **Demo state** (`data/world.json`) contains private keys by design and must never be used in production.
