# Identity for agents is not identity for people

How I approached the problem, what the product is, and why it is shaped this way.

## The problem with borrowed identity

Most agents today act with a person’s credentials: an API key pasted into an environment variable, an OAuth token minted for a human, a browser session cookie. That works while a person watches every step. It breaks once agents run on their own, for four reasons.

- **No attribution.** The logs say the person did it. When an agent misbehaves you cannot tell which agent, which version, or on whose instruction.
- **No scoping.** The token carries everything the person can do, so an agent hired to pay one invoice can also wire money anywhere.
- **No clean revocation.** Pulling a misbehaving agent means rotating the person’s own credentials and breaking everything else they use.
- **No delegation.** Agents spawn sub-agents. Shared secrets get copied down the tree and nobody can say who holds what.

## Why 2FA does not translate

Second factors assume a human who can read a code from a separate device. An agent that can read the code can be told to read it out by a poisoned web page, an email or a tool result. The second factor collapses into the first. Agents need factors that the model itself never sees and cannot be talked into revealing.

| Human factor | What AgentID uses instead |
| --- | --- |
| Something you know | **Nothing.** Secrets leak through prompts. No password or bearer token ever enters the model’s context. |
| Something you have | **Proof of key.** A per-agent Ed25519 key held by the runtime, outside the model. Every request is signed, single-use and expires within minutes, so a captured request is worthless. |
| Something you are | **Proof of runtime.** The host measures the model, system prompt, tool list and code, and signs that measurement. If any of it changes, the passport no longer matches. |
| Permission | **Proof of mandate.** A signed chain of grants from a principal. Each link can only narrow scope, limits, budget, rate and lifetime. |
| Push approval | **Co-sign.** Policy or a risk signal holds the request. A principal (or k of n guardian agents) signs the hash of that exact request. The agent receives a receipt only afterwards. |

## What the product is

I considered a browser extension, a desktop wallet and a pure SDK. An extension only covers agents that live in a browser. A wallet puts keys on a person’s machine when the agents run in the cloud. A bare SDK has no shared place to revoke, to co-sign or to audit. So AgentID is three pieces:

- **The authority**, a small self-hostable service. It registers principals, passports and mandates, verifies every intent through ten checks, holds risky ones for co-sign, keeps the revocation list and writes a signed, hash-chained ledger. It holds exactly one private key: its own.
- **The SDK**, for three audiences. Agents use it to sign intents and wait for co-signs. Principals use it to issue passports, mandates and revocations. Services use it to check receipts offline against the authority’s public identifier, with one middleware call.
- **The console**, where people see live traffic, inspect passports, delegate, co-sign and audit.

## Design decisions

- **Self-certifying identifiers.** `did:agentid:<public key>` means anyone can check a signature without a lookup.
- **Attenuation only.** Like macaroons and Biscuit tokens, a delegated mandate can never exceed its parent. The authority checks every link, not just the leaf.
- **Cumulative budgets.** A sub-agent’s spend counts against every mandate above it, so splitting work across sub-agents cannot multiply a budget.
- **Fail closed.** A limit that names a parameter the request omits is a refusal, not a pass.
- **Explainable risk.** Risk is a list of named signals with points (first contact, bursts, unusual amounts, instruction-override language), so a person can see why something was held.
- **Receipts, not sessions.** A cleared request yields a receipt signed by the authority, bound to that request. Services verify it offline and reject reuse.
- **Cascading revocation.** Revoking an agent voids every sub-agent and mandate below it on the next request, and declines anything it had waiting.

- **Keys are expected to fail.** Principals hold a key ring with roles (root, operational, approver); roots are replaced by a guardian quorum; agent keys are short-lived and superseded; one signature freezes everything.
- **An observable authority.** The ledger is a Merkle log with checkpoints that independent witnesses co-sign, so the authority itself is accountable.
- **Meet existing systems where they are.** MCP gateway, OAuth token exchange, SPIFFE, W3C credentials, Slack approvals, SIEM export, and federation between authorities.

## What is real in this build, and what is simulated

**Real:** Ed25519 signatures, passport and mandate chains, attenuation, limits, budgets, rate limits, replay protection, co-sign with capped approver keys, passkeys and guardian quorums, key rotation and recovery, the kill switch, receipts, cascading revocation, the signed hash chain, Merkle checkpoints and witnesses, image signatures and Nitro attestation verification, the Postgres store, OIDC admission, the OAuth, SPIFFE and VC bridges, federation, the MCP gateway and the policy language. The same core runs in the Node server and, for the hosted demo, inside your browser tab.
**Simulated in the demo:** the runtime host measures a manifest object rather than producing a hardware quote; passkeys fall back to a virtual authenticator when the page cannot reach a real one; the risk model is a transparent heuristic.

## Where it goes next

- An external security audit, then a 1.0 protocol freeze.
- More attestation formats: Azure and Google confidential VMs, NVIDIA confidential GPUs, TPM quotes.
- Approval apps for phones that hold the approver key in the secure enclave.
- Hosted witnesses run by independent parties, and a public log explorer.
