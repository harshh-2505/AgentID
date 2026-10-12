# Deploying the authority

The same `server/server.js` runs the demo and a real deployment. Everything is configured with environment variables.

## Minimal production setup

```bash
export AGENTID_MODE=production
export AGENTID_ISSUER=https://agentid.example.com          # public base URL (OAuth issuer, passkey origin)
export AGENTID_OIDC_ISSUER=https://login.example.com        # who may register principals
export AGENTID_OIDC_AUDIENCE=agentid
export AGENTID_OIDC_DOMAINS=example.com
export AGENTID_KEY_PROVIDER=file
export AGENTID_KEY_PASSPHRASE=…                             # from your secret manager
export AGENTID_DATABASE_URL=postgres://agentid@db/agentid
npm ci --omit=dev && npm start
```

Production mode refuses to start without a sign-up gate. It serves only the protocol API, not the demo console.

## Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `AGENTID_MODE` | `demo` | `production` disables the demo organisation and turns the sign-up gate on |
| `PORT` | `4600` | listen port |
| `AGENTID_ISSUER` | `http://localhost:$PORT` | public base URL; also the passkey relying-party ID and origin |
| `AGENTID_NAME` | `AgentID authority` | name in the trust bundle |
| `AGENTID_RP_ID`, `AGENTID_RP_ORIGINS` | from the issuer | override the WebAuthn relying party (comma-separated origins) |
| `AGENTID_OIDC_ISSUER`, `AGENTID_OIDC_AUDIENCE`, `AGENTID_OIDC_DOMAINS` | — | admit principals with an ID token from your identity provider (keys fetched from its JWKS) |
| `AGENTID_ADMIN_TOKEN` | — | admit principals that present this token (simple setups, CI) |
| `AGENTID_DEV` | — | `1` allows open sign-up in production mode; never use it on a reachable host |
| `AGENTID_KEY_PROVIDER` | `file` in production | `file`, `vault` or `ephemeral` |
| `AGENTID_KEY_FILE`, `AGENTID_KEY_PASSPHRASE` | `data/authority-key.json` | encrypted authority key (AES-256-GCM, scrypt), created on first start |
| `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `AGENTID_VAULT_KEY`, `AGENTID_VAULT_MOUNT` | — | sign with a Vault transit `ed25519` key; the private key never leaves Vault |
| `AGENTID_DATABASE_URL` | — | Postgres; without it state is in memory |
| `AGENTID_NITRO`, `AGENTID_NITRO_ROOT_PEM` | — | `1` accepts AWS Nitro Enclaves attestation documents (pinned to the AWS root by default) |
| `AGENTID_SPIFFE_TRUST_DOMAIN` | issuer host | trust domain for JWT-SVIDs |
| `SLACK_SIGNING_SECRET`, `SLACK_WEBHOOK_URL` or `SLACK_BOT_TOKEN` + `SLACK_CHANNEL`, `SLACK_APPROVERS` | — | post held requests to Slack; `SLACK_APPROVERS` maps Slack user IDs to approver keys, e.g. `{"U123":{"key":"approver"}}` |
| `TEAMS_WEBHOOK_URL`, `TEAMS_SHARED_SECRET`, `TEAMS_APPROVERS` | — | post held requests to Teams |
| `SIEM_KIND`, `SIEM_URL`, `SIEM_TOKEN`, `SIEM_BATCH_MS`, `SIEM_INDEX`, `SIEM_EVENTS` | — | stream events as `webhook`, `splunk-hec` or `otlp` logs |
| `AGENTID_CONSOLE_URL` | — | link to put in Slack and Teams messages |

AWS KMS cannot sign Ed25519 today. To use KMS, CloudHSM, GCP KMS or an HSM, wrap its signing call in `ExternalSigner` from `core/keys.js` (see `server/keystore.js`).

## Several authority processes

Every write runs in a database transaction that takes one Postgres advisory lock, so nonces, budgets, approvals and the ledger sequence are consistent no matter which process handles a request. Reads do not take the lock. The lock serialises writes per database; to scale further, shard principals across databases (or lock keys), since nothing crosses principals.

## Witnesses

Run at least one witness that you do not operate yourself:

```bash
AGENTID_URL=https://agentid.example.com WITNESS_NAME="Audit firm" WITNESS_KEY_PASSPHRASE=… node server/witness-cli.js
```

It polls the checkpoint, verifies the consistency proof against the last checkpoint it signed, co-signs, and posts the co-signature back. If the authority ever presents a log that does not extend the previous one, it records a fork or rollback alarm, keeps both signed checkpoints as evidence and exits with code 3.

## MCP gateway

```bash
node gateway/cli.js --agent scout.json --authority https://agentid.example.com --stdio "npx -y @modelcontextprotocol/server-github"
node gateway/cli.js --agent scout.json --authority https://agentid.example.com --upstream https://mcp.example.com/mcp --port 4800
```

`scout.json` is the agent's exported key, passport and mandate (`AgentRuntime.export()`); keep it readable only by the gateway.
