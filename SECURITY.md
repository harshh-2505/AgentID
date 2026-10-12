# Security policy

AgentID is security software, so reports are welcome and handled first.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Include what you found, how to reproduce it and what an attacker gains. You will get an acknowledgement within three working days and a fix or a plan within fourteen.

## Scope

In scope: anything that lets a request be allowed that the checks should refuse, lets a co-sign, key update, freeze or revocation be forged or replayed, leaks a private key, rewrites the ledger without detection, or makes two authority processes disagree about a nonce or budget. Also bugs in the SDKs, the MCP gateway, the OAuth bridge and the integrations that produce the same outcomes.

Out of scope: the demo organisation's keys (they are generated for the demo and saved in `data/`), denial of service against a single development server, and findings that need an attacker who already holds a principal's root key.

## Status

The code has unit, property-based and cross-language tests, but it has not had an external audit yet. Treat it as pre-1.0. The design, assumptions and known limits are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
