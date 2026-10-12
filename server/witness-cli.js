#!/usr/bin/env node
// Runs an independent witness against one AgentID authority.
//
//   AGENTID_URL=https://authority.example.com \
//   WITNESS_KEY_PASSPHRASE=... node server/witness-cli.js
//
// Environment:
//   AGENTID_URL             authority base URL (or first CLI argument)            required
//   WITNESS_AUTHORITY_DID   only vouch for this authority DID (recommended: pin it)
//   WITNESS_NAME            name shown next to co-signatures                       default: hostname
//   WITNESS_INTERVAL        seconds between rounds                                 default: 30
//   WITNESS_STATE           where co-signed checkpoints and alarms are kept        default: data/witness-state.json
//   WITNESS_KEY_FILE        encrypted witness key, created on first run            default: data/witness-key.json
//   WITNESS_KEY_PASSPHRASE  passphrase for that file                               required
//
// The witness must run under a different operator, key and machine than the authority;
// otherwise its signature adds nothing.

import os from 'node:os';
import { loadFileSigner } from './keystore.js';
import { createWitness, pollOnce } from './witness.js';

const env = process.env;
const url = process.argv[2] || env.AGENTID_URL;
if (!url) {
  console.error('usage: AGENTID_URL=<authority url> WITNESS_KEY_PASSPHRASE=... node server/witness-cli.js');
  process.exit(2);
}
const interval = Math.max(1, Number(env.WITNESS_INTERVAL || 30)) * 1000;

const signer = await loadFileSigner({ path: env.WITNESS_KEY_FILE || 'data/witness-key.json', passphrase: env.WITNESS_KEY_PASSPHRASE });
const witness = await createWitness({
  signer,
  name: env.WITNESS_NAME || os.hostname(),
  store: env.WITNESS_STATE || 'data/witness-state.json',
  authorities: env.WITNESS_AUTHORITY_DID ? [env.WITNESS_AUTHORITY_DID] : null,
});

console.log(`witness ${witness.name}  ${witness.did}`);
console.log(`watching ${url} every ${interval / 1000}s`);

let stopping = false;
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { stopping = true; });

while (!stopping) {
  try {
    const c = await pollOnce({ witness, url });
    console.log(`${new Date().toISOString()}  co-signed size ${c.checkpoint.size}  root ${c.checkpoint.root.slice(0, 16)}…`);
  } catch (e) {
    if (e.alarm) {
      // Loud on purpose: this is evidence the authority showed two histories.
      console.error(`${new Date().toISOString()}  ALARM ${e.alarm.kind}: ${e.alarm.message}`);
      console.error(JSON.stringify({ previous: e.alarm.previous, offered: e.alarm.offered }));
      process.exitCode = 3;
    } else {
      console.warn(`${new Date().toISOString()}  round failed: ${e.message}`);
    }
  }
  await new Promise((r) => { const t = setTimeout(r, interval); if (stopping) clearTimeout(t); });
}
