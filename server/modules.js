// Wires the optional server modules (stores, key providers, attestation formats,
// bridges and integrations) into the authority according to the configuration.

import { MemoryStore } from '../core/store.js';
import { loadAuthoritySigner } from './keystore.js';
import { createAdmission } from './auth.js';
import { nitroVerifier } from './attestation/nitro.js';
import * as oauth from './oauth.js';
import * as vc from './vc.js';
import * as witness from './witness.js';
import * as slack from './integrations/slack.js';
import * as teams from './integrations/teams.js';
import * as siem from './integrations/siem.js';

export async function buildAuthorityOptions(config) {
  const opts = { webauthn: config.webauthn };
  opts.signer = await loadAuthoritySigner({
    provider: config.keyProvider,
    file: { path: config.keyFile, passphrase: config.keyPassphrase },
    vault: config.vault,
  });
  if (config.databaseUrl) {
    const { PostgresStore } = await import('./store/postgres.js');
    opts.store = await PostgresStore.connect(config.databaseUrl);
  } else {
    opts.store = new MemoryStore();
  }
  if (config.mode === 'production') opts.admit = createAdmission(config.admission);
  if (config.nitro) opts.attestation = { 'aws-nitro': nitroVerifier(config.nitro.rootPem ? { root: config.nitro.rootPem } : {}) };
  return opts;
}

export async function moduleRoutes(ctx) {
  const c = { ...ctx, config: { ...ctx.config, slack: slack.slackConfigFromEnv(), teams: teams.teamsConfigFromEnv(), spiffe: { trustDomain: ctx.config.spiffeTrustDomain } } };
  return [oauth, vc, witness, slack, teams].flatMap((m) => m.routes(c));
}

// Subscribes Slack, Teams and SIEM to the authority's events. Returns a detach function.
export async function attachIntegrations(authority, config) {
  const offs = [];
  const s = slack.slackConfigFromEnv();
  if (s && (s.webhookUrl || s.botToken)) offs.push(slack.attachSlack(authority, { slack: s }));
  const t = teams.teamsConfigFromEnv();
  if (t?.webhookUrl) offs.push(teams.attachTeams(authority, { teams: t }));
  const sc = siem.siemConfigFromEnv();
  if (sc) {
    const sink = siem.attachSiem(authority, sc);
    offs.push(() => sink.stop({ drain: true }));
  }
  if (offs.length) console.log(`Integrations: ${[s && 'Slack', t && 'Teams', sc && 'SIEM ' + sc.kind].filter(Boolean).join(', ')}`);
  return () => offs.forEach((off) => off());
}
