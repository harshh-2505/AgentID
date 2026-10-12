// Server configuration, from environment variables only (see docs/DEPLOY.md).

const list = (v) => (v ? v.split(',').map((s) => s.trim()).filter(Boolean) : []);

export function loadConfig(env) {
  const mode = env.AGENTID_MODE === 'production' ? 'production' : 'demo';
  const port = Number(env.PORT || 4600);
  const issuer = (env.AGENTID_ISSUER || `http://localhost:${port}`).replace(/\/$/, '');
  const origin = new URL(issuer);
  const oidc = env.AGENTID_OIDC_ISSUER
    ? { issuer: env.AGENTID_OIDC_ISSUER, audience: env.AGENTID_OIDC_AUDIENCE, allowedDomains: list(env.AGENTID_OIDC_DOMAINS) }
    : null;
  const adminToken = env.AGENTID_ADMIN_TOKEN || null;
  // Production refuses to start with an open sign-up unless explicitly asked for.
  const dev = mode === 'demo' || env.AGENTID_DEV === '1';
  if (mode === 'production' && !oidc && !adminToken && !dev) {
    throw new Error('production mode needs AGENTID_OIDC_ISSUER or AGENTID_ADMIN_TOKEN (or AGENTID_DEV=1 for an open, unsafe sign-up)');
  }
  return {
    mode, port, issuer, name: env.AGENTID_NAME || 'AgentID authority',
    admission: { oidc, adminToken, dev },
    admissionMode: mode === 'demo' ? 'demo' : oidc ? 'oidc' : adminToken ? 'admin-token' : 'open (dev)',
    databaseUrl: env.AGENTID_DATABASE_URL || null,
    storeKind: env.AGENTID_DATABASE_URL ? 'postgres' : 'memory',
    keyProvider: env.AGENTID_KEY_PROVIDER || (mode === 'production' ? 'file' : 'ephemeral'),
    keyFile: env.AGENTID_KEY_FILE || 'data/authority-key.json',
    keyPassphrase: env.AGENTID_KEY_PASSPHRASE || null,
    vault: { addr: env.VAULT_ADDR, token: env.VAULT_TOKEN, key: env.AGENTID_VAULT_KEY || 'agentid', mount: env.AGENTID_VAULT_MOUNT || 'transit' },
    webauthn: { rpId: env.AGENTID_RP_ID || origin.hostname, origins: list(env.AGENTID_RP_ORIGINS).length ? list(env.AGENTID_RP_ORIGINS) : [origin.origin] },
    nitro: env.AGENTID_NITRO === '1' ? { rootPem: env.AGENTID_NITRO_ROOT_PEM || null } : null,
    slack: env.SLACK_SIGNING_SECRET ? {
      signingSecret: env.SLACK_SIGNING_SECRET, webhookUrl: env.SLACK_WEBHOOK_URL, botToken: env.SLACK_BOT_TOKEN, channel: env.SLACK_CHANNEL,
      approvers: env.SLACK_APPROVERS ? JSON.parse(env.SLACK_APPROVERS) : {},
    } : null,
    teams: env.TEAMS_WEBHOOK_URL ? { webhookUrl: env.TEAMS_WEBHOOK_URL, sharedSecret: env.TEAMS_SHARED_SECRET } : null,
    siem: env.AGENTID_SIEM_URL ? { kind: env.AGENTID_SIEM_KIND || 'webhook', url: env.AGENTID_SIEM_URL, token: env.AGENTID_SIEM_TOKEN } : null,
    spiffeTrustDomain: env.AGENTID_SPIFFE_TRUST_DOMAIN || origin.hostname,
  };
}
