// Who may register a principal, and who may call admin routes.
//
// An open registry would let anyone mint principals, and with them passports and
// mandates, so production deployments put an admission gate in front of
// registerPrincipal. Two gates, usable together:
//   * adminToken  an operator-held secret (bootstrap, scripts, CI);
//   * oidc        an ID token from the organisation's identity provider (Google
//                 Workspace, Entra ID, Okta, ...), so "who registered this principal"
//                 is a verified corporate identity recorded in the ledger (admittedAs).
//
// The ID token must be bound to the registration it admits, otherwise one token could
// admit any key: the signed registration names the token's subject (reg.subject or
// reg.name equal to the email/sub), or the token's `nonce` is the principal's DID.

import { createHash, createPublicKey, timingSafeEqual, verify as nodeVerify } from 'node:crypto';

const JWKS_TTL_MS = 10 * 60 * 1000;
const JWKS_MIN_REFRESH_MS = 30 * 1000;
const SKEW_SEC = 60;
const ALGS = {
  RS256: { hash: 'sha256', kty: 'RSA' },
  ES256: { hash: 'sha256', kty: 'EC', crv: 'P-256', p1363: true },
  ES384: { hash: 'sha384', kty: 'EC', crv: 'P-384', p1363: true },
  EdDSA: { hash: null, kty: 'OKP', crv: 'Ed25519' },
};

const httpError = (status, message) => Object.assign(new Error(message), { status });
const b64uJson = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

// Constant-time compare of two secrets of any length.
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !a || !b) return false;
  const h = (s) => createHash('sha256').update(s).digest();
  return timingSafeEqual(h(a), h(b));
}

// ---------------------------------------------------------------- JWKS

// One cache per issuer. Keys are refetched after the TTL, or early when a token names a
// kid we have not seen (the provider rotated), but never more than every 30 seconds so a
// flood of junk kids cannot turn us into a request amplifier against the provider.
export function jwksClient({ issuer, jwksUrl, ttlMs = JWKS_TTL_MS, fetch: fetchFn = globalThis.fetch }) {
  let cache = { keys: [], at: 0 };
  let inflight = null;
  let uri = jwksUrl || null;

  const getJson = async (url) => {
    const res = await fetchFn(url, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`${url} answered ${res.status}`);
    return res.json();
  };

  async function refresh() {
    if (!uri) {
      const conf = await getJson(issuer.replace(/\/$/, '') + '/.well-known/openid-configuration');
      if (conf.issuer !== issuer) throw new Error('discovery document is for a different issuer');
      if (!conf.jwks_uri) throw new Error('issuer publishes no jwks_uri');
      uri = conf.jwks_uri;
    }
    const jwks = await getJson(uri);
    cache = { keys: Array.isArray(jwks.keys) ? jwks.keys : [], at: Date.now() };
  }

  const load = () => (inflight ||= refresh().finally(() => { inflight = null; }));

  return {
    async key(kid, alg) {
      const age = Date.now() - cache.at;
      const pick = () => cache.keys.find((k) => (kid ? k.kid === kid : true) && (!k.alg || k.alg === alg) && (!k.use || k.use === 'sig'));
      if (age > ttlMs) await load();
      let jwk = pick();
      if (!jwk && Date.now() - cache.at > JWKS_MIN_REFRESH_MS) { await load(); jwk = pick(); }
      return jwk || null;
    },
  };
}

// ---------------------------------------------------------------- JWT

// Verifies a compact JWS ID token. Returns the claims or throws with a reason.
export async function verifyIdToken(token, { issuer, audience, jwks, nowSec = Math.floor(Date.now() / 1000) }) {
  if (typeof token !== 'string') throw new Error('no ID token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('ID token is not a compact JWS');
  let header, claims;
  try { header = b64uJson(parts[0]); claims = b64uJson(parts[1]); } catch { throw new Error('ID token is not valid JSON'); }
  const alg = ALGS[header.alg];
  if (!alg) throw new Error(`ID token algorithm ${header.alg} is not accepted`); // rejects "none" and HS*
  const jwk = await jwks.key(header.kid, header.alg);
  if (!jwk) throw new Error('ID token is signed by an unknown key');
  if (jwk.kty !== alg.kty || (alg.crv && jwk.crv !== alg.crv)) throw new Error('ID token key does not match its algorithm');
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const ok = nodeVerify(alg.hash, Buffer.from(parts[0] + '.' + parts[1]), alg.p1363 ? { key, dsaEncoding: 'ieee-p1363' } : key, Buffer.from(parts[2], 'base64url'));
  if (!ok) throw new Error('ID token signature is invalid');

  if (claims.iss !== issuer) throw new Error('ID token is from a different issuer');
  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(audience)) throw new Error('ID token is for a different audience');
  if (auds.length > 1 && claims.azp && claims.azp !== audience) throw new Error('ID token was issued to a different party');
  if (typeof claims.exp !== 'number' || claims.exp < nowSec - SKEW_SEC) throw new Error('ID token expired');
  if (typeof claims.nbf === 'number' && claims.nbf > nowSec + SKEW_SEC) throw new Error('ID token is not valid yet');
  if (typeof claims.iat === 'number' && claims.iat > nowSec + SKEW_SEC) throw new Error('ID token is issued in the future');
  return claims;
}

// ---------------------------------------------------------------- admission

// Returns `admit(registration, evidence)` for the Authority's `admit` option.
//   dev         admit everything (local development only)
//   adminToken  evidence { adminToken }
//   oidc        evidence { idToken }; { issuer, audience, jwksUrl?, allowedDomains? }
export function createAdmission({ oidc, adminToken, dev = false, fetch: fetchFn } = {}) {
  const jwks = oidc ? jwksClient({ issuer: oidc.issuer, jwksUrl: oidc.jwksUrl, fetch: fetchFn }) : null;
  const domains = (oidc?.allowedDomains || []).map((d) => d.toLowerCase());

  return async function admit(reg, evidence) {
    if (dev) return { ok: true, subject: 'dev' };
    if (evidence?.adminToken !== undefined) {
      if (adminToken && safeEqual(evidence.adminToken, adminToken)) return { ok: true, subject: 'admin' };
      return { ok: false, reason: 'admin token is not valid' };
    }
    if (evidence?.idToken !== undefined) {
      if (!jwks) return { ok: false, reason: 'sign-in with an identity provider is not configured' };
      let claims;
      try { claims = await verifyIdToken(evidence.idToken, { issuer: oidc.issuer, audience: oidc.audience, jwks }); } catch (e) { return { ok: false, reason: e.message }; }
      const email = typeof claims.email === 'string' ? claims.email.toLowerCase() : null;
      if (domains.length) {
        if (!email || !(claims.email_verified === true || claims.email_verified === 'true')) return { ok: false, reason: 'a verified email address is required' };
        if (!domains.includes(email.split('@').pop())) return { ok: false, reason: `${email.split('@').pop()} is not an allowed domain` };
      }
      const ids = [email, claims.sub].filter(Boolean);
      const named = [reg?.subject, reg?.name].filter((x) => typeof x === 'string').map((x) => x.toLowerCase());
      const bound = named.some((n) => ids.map((i) => i.toLowerCase()).includes(n)) || (claims.nonce && claims.nonce === reg?.did);
      if (!bound) return { ok: false, reason: 'ID token is not bound to this registration (set registration.subject to your email, or the token nonce to the DID)' };
      return { ok: true, subject: email || claims.sub };
    }
    return { ok: false, reason: oidc ? 'sign in with your identity provider (evidence.idToken)' : 'registration requires an admin token' };
  };
}

// For admin-only routes: `Authorization: Bearer <token>` or `x-admin-token`.
export function requireAdmin(req, adminToken) {
  if (!adminToken) throw httpError(403, 'admin API is disabled (no admin token configured)');
  const h = req?.headers || {};
  const bearer = /^Bearer\s+(.+)$/i.exec(h.authorization || '')?.[1];
  const given = bearer || h['x-admin-token'];
  if (!given) throw httpError(401, 'admin token required');
  if (!safeEqual(String(given).trim(), adminToken)) throw httpError(403, 'admin token is not valid');
  return true;
}
