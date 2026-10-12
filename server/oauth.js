// OAuth bridge: lets existing OAuth resource servers accept AgentID decisions without
// knowing anything about AgentID.
//
//   POST /oauth/token                         RFC 8693 token exchange: Receipt or Intent → JWT
//   GET  /.well-known/jwks.json               the authority key as an OKP/Ed25519 JWK
//   GET  /.well-known/oauth-authorization-server   RFC 8414 metadata
//   GET  /.well-known/spiffe-bundle           the same key as a SPIFFE JWT-SVID bundle
//
// The subject token is itself the proof (a receipt signed by this authority, or an intent
// the agent signed and we evaluate now), so there is no client authentication. Access
// tokens are EdDSA JWTs (RFC 9068) signed with the authority key through signer.signBytes,
// so a KMS-backed signer works unchanged. kid is the RFC 7638 thumbprint everywhere.
//
// config.oauth:  { accessTokenTtlSec = 300, receiptMaxAgeSec = 120, singleUse = true,
//                  audiences: { <receipt aud>: [allowed resource URIs] } }
// config.spiffe: { trustDomain }  (default: the issuer's host name)

import { b64u, unb64u, utf8, canonical, hashObject, randomId } from '../core/encoding.js';
import { publicKeyFromDid, verifySealed } from '../core/keys.js';

export const GRANT_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const TOKEN_TYPE_RECEIPT = 'urn:agentid:params:oauth:token-type:receipt';
export const TOKEN_TYPE_INTENT = 'urn:agentid:params:oauth:token-type:intent';
export const TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';
export const TOKEN_TYPE_SVID = 'urn:ietf:params:oauth:token-type:jwt-svid';
const MAX_TTL = 300;
const ALG = { name: 'Ed25519' };

// ---------------------------------------------------------------- JOSE helpers

const b64uJson = (obj) => b64u(utf8(JSON.stringify(obj)));
const decodeJson = (s) => JSON.parse(new TextDecoder().decode(unb64u(s)));

export const jwkFromDid = (did) => ({ kty: 'OKP', crv: 'Ed25519', x: b64u(publicKeyFromDid(did)) });

// RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace.
export async function jwkThumbprint(jwk) {
  const json = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(json))));
}

export async function authorityJwk(did, use = 'sig') {
  const jwk = jwkFromDid(did);
  return { ...jwk, kid: await jwkThumbprint(jwk), alg: 'EdDSA', use };
}

export async function signJwt(signer, header, payload) {
  const input = b64uJson(header) + '.' + b64uJson(payload);
  return input + '.' + (await signer.signBytes(utf8(input)));
}

// For resource servers. Pass `jwks` (a JWKS object or keys array) or `authorityDid`.
// `aud` must appear in the token's audience. `typ` defaults to RFC 9068's 'at+jwt';
// pass typ: 'JWT' for a JWT-SVID or null to skip. `leewaySec` tolerates clock skew.
export async function verifyAccessToken(jwt, { jwks, authorityDid, aud, issuer, typ = 'at+jwt', leewaySec = 30, now = Date.now() } = {}) {
  const fail = (reason) => ({ ok: false, reason });
  try {
    const parts = String(jwt).split('.');
    if (parts.length !== 3) return fail('not a compact JWS');
    const header = decodeJson(parts[0]);
    const claims = decodeJson(parts[1]);
    if (header.alg !== 'EdDSA') return fail('unexpected alg ' + header.alg);
    if (typ && String(header.typ).toLowerCase() !== typ.toLowerCase() && !(typ === 'at+jwt' && header.typ === 'application/at+jwt')) return fail(`typ must be ${typ}`);
    let keys = Array.isArray(jwks) ? jwks : jwks?.keys || [];
    if (authorityDid) keys = [...keys, await authorityJwk(authorityDid)];
    const jwk = keys.find((k) => k.kid === header.kid && k.kty === 'OKP' && k.crv === 'Ed25519');
    if (!jwk) return fail('no key for kid ' + header.kid);
    const key = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, ALG, false, ['verify']);
    if (!(await crypto.subtle.verify(ALG, key, unb64u(parts[2]), utf8(parts[0] + '.' + parts[1])))) return fail('signature is invalid');
    const t = Math.floor(now / 1000);
    if (typeof claims.exp !== 'number' || claims.exp + leewaySec < t) return fail('token expired');
    if (typeof claims.nbf === 'number' && claims.nbf - leewaySec > t) return fail('token not valid yet');
    if (typeof claims.iat === 'number' && claims.iat - leewaySec > t) return fail('token issued in the future');
    if (issuer && claims.iss !== issuer) return fail('token comes from a different issuer');
    if (aud !== undefined) {
      const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!auds.includes(aud)) return fail('token is for a different audience');
    }
    return { ok: true, header, claims };
  } catch (e) {
    return fail('malformed token: ' + e.message);
  }
}

// ---------------------------------------------------------------- token exchange

const raw = (status, body, headers = {}) => ({ __raw: { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', pragma: 'no-cache', ...headers }, body } });
const oauthError = (error, description, extra = {}) => raw(400, { error, error_description: description, ...extra });
const issuerOf = (ctx, req) => String(typeof ctx.issuer === 'function' ? ctx.issuer(req) : ctx.issuer).replace(/\/$/, '');
const list = (v) => (v === undefined || v === null || v === '' ? [] : Array.isArray(v) ? v : [v]);

// Subject tokens travel as base64url JSON; a bare JSON string is accepted for convenience.
function decodeSubject(token) {
  if (typeof token !== 'string' || !token) throw new Error('subject_token is required');
  const s = token.trim();
  return s.startsWith('{') ? JSON.parse(s) : decodeJson(s);
}

export function spiffeId(trustDomain, agentDid) {
  // The base64url public key is already a valid SPIFFE path segment ([A-Za-z0-9._-]).
  return `spiffe://${trustDomain}/agent/${b64u(publicKeyFromDid(agentDid))}`;
}

async function exchange(ctx, body, req) {
  const A = ctx.authority();
  const cfg = ctx.config?.oauth || {};
  const issuer = issuerOf(ctx, req);
  if (body.grant_type !== GRANT_TOKEN_EXCHANGE) return oauthError('unsupported_grant_type', `grant_type must be ${GRANT_TOKEN_EXCHANGE}`);
  if (body.actor_token) return oauthError('invalid_request', 'actor_token is not supported; the actor is the principal named in the receipt');
  const svid = body.requested_token_type === TOKEN_TYPE_SVID || body.spiffe === '1' || body.spiffe === 1 || body.spiffe === true;
  if (body.requested_token_type && !svid && ![TOKEN_TYPE_JWT, 'urn:ietf:params:oauth:token-type:access_token'].includes(body.requested_token_type)) {
    return oauthError('invalid_request', 'requested_token_type is not supported');
  }

  let subject;
  try { subject = decodeSubject(body.subject_token); } catch (e) { return oauthError('invalid_request', 'subject_token is not base64url JSON: ' + e.message); }

  const now = A.now();
  const maxAge = Math.min(cfg.receiptMaxAgeSec ?? 120, 3600);
  let receipt;
  if (body.subject_token_type === TOKEN_TYPE_RECEIPT) {
    receipt = subject;
    if (receipt?.type !== 'Receipt') return oauthError('invalid_grant', 'subject_token is not an AgentID receipt');
    // A receipt from any other authority fails here: it must carry *our* signature.
    if (receipt.authority !== A.did || !(await verifySealed(receipt, A.did))) return oauthError('invalid_grant', 'receipt is not signed by this authority');
  } else if (body.subject_token_type === TOKEN_TYPE_INTENT) {
    if (subject?.type !== 'Intent') return oauthError('invalid_grant', 'subject_token is not an AgentID intent');
    const result = await A.verifyIntent(subject);
    if (result.decision !== 'allow') {
      const desc = result.decision === 'step_up'
        ? 'a co-sign is required; exchange the receipt once approval ' + result.approvalId + ' is granted'
        : `denied at ${result.failedAt}: ` + (result.checks?.find((c) => c.key === result.failedAt)?.detail || 'policy');
      return oauthError('invalid_grant', desc, { agentid: { decision: result.decision, failedAt: result.failedAt, approvalId: result.approvalId, ledgerSeq: result.ledgerSeq } });
    }
    receipt = result.receipt;
  } else {
    return oauthError('invalid_request', `subject_token_type must be ${TOKEN_TYPE_RECEIPT} or ${TOKEN_TYPE_INTENT}`);
  }

  if (receipt.iat > now + 30) return oauthError('invalid_grant', 'receipt is issued in the future');
  const notAfter = receipt.iat + maxAge;
  if (notAfter <= now) return oauthError('invalid_grant', 'receipt is too old');

  // Scope can only narrow: the receipt authorises exactly one action.
  const scopes = String(body.scope || '').split(/\s+/).filter(Boolean);
  if (scopes.some((s) => s !== receipt.action)) return oauthError('invalid_scope', `this receipt only grants ${receipt.action}`);

  // Audience: the receipt's own aud, or a resource URI configured for it. 'any' receipts may target anything.
  const requested = [...list(body.resource), ...list(body.audience)];
  const allowed = [receipt.aud, ...list(cfg.audiences?.[receipt.aud])];
  const bad = requested.find((a) => receipt.aud !== 'any' && !allowed.includes(a));
  if (bad) return oauthError('invalid_target', `receipt for ${receipt.aud} cannot be used at ${bad}`);
  if (svid && !requested.length) return oauthError('invalid_request', 'a JWT-SVID needs an audience or resource');
  const aud = requested.length ? (requested.length === 1 ? requested[0] : requested) : receipt.aud;

  // One receipt, one token: a captured receipt cannot mint a stream of access tokens.
  // claimNonce runs in a store transaction, so this holds across authority processes.
  const receiptHash = await hashObject(receipt);
  if (cfg.singleUse !== false) {
    const fresh = await A.store.transaction((tx) => tx.claimNonce('oauth:' + receiptHash, notAfter, now));
    if (!fresh) return oauthError('invalid_grant', 'this receipt was already exchanged');
  }

  const exp = Math.min(now + Math.min(cfg.accessTokenTtlSec ?? MAX_TTL, MAX_TTL), notAfter);
  const kid = (await authorityJwk(A.did)).kid;
  let token;
  if (svid) {
    const td = ctx.config?.spiffe?.trustDomain || new URL(issuer).hostname;
    token = await signJwt(A.signer, { alg: 'EdDSA', kid, typ: 'JWT' }, {
      sub: spiffeId(td, receipt.agent), aud, exp, iat: now, iss: issuer, jti: randomId('svid'),
      agentid: { did: receipt.agent, receipt: receiptHash, action: receipt.action, resource: receipt.resource },
    });
  } else {
    token = await signJwt(A.signer, { alg: 'EdDSA', kid, typ: 'at+jwt' }, {
      iss: issuer, sub: receipt.agent, aud, exp, iat: now, jti: randomId('at'),
      client_id: receipt.agent, scope: receipt.action,
      act: { sub: receipt.principal },
      agentid: {
        authority: A.did, receipt: receiptHash, intent: receipt.intentHash,
        action: receipt.action, resource: receipt.resource, params: receipt.params,
        ledgerSeq: receipt.ledgerSeq, cosigners: receipt.cosigners || [],
      },
    });
  }
  return raw(200, {
    access_token: token,
    issued_token_type: svid ? TOKEN_TYPE_SVID : TOKEN_TYPE_JWT,
    token_type: 'Bearer',
    expires_in: exp - now,
    scope: receipt.action,
  });
}

// ---------------------------------------------------------------- routes

export function routes(ctx) {
  return [
    ['POST', '/oauth/token', async (body, _p, _q, req) => {
      try {
        return await exchange(ctx, body || {}, req);
      } catch (e) {
        return oauthError('invalid_request', e.message);
      }
    }],
    ['GET', '/.well-known/jwks.json', async () => ({ keys: [await authorityJwk(ctx.authority().did)] })],
    ['GET', '/.well-known/spiffe-bundle', async () => ({
      keys: [await authorityJwk(ctx.authority().did, 'jwt-svid')],
      spiffe_refresh_hint: 300,
      spiffe_sequence: 1,
    })],
    ['GET', '/.well-known/oauth-authorization-server', (_b, _p, _q, req) => {
      const issuer = issuerOf(ctx, req);
      return {
        issuer,
        token_endpoint: issuer + '/oauth/token',
        jwks_uri: issuer + '/.well-known/jwks.json',
        grant_types_supported: [GRANT_TOKEN_EXCHANGE],
        response_types_supported: [],
        token_endpoint_auth_methods_supported: ['none'],
        subject_token_types_supported: [TOKEN_TYPE_RECEIPT, TOKEN_TYPE_INTENT],
        issued_token_types_supported: [TOKEN_TYPE_JWT, TOKEN_TYPE_SVID],
        token_endpoint_auth_signing_alg_values_supported: ['EdDSA'],
        agentid_authority: ctx.authority().did,
        spiffe_bundle_endpoint: issuer + '/.well-known/spiffe-bundle',
      };
    }],
  ];
}

// Re-exported for callers that want to build a subject_token from a receipt or intent.
export const encodeSubjectToken = (obj) => b64u(utf8(canonical(obj)));
