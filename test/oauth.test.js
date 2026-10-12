import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { Authority, Principal, Attestor, AgentRuntime } from '../core/index.js';
import { b64u, utf8, canonical } from '../core/encoding.js';
import {
  routes, verifyAccessToken, jwkThumbprint, TOKEN_TYPE_RECEIPT, TOKEN_TYPE_INTENT, TOKEN_TYPE_SVID, GRANT_TOKEN_EXCHANGE,
} from '../server/oauth.js';

const ISSUER = 'https://auth.agentid.test';

async function setup(config = {}) {
  const A = await Authority.create();
  const org = await Principal.create({ name: 'Acme' });
  const host = await Attestor.create('host');
  await A.registerPrincipal(await org.registration());
  await A.endorseAttestor(await org.endorseAttestor(host));
  const agent = await AgentRuntime.create({ name: 'Payer', purpose: 'pays', model: 'm', manifest: { model: 'm', tools: ['pay'] } });
  agent.passport = await org.issuePassport(agent);
  await A.registerPassport(agent.passport);
  agent.mandate = await org.issueMandate({ sub: agent.did, caps: [{ action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 5000 } } }], cosign: { above: 500 } });
  await A.registerMandate(agent.mandate);
  agent.attestation = await host.attest(agent.did, agent.manifest);
  const ctx = { authority: () => A, world: () => null, config, issuer: ISSUER };
  return { A, org, agent, ctx, table: routes(ctx) };
}

// Minimal stand-in for the server's router: same matching rules, handler contract.
async function call(table, method, path, body = null) {
  for (const [m, pattern, handler] of table) {
    if (m !== method) continue;
    const pp = pattern.split('/');
    const up = path.split('/');
    if (pp.length !== up.length) continue;
    const params = {};
    if (pp.every((seg, i) => (seg.startsWith(':') ? (params[seg.slice(1)] = decodeURIComponent(up[i])) : seg === up[i]))) {
      const out = await handler(body, params, new URLSearchParams(), { headers: {}, rawBody: Buffer.from('') });
      return out?.__raw ? { status: out.__raw.status, headers: out.__raw.headers, body: out.__raw.body } : { status: 200, body: out };
    }
  }
  throw new Error('no route ' + method + ' ' + path);
}

const enc = (obj) => b64u(utf8(JSON.stringify(obj)));
const pay = (agent, amount, extra) => agent.intent({ action: 'payments.send', resource: 'vendor:x', params: { amount }, reason: 'invoice 7', aud: 'payments', ...extra });
const exchange = (table, fields) => call(table, 'POST', '/oauth/token', { grant_type: GRANT_TOKEN_EXCHANGE, ...fields });

function nodeVerifyJwt(jwt, jwk) {
  const [h, p, s] = jwt.split('.');
  const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x }, format: 'jwk' });
  return nodeVerify(null, Buffer.from(h + '.' + p), key, Buffer.from(s, 'base64url'));
}
const claimsOf = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'));
const headerOf = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url'));

test('oauth: metadata and JWKS describe the authority key consistently', async () => {
  const { A, table } = await setup();
  const meta = (await call(table, 'GET', '/.well-known/oauth-authorization-server')).body;
  assert.equal(meta.issuer, ISSUER);
  assert.equal(meta.token_endpoint, ISSUER + '/oauth/token');
  assert.deepEqual(meta.grant_types_supported, [GRANT_TOKEN_EXCHANGE]);
  assert.deepEqual(meta.token_endpoint_auth_methods_supported, ['none']);
  const { keys } = (await call(table, 'GET', '/.well-known/jwks.json')).body;
  assert.equal(keys.length, 1);
  assert.equal(keys[0].kty, 'OKP');
  assert.equal(keys[0].crv, 'Ed25519');
  assert.equal(keys[0].x, A.did.slice('did:agentid:'.length), 'JWK x is the raw key from the DID');
  // RFC 7638 thumbprint, recomputed with node:crypto.
  assert.equal(keys[0].kid, await jwkThumbprint(keys[0]));
  const bundle = (await call(table, 'GET', '/.well-known/spiffe-bundle')).body;
  assert.equal(bundle.keys[0].use, 'jwt-svid');
  assert.equal(bundle.keys[0].kid, keys[0].kid);
});

test('oauth: exchanges a receipt for an RFC 9068 access token', async () => {
  const { A, org, agent, table } = await setup();
  const r = await A.verifyIntent(await pay(agent, 200));
  assert.equal(r.decision, 'allow');
  const res = await exchange(table, { subject_token: enc(r.receipt), subject_token_type: TOKEN_TYPE_RECEIPT, resource: 'payments', scope: 'payments.send' });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.body.issued_token_type, 'urn:ietf:params:oauth:token-type:jwt');
  assert.equal(res.body.token_type, 'Bearer');
  assert.ok(res.body.expires_in > 0 && res.body.expires_in <= 120, 'never beyond the receipt age limit');

  const jwt = res.body.access_token;
  const { keys } = (await call(table, 'GET', '/.well-known/jwks.json')).body;
  assert.ok(nodeVerifyJwt(jwt, keys[0]), 'node:crypto verifies the EdDSA signature from the JWK');
  assert.deepEqual(headerOf(jwt), { alg: 'EdDSA', kid: keys[0].kid, typ: 'at+jwt' });
  const c = claimsOf(jwt);
  assert.equal(c.iss, ISSUER);
  assert.equal(c.sub, agent.did);
  assert.equal(c.client_id, agent.did);
  assert.equal(c.aud, 'payments');
  assert.equal(c.scope, 'payments.send');
  assert.deepEqual(c.act, { sub: org.did });
  assert.equal(c.agentid.action, 'payments.send');
  assert.equal(c.agentid.resource, 'vendor:x');
  assert.deepEqual(c.agentid.params, { amount: 200 });
  assert.equal(c.agentid.ledgerSeq, r.receipt.ledgerSeq);
  assert.match(c.agentid.receipt, /^[0-9a-f]{64}$/);
  assert.ok(c.exp - c.iat <= 300);
  assert.ok(c.jti);

  assert.ok((await verifyAccessToken(jwt, { jwks: { keys }, aud: 'payments', issuer: ISSUER })).ok);
  assert.ok((await verifyAccessToken(jwt, { authorityDid: A.did, aud: 'payments' })).ok);
  assert.equal((await verifyAccessToken(jwt, { authorityDid: A.did, aud: 'other' })).reason, 'token is for a different audience');
  const [h, p, s] = jwt.split('.');
  const forged = h + '.' + enc({ ...c, scope: 'payments.*' }) + '.' + s;
  assert.ok(!(await verifyAccessToken(forged, { jwks: keys, aud: 'payments' })).ok);
  assert.equal((await verifyAccessToken(jwt, { jwks: keys, aud: 'payments', now: (c.exp + 60) * 1000 })).reason, 'token expired');

  const again = await exchange(table, { subject_token: enc(r.receipt), subject_token_type: TOKEN_TYPE_RECEIPT });
  assert.equal(again.status, 400);
  assert.equal(again.body.error, 'invalid_grant', 'a receipt is exchanged once');
});

test('oauth: exchanges an allowed intent; step_up and deny get no token', async () => {
  const { agent, table } = await setup();
  const ok = await exchange(table, { subject_token: enc(await pay(agent, 100)), subject_token_type: TOKEN_TYPE_INTENT, audience: 'payments' });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(claimsOf(ok.body.access_token).agentid.params.amount, 100);

  const held = await exchange(table, { subject_token: enc(await pay(agent, 900)), subject_token_type: TOKEN_TYPE_INTENT });
  assert.equal(held.status, 400);
  assert.equal(held.body.error, 'invalid_grant');
  assert.equal(held.body.agentid.decision, 'step_up');
  assert.match(held.body.agentid.approvalId, /^ap_/);
  assert.ok(!held.body.access_token);

  const denied = await exchange(table, { subject_token: enc(await agent.intent({ action: 'payments.refund', resource: 'vendor:x', reason: 'x' })), subject_token_type: TOKEN_TYPE_INTENT });
  assert.equal(denied.status, 400);
  assert.equal(denied.body.agentid.decision, 'deny');
  assert.equal(denied.body.agentid.failedAt, 'scope');
});

test('oauth: rejects expired, foreign and malformed subject tokens and wrong grants', async () => {
  const { A, agent, table } = await setup({ oauth: { receiptMaxAgeSec: 60 } });
  const other = await setup();
  const r = await A.verifyIntent(await pay(agent, 50));

  const wrongGrant = await call(table, 'POST', '/oauth/token', { grant_type: 'client_credentials', subject_token: enc(r.receipt), subject_token_type: TOKEN_TYPE_RECEIPT });
  assert.equal(wrongGrant.body.error, 'unsupported_grant_type');
  assert.equal(wrongGrant.status, 400);

  const foreign = await exchange(other.table, { subject_token: enc(r.receipt), subject_token_type: TOKEN_TYPE_RECEIPT });
  assert.equal(foreign.body.error, 'invalid_grant');
  assert.match(foreign.body.error_description, /not signed by this authority/);

  const tampered = await exchange(table, { subject_token: enc({ ...r.receipt, params: { amount: 5000 } }), subject_token_type: TOKEN_TYPE_RECEIPT });
  assert.equal(tampered.body.error, 'invalid_grant');

  const old = await A.signer.seal({ ...r.receipt, proof: undefined, iat: A.now() - 61 });
  const expired = await exchange(table, { subject_token: enc(old), subject_token_type: TOKEN_TYPE_RECEIPT });
  assert.equal(expired.body.error, 'invalid_grant');
  assert.match(expired.body.error_description, /too old/);

  assert.equal((await exchange(table, { subject_token: 'not-json', subject_token_type: TOKEN_TYPE_RECEIPT })).body.error, 'invalid_request');
  assert.equal((await exchange(table, { subject_token: enc(r.receipt), subject_token_type: 'urn:ietf:params:oauth:token-type:jwt' })).body.error, 'invalid_request');
  assert.equal((await exchange(table, { subject_token: enc(r.receipt), subject_token_type: TOKEN_TYPE_RECEIPT, scope: 'payments.send admin' })).body.error, 'invalid_scope');
  assert.equal((await exchange(table, { subject_token: enc(r.receipt), subject_token_type: TOKEN_TYPE_RECEIPT, resource: 'https://evil.example' })).body.error, 'invalid_target');

  // The receipt survived the failed attempts and still exchanges once, capped at its remaining age.
  const ok = await exchange(table, { subject_token: enc(r.receipt), subject_token_type: TOKEN_TYPE_RECEIPT });
  assert.equal(ok.status, 200);
  assert.ok(ok.body.expires_in <= 60);
});

test('oauth: configured resource URIs and canonical-JSON subject tokens', async () => {
  const { A, agent, table } = await setup({ oauth: { audiences: { payments: ['https://api.pay.example'] } } });
  const r = await A.verifyIntent(await pay(agent, 50));
  const res = await exchange(table, { subject_token: b64u(utf8(canonical(r.receipt))), subject_token_type: TOKEN_TYPE_RECEIPT, resource: 'https://api.pay.example' });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.ok((await verifyAccessToken(res.body.access_token, { authorityDid: A.did, aud: 'https://api.pay.example' })).ok);
});

test('oauth: issues a SPIFFE JWT-SVID on request', async () => {
  const { A, agent, table } = await setup({ spiffe: { trustDomain: 'prod.acme.example' } });
  const r1 = await A.verifyIntent(await pay(agent, 10));
  const noAud = await exchange(table, { subject_token: enc(r1.receipt), subject_token_type: TOKEN_TYPE_RECEIPT, requested_token_type: TOKEN_TYPE_SVID });
  assert.equal(noAud.body.error, 'invalid_request', 'JWT-SVIDs require an audience');

  const res = await exchange(table, { subject_token: enc(r1.receipt), subject_token_type: TOKEN_TYPE_RECEIPT, requested_token_type: TOKEN_TYPE_SVID, audience: 'payments' });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.equal(res.body.issued_token_type, TOKEN_TYPE_SVID);
  const svid = res.body.access_token;
  assert.equal(headerOf(svid).typ, 'JWT');
  const c = claimsOf(svid);
  assert.equal(c.sub, `spiffe://prod.acme.example/agent/${agent.did.slice('did:agentid:'.length)}`);
  assert.match(c.sub, /^spiffe:\/\/[a-z0-9.-]+\/agent\/[A-Za-z0-9._-]+$/);
  assert.equal(c.aud, 'payments');
  assert.ok(c.exp > c.iat);
  const bundle = (await call(table, 'GET', '/.well-known/spiffe-bundle')).body;
  assert.ok(nodeVerifyJwt(svid, bundle.keys[0]));
  assert.ok((await verifyAccessToken(svid, { jwks: bundle, aud: 'payments', typ: 'JWT' })).ok);
  assert.ok(!(await verifyAccessToken(svid, { jwks: bundle, aud: 'payments' })).ok, 'an SVID is not an at+jwt');

  const r2 = await A.verifyIntent(await pay(agent, 11));
  const viaFlag = await exchange(table, { subject_token: enc(r2.receipt), subject_token_type: TOKEN_TYPE_RECEIPT, spiffe: '1', audience: 'payments' });
  assert.equal(viaFlag.status, 200);
  assert.match(claimsOf(viaFlag.body.access_token).sub, /^spiffe:\/\/prod\.acme\.example\/agent\//);
});
