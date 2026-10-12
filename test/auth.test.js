import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { createAdmission, requireAdmin } from '../server/auth.js';
import { Authority, Principal } from '../core/index.js';

const keys = {
  RS256: generateKeyPairSync('rsa', { modulusLength: 2048 }),
  ES256: generateKeyPairSync('ec', { namedCurve: 'P-256' }),
  EdDSA: generateKeyPairSync('ed25519'),
};
const rogue = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwkOf = (alg, kid) => ({ ...keys[alg].publicKey.export({ format: 'jwk' }), kid, alg, use: 'sig' });

function jwt(alg, kid, claims, privateKey = keys[alg].privateKey) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const input = enc({ alg, kid, typ: 'JWT' }) + '.' + enc(claims);
  const hash = alg === 'EdDSA' ? null : 'sha256';
  const sig = nodeSign(hash, Buffer.from(input), alg === 'ES256' ? { key: privateKey, dsaEncoding: 'ieee-p1363' } : privateKey);
  return input + '.' + sig.toString('base64url');
}

async function idp() {
  const published = [jwkOf('RS256', 'rsa1'), jwkOf('ES256', 'ec1')];
  let jwksHits = 0;
  const server = http.createServer((req, res) => {
    const base = `http://127.0.0.1:${server.address().port}`;
    res.setHeader('content-type', 'application/json');
    if (req.url === '/.well-known/openid-configuration') return res.end(JSON.stringify({ issuer: base, jwks_uri: base + '/jwks' }));
    if (req.url === '/jwks') { jwksHits++; return res.end(JSON.stringify({ keys: published })); }
    res.statusCode = 404; res.end('{}');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, issuer: `http://127.0.0.1:${server.address().port}`, published, hits: () => jwksHits };
}

test('auth: OIDC admission verifies ID tokens against the issuer JWKS', async () => {
  const p = await idp();
  try {
    const admit = createAdmission({ oidc: { issuer: p.issuer, audience: 'agentid', allowedDomains: ['acme.com'] } });
    const now = Math.floor(Date.now() / 1000);
    const claims = (extra = {}) => ({ iss: p.issuer, aud: 'agentid', sub: 'u-1', email: 'ana@acme.com', email_verified: true, iat: now, exp: now + 300, ...extra });
    const reg = { did: 'did:agentid:x', name: 'Acme', subject: 'ana@acme.com' };

    for (const [alg, kid] of [['RS256', 'rsa1'], ['ES256', 'ec1']]) {
      const v = await admit(reg, { idToken: jwt(alg, kid, claims()) });
      assert.deepEqual(v, { ok: true, subject: 'ana@acme.com' }, alg);
    }
    const fails = async (token, pattern, r = reg) => assert.match((await admit(r, { idToken: token })).reason, pattern);
    await fails(jwt('RS256', 'rsa1', claims({ iss: 'https://evil' })), /different issuer/);
    await fails(jwt('RS256', 'rsa1', claims({ aud: 'other' })), /different audience/);
    await fails(jwt('RS256', 'rsa1', claims({ exp: now - 3600 })), /expired/);
    await fails(jwt('RS256', 'rsa1', claims({ nbf: now + 3600 })), /not valid yet/);
    await fails(jwt('RS256', 'rsa1', claims({ email: 'eve@evil.com', email_verified: true })), /not an allowed domain/);
    await fails(jwt('RS256', 'rsa1', claims({ email_verified: false })), /verified email/);
    await fails(jwt('ES256', 'ec1', claims(), rogue.privateKey), /signature is invalid/);
    await fails(jwt('RS256', 'rsa1', claims()).replace(/\.[^.]+$/, '.'), /signature is invalid/);
    const none = Buffer.from('{"alg":"none"}').toString('base64url') + '.' + Buffer.from(JSON.stringify(claims())).toString('base64url') + '.';
    await fails(none, /not accepted/);
    await fails(jwt('RS256', 'rsa1', claims()), /not bound/, { did: 'did:agentid:x', name: 'Acme' });
    assert.ok((await admit({ did: 'did:agentid:x', name: 'Acme' }, { idToken: jwt('RS256', 'rsa1', claims({ nonce: 'did:agentid:x' })) })).ok, 'nonce = DID binds');
    assert.match((await admit(reg, {})).reason, /identity provider/);

    // Key rotation: an unknown kid triggers a refetch, rate limited.
    const hits = p.hits();
    await fails(jwt('EdDSA', 'ed1', claims()), /unknown key/);
    p.published.push(jwkOf('EdDSA', 'ed1'));
    await fails(jwt('EdDSA', 'ed1', claims()), /unknown key/); // within the 30 s refresh floor
    assert.equal(p.hits(), hits, 'no refetch storm on unknown kids');
    const fresh = createAdmission({ oidc: { issuer: p.issuer, audience: 'agentid' } });
    assert.ok((await fresh(reg, { idToken: jwt('EdDSA', 'ed1', claims()) })).ok, 'EdDSA verifies after rotation');
  } finally {
    p.server.close();
  }
});

test('auth: admin token and dev admission, wired into the authority', async () => {
  const admit = createAdmission({ adminToken: 's3cret-token' });
  assert.ok((await admit({}, { adminToken: 's3cret-token' })).ok);
  assert.ok(!(await admit({}, { adminToken: 's3cret-tokeN' })).ok);
  assert.match((await admit({}, null)).reason, /admin token/);
  assert.ok((await createAdmission({ dev: true })({}, null)).ok);

  const A = await Authority.create({ admit });
  const p = await Principal.create({ name: 'Acme' });
  await assert.rejects(A.registerPrincipal(await p.registration()), /not admitted/);
  const rec = await A.registerPrincipal(await p.registration(), { adminToken: 's3cret-token' });
  assert.equal(rec.admittedAs, 'admin');
});

test('auth: requireAdmin', () => {
  const req = (headers) => ({ headers });
  assert.ok(requireAdmin(req({ authorization: 'Bearer tok' }), 'tok'));
  assert.ok(requireAdmin(req({ 'x-admin-token': 'tok' }), 'tok'));
  assert.throws(() => requireAdmin(req({}), 'tok'), (e) => e.status === 401);
  assert.throws(() => requireAdmin(req({ authorization: 'Bearer nope' }), 'tok'), (e) => e.status === 403);
  assert.throws(() => requireAdmin(req({ authorization: 'Bearer tok' }), ''), (e) => e.status === 403);
});
