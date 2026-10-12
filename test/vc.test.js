import test from 'node:test';
import assert from 'node:assert/strict';
import { Authority, Principal, AgentRuntime, Signer, ExternalSigner } from '../core/index.js';
import { b64u, unb64u } from '../core/encoding.js';
import {
  passportToCredential, verifyCredential, didKeyFromAgentId, agentIdFromDidKey, didKeyFromPublicKey,
  publicKeyFromDidKey, base58btcEncode, base58btcDecode,
} from '../core/vc.js';
import { routes } from '../server/vc.js';

async function setup() {
  const A = await Authority.create();
  const org = await Principal.create({ name: 'Acme' });
  await A.registerPrincipal(await org.registration());
  const agent = await AgentRuntime.create({ name: 'Payer', purpose: 'pays invoices', model: 'claude-x', manifest: { model: 'claude-x', tools: ['pay'] } });
  agent.passport = await org.issuePassport(agent, { depth: 1 });
  await A.registerPassport(agent.passport);
  return { A, org, agent };
}

test('vc: did:key matches the published Ed25519 test vectors', () => {
  // did:key spec example: publicKeyBase58 → did:key.
  const raw = base58btcDecode('B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u');
  assert.equal(raw.length, 32);
  assert.equal(didKeyFromPublicKey(raw), 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH');
  // did:key test-vector suite: JWK x → did:key, and back through did:agentid.
  const x = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';
  const didKey = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
  assert.equal(didKeyFromAgentId('did:agentid:' + x), didKey);
  assert.equal(agentIdFromDidKey(didKey), 'did:agentid:' + x);
  assert.equal(b64u(publicKeyFromDidKey(didKey)), x);
  assert.throws(() => publicKeyFromDidKey('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme'), /not an Ed25519 key/);
});

test('vc: base58btc round trip keeps leading zeros', () => {
  for (const bytes of [[], [0], [0, 0, 1], [255, 254, 0, 1], Array.from({ length: 64 }, (_, i) => (i * 37) & 255)]) {
    const u = Uint8Array.from(bytes);
    assert.deepEqual(base58btcDecode(base58btcEncode(u)), u);
  }
  assert.equal(base58btcEncode(Uint8Array.from([0, 0, 1, 2])), '115T');
  assert.throws(() => base58btcDecode('0OIl'), /invalid/);
});

test('vc: passport credential round trip', async () => {
  const { A, org, agent } = await setup();
  const vc = await passportToCredential(agent.passport, A.signer, { principal: org.did });
  assert.deepEqual(vc['@context'], ['https://www.w3.org/ns/credentials/v2']);
  assert.deepEqual(vc.type, ['VerifiableCredential', 'AgentPassportCredential']);
  assert.equal(vc.issuer, didKeyFromAgentId(A.did));
  assert.match(vc.issuer, /^did:key:z6Mk/);
  assert.equal(vc.credentialSubject.id, didKeyFromAgentId(agent.did));
  assert.equal(vc.credentialSubject.agentid, agent.did);
  assert.equal(vc.credentialSubject.name, 'Payer');
  assert.equal(vc.credentialSubject.purpose, 'pays invoices');
  assert.equal(vc.credentialSubject.model, 'claude-x');
  assert.equal(vc.credentialSubject.depth, 1);
  assert.equal(vc.credentialSubject.principal, org.did);
  assert.deepEqual(vc.evidence[0].passport, JSON.parse(JSON.stringify(agent.passport)), 'the passport exactly as signed');
  assert.equal(vc.validUntil, new Date(agent.passport.exp * 1000).toISOString().replace('.000', ''));
  assert.equal(vc.proof.type, 'DataIntegrityProof');
  assert.equal(vc.proof.cryptosuite, 'eddsa-jcs-2022');
  assert.equal(vc.proof.verificationMethod, vc.issuer + '#' + vc.issuer.slice('did:key:'.length));
  assert.match(vc.proof.proofValue, /^z[1-9A-HJ-NP-Za-km-z]+$/);

  const r = await verifyCredential(JSON.parse(JSON.stringify(vc)));
  assert.ok(r.ok, r.reason);
  assert.equal(r.subject, agent.did);
  assert.ok((await verifyCredential(vc, { issuer: A.did })).ok, 'issuer may be pinned as did:agentid');
  assert.ok((await verifyCredential(vc, { issuer: vc.issuer })).ok);
  assert.equal((await verifyCredential(vc, { issuer: (await Signer.generate()).did })).reason, 'credential comes from a different issuer');
  assert.equal((await verifyCredential(vc, { now: Date.parse(vc.validUntil) + 1000 })).reason, 'credential expired');
});

test('vc: tampering anywhere breaks the proof', async () => {
  const { A, agent } = await setup();
  const vc = await passportToCredential(agent.passport, A.signer);
  const clone = () => JSON.parse(JSON.stringify(vc));

  const a = clone(); a.credentialSubject.model = 'gpt-evil';
  assert.equal((await verifyCredential(a)).reason, 'proof signature is invalid');
  const b = clone(); b.validUntil = '2099-01-01T00:00:00Z';
  assert.equal((await verifyCredential(b)).reason, 'proof signature is invalid');
  const c = clone(); c.proof.created = '2020-01-01T00:00:00Z';
  assert.equal((await verifyCredential(c)).reason, 'proof signature is invalid', 'proof options are signed too');
  const d = clone(); d.evidence[0].passport.name = 'Other';
  assert.ok(!(await verifyCredential(d)).ok);

  // A forger re-signing with their own key must claim their own issuer; then the pin catches it.
  const thief = await Signer.generate();
  const forged = await passportToCredential(agent.passport, thief);
  assert.ok((await verifyCredential(forged)).ok);
  assert.ok(!(await verifyCredential(forged, { issuer: A.did })).ok);
  const swapped = { ...forged, issuer: vc.issuer };
  assert.equal((await verifyCredential(swapped)).reason, 'proof was not made by the issuer');
});

test('vc: works with a KMS-style external signer', async () => {
  const { agent } = await setup();
  const inner = await Signer.generate();
  const kms = new ExternalSigner(inner.did, async (bytes) => unb64u(await inner.signBytes(bytes)));
  const vc = await passportToCredential(agent.passport, kms);
  assert.ok((await verifyCredential(vc, { issuer: inner.did })).ok);
});

test('vc: GET /v1/passports/:id/credential issues for active passports only', async () => {
  const { A, org, agent } = await setup();
  const [[method, pattern, handler]] = routes({ authority: () => A, world: () => null, config: {}, issuer: 'https://x' });
  assert.equal(method, 'GET');
  assert.equal(pattern, '/v1/passports/:id/credential');
  const vc = await handler(null, { id: agent.passport.id }, new URLSearchParams(), { headers: {} });
  assert.ok((await verifyCredential(vc, { issuer: A.did })).ok);
  assert.equal(vc.credentialSubject.principal, org.did);
  assert.equal(vc.credentialSubject.status, 'active');
  assert.ok(!('status' in vc.evidence[0].passport), 'evidence is the passport as signed');
  const byDid = await handler(null, { id: agent.did });
  assert.equal(byDid.id, vc.id);
  await assert.rejects(handler(null, { id: 'pp_nope' }), (e) => e.status === 404);
  await A.revoke(await org.revoke(agent.passport.id, 'retired'));
  await assert.rejects(handler(null, { id: agent.passport.id }), (e) => e.status === 409);
});
