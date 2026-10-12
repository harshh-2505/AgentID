import test from 'node:test';
import assert from 'node:assert/strict';
import { Authority, Principal, Attestor, AgentRuntime, Signer } from '../core/index.js';
import { VirtualAuthenticator } from '../core/virtual-authenticator.js';
import { enrollmentChallenge, checkpointExtends } from '../core/authority.js';
import { approvalChallenge } from '../core/webauthn.js';
import { MerkleTree, verifyInclusion, verifyConsistency } from '../core/merkle.js';
import { verifyFederatedReceipt } from '../core/federation.js';
import { b64u, utf8, sha256 } from '../core/encoding.js';

const WEBAUTHN = { rpId: 'agentid.test', origins: ['https://agentid.test'] };

async function org({ recovery, webauthn = WEBAUTHN, cosign = { above: 500 } } = {}) {
  const A = await Authority.create({ webauthn });
  const p = await Principal.create({ name: 'Acme', recovery });
  const host = await Attestor.create('host');
  await A.registerPrincipal(await p.registration());
  await A.endorseAttestor(await p.endorseAttestor(host));
  const agent = await AgentRuntime.create({ name: 'Payer', purpose: 'pays', model: 'm', manifest: { model: 'm', tools: ['pay'] } });
  agent.passport = await p.issuePassport(agent, { depth: 1 });
  await A.registerPassport(agent.passport);
  agent.mandate = await p.issueMandate({ sub: agent.did, depth: 1, caps: [{ action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 5000 } } }], budget: { amount: 10000, currency: 'USD' }, cosign });
  await A.registerMandate(agent.mandate);
  agent.attestation = await host.attest(agent.did, agent.manifest);
  return { A, p, host, agent };
}

const pay = (agent, amount) => agent.intent({ action: 'payments.send', resource: 'vendor:x', params: { amount, currency: 'USD' }, reason: 'invoice' });
const addKey = async (A, p, role, opts) => {
  const { signer, update } = await p.newKey(role, opts);
  await A.updateKeys({ update, approvals: [await p.signKeyUpdate(update)] });
  p.adoptKey(role, signer);
  return signer;
};

test('keys: operational key issues; retired keys cannot sign anything new', async () => {
  const { A, p, agent } = await org();
  const op = await addKey(A, p, 'operational');
  const m1 = await p.issueMandate({ sub: agent.did, caps: [{ action: 'payments.send', resource: 'vendor:y' }] });
  assert.equal(m1.proof.kid, op.did, 'issued with the operational key, root stays offline');
  await A.registerMandate(m1);

  const fresh = await Signer.generate();
  const update = p.keyUpdate({ add: [{ kid: fresh.did, role: 'operational' }], remove: [{ kid: op.did }] });
  await assert.rejects(A.updateKeys({ update, approvals: [await op.seal(update)] }), /root key signature or the recovery quorum/, 'an operational key cannot change keys');
  await A.updateKeys({ update, approvals: [await p.signKeyUpdate(update)] });

  // m1 was signed before the key was retired: still valid.
  assert.equal((await A.verifyIntent(await pay(agent, 100))).decision, 'allow');
  // The retired key signing something new is refused, even with a back-dated iat it cannot pass "issued after removal".
  const late = await op.seal({ ...(await p.issueMandate({ sub: agent.did, caps: [{ action: 'payments.send', resource: 'vendor:z' }] })), iat: undefined });
  await assert.rejects(A.registerMandate(late), /signing key was withdrawn/);
});

test('keys: a compromised key invalidates everything it ever signed', async () => {
  const { A, p, agent } = await org();
  const op = await addKey(A, p, 'operational');
  const sub = await AgentRuntime.create({ name: 'Sub', purpose: 'x', model: 'm', manifest: { model: 'm', tools: [] } });
  sub.passport = await p.issuePassport(sub, { depth: 0 });
  await A.registerPassport(sub.passport);
  const update = p.keyUpdate({ remove: [{ kid: op.did, compromised: true }] });
  await A.updateKeys({ update, approvals: [await p.signKeyUpdate(update)] });
  const snap = await A.snapshot();
  assert.ok(snap.principals[0].keys.find((k) => k.kid === op.did).compromised);
  await assert.rejects(A.registerMandate(await op.seal({ type: 'Mandate', v: 1, id: 'md_x', iss: p.did, sub: sub.did, parent: null, caps: [], depth: 0, nbf: 0, exp: 9e9, iat: 1 })), /withdrawn/);
});

test('keys: guardians recover a lost root key with a 2 of 3 quorum', async () => {
  const guardians = await Promise.all([0, 1, 2].map(() => Signer.generate()));
  const { A, p } = await org({ recovery: { k: 2, of: guardians.map((g) => g.did) } });
  const fresh = await Signer.generate();
  const update = p.keyUpdate({ add: [{ kid: fresh.did, role: 'root' }], remove: [{ kid: p.did, compromised: true }] });
  await assert.rejects(A.updateKeys({ update, approvals: [await guardians[0].seal(update)] }), /quorum/);
  const tampered = { ...update, add: [{ kid: (await Signer.generate()).did, role: 'root' }] };
  await assert.rejects(A.updateKeys({ update: tampered, approvals: [await guardians[0].seal(update), await guardians[1].seal(update)] }), /quorum/, 'signatures over a different update do not count');
  const r = await A.updateKeys({ update, approvals: [await guardians[0].seal(update), await guardians[2].seal(update)] });
  assert.equal(r.keys.filter((k) => k.role === 'root' && !k.removedAt)[0].kid, fresh.did);
  // The thief holding the old root key can no longer issue.
  const agent = await AgentRuntime.create({ name: 'Evil', purpose: 'x', model: 'm', manifest: {} });
  await assert.rejects(A.registerPassport(await p.issuePassport(agent)), /withdrawn/);
  p.adoptKey('root', fresh);
  await A.registerPassport(await p.issuePassport(agent));
});

test('approver keys can co-sign only up to their limit', async () => {
  const { A, p, agent } = await org();
  await addKey(A, p, 'approver', { label: 'phone', maxAmount: 1000 });
  const big = await A.verifyIntent(await pay(agent, 2500));
  const ap = await A.approval(big.approvalId);
  await assert.rejects(A.resolveApproval(await p.cosign(ap, 'approve', { key: 'approver' })), /up to 1,000/);
  const small = await A.verifyIntent(await pay(agent, 700));
  const r = await A.resolveApproval(await p.cosign(await A.approval(small.approvalId), 'approve', { key: 'approver' }));
  assert.equal(r.status, 'approved');
  // Approver keys cannot issue.
  await assert.rejects(A.registerMandate(await p.keys.approver.seal({ ...agent.mandate, id: 'md_2' })), /withdrawn|invalid/);
});

test('freeze: one signature stops every agent and declines what is waiting', async () => {
  const { A, p, agent } = await org();
  const held = await A.verifyIntent(await pay(agent, 900));
  const r = await A.setFreeze(await p.freeze(true, 'incident'));
  assert.equal(r.declined, 1);
  assert.equal((await A.approval(held.approvalId)).status, 'declined');
  const d = await A.verifyIntent(await pay(agent, 10));
  assert.equal(d.failedAt, 'identity');
  assert.match(d.checks[2].detail, /froze all agents: incident/);
  const outsider = await Principal.create({ name: 'x' });
  await assert.rejects(A.setFreeze({ ...(await outsider.freeze(false)), principal: p.did }), /root or operational/);
  await A.setFreeze(await p.freeze(false));
  assert.equal((await A.verifyIntent(await pay(agent, 10))).decision, 'allow');
});

test('passkeys: enroll, approve with user verification, reject replays and wrong sites', async () => {
  const { A, p, agent } = await org({ cosign: { above: 500, passkey: true } });
  const va = new VirtualAuthenticator();
  const nonce = 'n1';
  const reg = await va.create({ challenge: await enrollmentChallenge(p.did, nonce), rpId: WEBAUTHN.rpId, origin: WEBAUTHN.origins[0] });
  await assert.rejects(A.enrollPasskey(await p.passkeyEnrollment({ label: 'k', nonce: 'other', response: reg })), /different challenge/);
  const { credentialId } = await A.enrollPasskey(await p.passkeyEnrollment({ label: 'Laptop', nonce, response: reg }));

  const held = await A.verifyIntent(await pay(agent, 800));
  const ap = await A.approval(held.approvalId);
  await assert.rejects(A.resolveApproval(await p.cosign(ap)), /requires a passkey/);

  const challenge = await approvalChallenge({ approval: ap.id, intentHash: ap.intentHash, decision: 'approve' });
  const wrongSite = await va.get({ credentialId, challenge, rpId: 'evil.test', origin: 'https://evil.test' });
  await assert.rejects(A.resolveApproval({ type: 'PasskeyCoSign', approval: ap.id, decision: 'approve', principal: p.did, ...wrongSite }), /not allowed|different site/);
  const noUV = await va.get({ credentialId, challenge, ...WEBAUTHN, origin: WEBAUTHN.origins[0], userVerified: false });
  await assert.rejects(A.resolveApproval({ type: 'PasskeyCoSign', approval: ap.id, decision: 'approve', principal: p.did, ...noUV }), /did not verify the user/);
  const declineSig = await va.get({ credentialId, challenge: await approvalChallenge({ approval: ap.id, intentHash: ap.intentHash, decision: 'decline' }), rpId: WEBAUTHN.rpId, origin: WEBAUTHN.origins[0] });
  await assert.rejects(A.resolveApproval({ type: 'PasskeyCoSign', approval: ap.id, decision: 'approve', principal: p.did, ...declineSig }), /different challenge/, 'a signed decline cannot be replayed as an approve');

  const ok = await va.get({ credentialId, challenge, rpId: WEBAUTHN.rpId, origin: WEBAUTHN.origins[0] });
  const r = await A.resolveApproval({ type: 'PasskeyCoSign', approval: ap.id, decision: 'approve', principal: p.did, ...ok });
  assert.equal(r.status, 'approved');
  assert.match(r.decision.checks.at(-1).detail, /passkey/);
});

test('merkle: inclusion and consistency proofs verify for every size, and fail when tampered', async () => {
  const leaves = await Promise.all(Array.from({ length: 23 }, (_, i) => sha256('leaf' + i)));
  const t = new MerkleTree();
  for (let n = 1; n <= leaves.length; n++) {
    const root = await t.root(leaves, n);
    for (let i = 0; i < n; i++) assert.ok(await verifyInclusion(leaves[i], i, n, await t.inclusionProof(leaves, i, n), root), `incl ${i}/${n}`);
    for (let m = 1; m <= n; m++) {
      const proof = await t.consistencyProof(leaves, m, n);
      assert.ok(await verifyConsistency(m, n, await t.root(leaves, m), root, proof), `cons ${m}/${n}`);
    }
  }
  const root = await t.root(leaves);
  const proof = await t.inclusionProof(leaves, 5);
  assert.ok(!(await verifyInclusion(leaves[6], 5, leaves.length, proof, root)));
  const forked = [...leaves.slice(0, 10), await sha256('evil'), ...leaves.slice(11)];
  assert.ok(!(await verifyConsistency(12, 23, await t.root(leaves, 12), await new MerkleTree().root(forked), await t.consistencyProof(leaves, 12, 23))), 'a rewritten history is not consistent');
});

test('checkpoints: signed, provable, and witnessed', async () => {
  const { A, agent } = await org();
  const c1 = await A.checkpoint();
  await A.verifyIntent(await pay(agent, 10));
  const c2 = await A.checkpoint();
  const { proof } = await A.consistencyProof(c1.size, c2.size);
  assert.ok(await checkpointExtends(c1, c2, proof));
  const incl = await A.inclusionProof(c2.size - 1);
  assert.ok(await verifyInclusion(incl.leaf, incl.seq, incl.size, incl.proof, c2.root));
  const witness = await Signer.generate();
  const cos = await witness.seal({ type: 'WitnessCosignature', witness: witness.did, name: 'w1', checkpoint: c2 });
  await A.recordWitness(cos);
  assert.equal((await A.snapshot()).ledger.witnessed[0].size, c2.size);
});

test('signed images: a pinned image must carry a cosign signature from an endorsed publisher', async () => {
  const { A, p, host } = await org();
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const pem = '-----BEGIN PUBLIC KEY-----\n' + btoa(String.fromCharCode(...spki)) + '\n-----END PUBLIC KEY-----';
  await A.endorsePublisher(await p.endorsePublisher({ name: 'Acme CI', publicKeyPem: pem }));
  const digest = 'sha256:' + (await sha256('image'));
  const signImage = async (d, key = kp.privateKey) => {
    const payload = utf8(JSON.stringify({ critical: { identity: { 'docker-reference': 'ghcr.io/acme/payer' }, image: { 'docker-manifest-digest': d }, type: 'cosign container image signature' }, optional: null }));
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, payload));
    return { payload: b64u(payload), signature: b64u(sig) };
  };
  const agent = await AgentRuntime.create({ name: 'Img', purpose: 'x', model: 'm', manifest: { model: 'm', tools: [] } });
  agent.passport = await p.issuePassport(agent, { depth: 0, image: digest });
  await A.registerPassport(agent.passport);
  agent.mandate = await p.issueMandate({ sub: agent.did, caps: [{ action: 'x.run', resource: '*' }] });
  await A.registerMandate(agent.mandate);
  const run = async (att) => { agent.attestation = att; return A.verifyIntent(await agent.intent({ action: 'x.run', resource: 'a', reason: 'r' })); };

  assert.equal((await run(await host.attest(agent.did, agent.manifest, 600, { image: digest, imageSignature: await signImage(digest) }))).decision, 'allow');
  const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const r1 = await run(await host.attest(agent.did, agent.manifest, 600, { image: digest, imageSignature: await signImage(digest, other.privateKey) }));
  assert.equal(r1.failedAt, 'runtime');
  const r2 = await run(await host.attest(agent.did, agent.manifest, 600, { image: 'sha256:' + (await sha256('other')), imageSignature: await signImage(digest) }));
  assert.match(r2.checks[3].detail, /passport pins/);
  const r3 = await run(await host.attest(agent.did, agent.manifest));
  assert.equal(r3.failedAt, 'runtime');
});

test('federation: partner receipts are accepted only for agreed actions', async () => {
  const home = await org({ cosign: null });
  const partner = await org({ cosign: null });
  const bundle = await partner.A.trustBundle({ name: 'Partner' });
  await assert.rejects(home.A.federate(await home.p.federate({ ...bundle, name: 'Forged' }, ['payments.*'])), /not signed/);
  await home.A.federate(await home.p.federate(bundle, ['payments.send'], ['any']));
  const r = await partner.A.verifyIntent(await pay(partner.agent, 50));
  assert.ok((await home.A.acceptForeignReceipt(r.receipt)).ok);
  const trusted = [{ authority: partner.A.did, name: 'Partner', actions: ['shipments.*'] }];
  assert.match((await verifyFederatedReceipt(r.receipt, trusted)).reason, /not trusted for payments.send/);
  const own = await home.A.verifyIntent(await pay(home.agent, 50));
  assert.match((await verifyFederatedReceipt(own.receipt, trusted)).reason, /do not federate/);
});

test('rotation: a superseding passport retires the old key', async () => {
  const { A, p, host, agent } = await org({ cosign: null });
  const next = await agent.rotated();
  next.passport = await p.issuePassport(next, { supersedes: agent.passport.id });
  await A.registerPassport(next.passport);
  next.mandate = await p.issueMandate({ sub: next.did, caps: agent.mandate.caps });
  await A.registerMandate(next.mandate);
  next.attestation = await host.attest(next.did, next.manifest);
  assert.equal((await A.verifyIntent(await pay(next, 10))).decision, 'allow');
  const old = await A.verifyIntent(await pay(agent, 10));
  assert.equal(old.failedAt, 'identity');
  assert.match(old.checks[2].detail, /rotated/);
});

test('concurrency: a burst of identical or competing requests cannot double-spend', async () => {
  const { A, agent } = await org({ cosign: null });
  const intent = await pay(agent, 10);
  const same = await Promise.all(Array.from({ length: 20 }, () => A.verifyIntent(intent)));
  assert.equal(same.filter((r) => r.decision === 'allow').length, 1);
  const burst = await Promise.all(Array.from({ length: 30 }, async () => A.verifyIntent(await pay(agent, 900))));
  const allowed = burst.filter((r) => r.decision === 'allow').length;
  assert.equal(allowed, 11, 'only what fits in the 10,000 budget clears (10 + 11 × 900)');
});
