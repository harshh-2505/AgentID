import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createPrivateKey, createHash, sign as nodeSign, X509Certificate } from 'node:crypto';
import { nitroVerifier, encodeCbor, AWS_NITRO_ROOT_G1 } from '../server/attestation/nitro.js';
import { Authority, Principal, AgentRuntime } from '../core/index.js';

let openssl = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { openssl = false; }

// root -> intermediate -> leaf, all EC P-384, like the real Nitro PKI.
function makeChain(dir, tag) {
  const run = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  const f = (n) => `${tag}-${n}`;
  writeFileSync(path.join(dir, 'ca.ext'), 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
  writeFileSync(path.join(dir, 'leaf.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
  const key = (n) => run('ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', f(n + '.key'));
  key('root'); key('int'); key('leaf');
  run('req', '-x509', '-new', '-key', f('root.key'), '-sha384', '-days', '30', '-subj', `/CN=${tag} root`, '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', f('root.pem'));
  run('req', '-new', '-key', f('int.key'), '-subj', `/CN=${tag} intermediate`, '-out', f('int.csr'));
  run('x509', '-req', '-in', f('int.csr'), '-CA', f('root.pem'), '-CAkey', f('root.key'), '-CAcreateserial', '-days', '30', '-sha384', '-extfile', 'ca.ext', '-out', f('int.pem'));
  run('req', '-new', '-key', f('leaf.key'), '-subj', `/CN=${tag} enclave host`, '-out', f('leaf.csr'));
  run('x509', '-req', '-in', f('leaf.csr'), '-CA', f('int.pem'), '-CAkey', f('int.key'), '-CAcreateserial', '-days', '2', '-sha384', '-extfile', 'leaf.ext', '-out', f('leaf.pem'));
  const pem = (n) => readFileSync(path.join(dir, f(n)), 'utf8');
  const der = (n) => new Uint8Array(new X509Certificate(pem(n)).raw);
  return { rootPem: pem('root.pem'), rootDer: der('root.pem'), intDer: der('int.pem'), leafDer: der('leaf.pem'), leafKey: createPrivateKey(pem('leaf.key')) };
}

const PCR0 = new Uint8Array(48).fill(0xa0);
const PCR8 = new Uint8Array(48).fill(0x08);
const hex = (b) => Buffer.from(b).toString('hex');

function buildDoc(chain, { agent, pcrs = { 0: PCR0, 8: PCR8 }, timestamp = Date.now(), userData, tamper } = {}) {
  const pcrMap = new Map(Object.entries(pcrs).map(([k, v]) => [Number(k), v]));
  const payload = new Map([
    ['module_id', 'i-0abc-enc0123'], ['digest', 'SHA384'], ['timestamp', timestamp], ['pcrs', pcrMap],
    ['certificate', chain.leafDer], ['cabundle', [chain.rootDer, chain.intDer]],
    ['public_key', null], ['user_data', userData ?? createHash('sha256').update(agent).digest()], ['nonce', null],
  ]);
  const protectedBytes = encodeCbor(new Map([[1, -35]]));
  let payloadBytes = encodeCbor(payload);
  const toSign = encodeCbor(['Signature1', protectedBytes, new Uint8Array(0), payloadBytes]);
  const sig = nodeSign('sha384', toSign, { key: chain.leafKey, dsaEncoding: 'ieee-p1363' });
  if (tamper) payloadBytes = tamper(payloadBytes);
  const cose = Buffer.concat([Buffer.from([0xd2]), encodeCbor([protectedBytes, new Map(), payloadBytes, new Uint8Array(sig)])]);
  return { format: 'aws-nitro', document: cose.toString('base64') };
}

test('nitro: the embedded AWS root is the published Root-G1', () => {
  const c = new X509Certificate(AWS_NITRO_ROOT_G1);
  assert.equal(c.fingerprint256, '64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B');
  assert.ok(c.verify(c.publicKey));
});

test('nitro: attestation documents', { skip: !openssl && 'openssl not installed' }, async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'nitro-'));
  try {
    const good = makeChain(dir, 'good');
    const evil = makeChain(dir, 'evil');
    const verify = nitroVerifier({ root: good.rootPem });
    const agent = 'did:agentid:' + 'A'.repeat(43);
    const passport = { runtime: { pcrs: { 0: hex(PCR0), 8: hex(PCR8) } } };
    const ctx = { passport, agent, nowMs: Date.now() };

    const ok = await verify(buildDoc(good, { agent }), ctx);
    assert.ok(ok.ok, ok.reason);
    assert.match(ok.detail, /Nitro enclave/);
    assert.ok((await verify(buildDoc(good, { agent, userData: Buffer.from('agent=' + agent) }), ctx)).ok, 'DID in user_data also binds');

    const wrongPcr = await verify(buildDoc(good, { agent, pcrs: { 0: new Uint8Array(48), 8: PCR8 } }), ctx);
    assert.match(wrongPcr.reason, /PCR0 does not match/);

    const foreign = await verify(buildDoc(evil, { agent }), ctx);
    assert.match(foreign.reason, /pinned Nitro root/);
    // The default verifier pins the real AWS root, which the test chain does not lead to.
    assert.ok(!(await nitroVerifier()(buildDoc(good, { agent }), ctx)).ok);

    const tampered = await verify(buildDoc(good, { agent, tamper: (b) => { const c = Buffer.from(b); c[c.indexOf('i-0abc')] ^= 1; return c; } }), ctx);
    assert.match(tampered.reason, /signature is invalid/);

    const stale = await verify(buildDoc(good, { agent, timestamp: Date.now() - 3_600_000 }), ctx);
    assert.match(stale.reason, /old/);

    const unbound = await verify(buildDoc(good, { agent: 'did:agentid:someone-else' }), ctx);
    assert.match(unbound.reason, /not bound/);

    assert.match((await verify(buildDoc(good, { agent }), { ...ctx, passport: { runtime: {} } })).reason, /pins no enclave PCRs/);
    assert.match((await verify({ format: 'aws-nitro', document: 'AAAA' }, ctx)).reason, /malformed/);

    // End to end through the authority: a passport that pins PCRs, an intent carrying the document.
    const A = await Authority.create({ attestation: { 'aws-nitro': nitroVerifier({ root: good.rootPem }) } });
    const p = await Principal.create({ name: 'Acme' });
    await A.registerPrincipal(await p.registration());
    const bot = await AgentRuntime.create({ name: 'Enclave bot', purpose: 'x', model: 'm', manifest: { model: 'm', tools: [] } });
    const body = await p.issuePassport(bot, { depth: 0 });
    const { proof: _p, ...unsigned } = body;
    bot.passport = await p.signer.seal({ ...unsigned, runtime: { ...unsigned.runtime, pcrs: passport.runtime.pcrs } });
    await A.registerPassport(bot.passport);
    bot.mandate = await p.issueMandate({ sub: bot.did, caps: [{ action: 'x.run', resource: '*' }] });
    await A.registerMandate(bot.mandate);
    bot.attestation = buildDoc(good, { agent: bot.did });
    const r = await A.verifyIntent(await bot.intent({ action: 'x.run', resource: 'a', reason: 'r' }));
    assert.equal(r.decision, 'allow', JSON.stringify(r.checks));
    bot.attestation = buildDoc(good, { agent: bot.did, pcrs: { 0: PCR0, 8: new Uint8Array(48) } });
    assert.equal((await A.verifyIntent(await bot.intent({ action: 'x.run', resource: 'a', reason: 'r' }))).failedAt, 'runtime');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
