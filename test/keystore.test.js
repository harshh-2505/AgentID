import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { loadAuthoritySigner } from '../server/keystore.js';
import { verifySealed, Authority, Principal } from '../core/index.js';

test('keystore: encrypted file round-trip, wrong passphrase, tampering', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'agentid-key-'));
  try {
    const file = path.join(dir, 'nested', 'key.json');
    const cfg = (passphrase) => ({ provider: 'file', file: { path: file, passphrase } });
    const first = await loadAuthoritySigner(cfg('correct horse battery'), {});
    assert.ok(first.created);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.doesNotMatch(readFileSync(file, 'utf8'), new RegExp(first.export().d), 'private key is not stored in clear');

    const again = await loadAuthoritySigner(cfg('correct horse battery'), {});
    assert.equal(again.did, first.did);
    assert.ok(await verifySealed(await again.seal({ hello: 1 }), first.did));

    await assert.rejects(loadAuthoritySigner(cfg('wrong horse'), {}), /wrong passphrase/);
    await assert.rejects(loadAuthoritySigner(cfg(undefined), {}), /AGENTID_KEY_PASSPHRASE/);

    const orig = JSON.parse(readFileSync(file, 'utf8'));
    const ct = Buffer.from(orig.ciphertext, 'base64'); ct[5] ^= 1;
    writeFileSync(file, JSON.stringify({ ...orig, ciphertext: ct.toString('base64') }));
    await assert.rejects(loadAuthoritySigner(cfg('correct horse battery'), {}), /modified/);
    writeFileSync(file, JSON.stringify({ ...orig, did: 'did:agentid:' + 'B'.repeat(43) }));
    await assert.rejects(loadAuthoritySigner(cfg('correct horse battery'), {}), /modified/, 'header is authenticated too');

    // Environment configuration.
    writeFileSync(file, JSON.stringify(orig));
    const fromEnv = await loadAuthoritySigner({}, { AGENTID_KEY_FILE: file, AGENTID_KEY_PASSPHRASE: 'correct horse battery' });
    assert.equal(fromEnv.did, first.did);
    await assert.rejects(loadAuthoritySigner({ provider: 'kms' }, {}), /Ed25519/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A tiny stand-in for Vault's transit engine that signs with a real Ed25519 key.
async function fakeVault() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  const seen = [];
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const c of req) body += c;
    seen.push({ method: req.method, url: req.url, token: req.headers['x-vault-token'], body: body && JSON.parse(body) });
    res.setHeader('content-type', 'application/json');
    if (req.headers['x-vault-token'] !== 'root-token') { res.statusCode = 403; return res.end(JSON.stringify({ errors: ['permission denied'] })); }
    if (req.method === 'GET' && req.url === '/v1/transit/keys/agentid') {
      return res.end(JSON.stringify({ data: { type: 'ed25519', latest_version: 1, keys: { 1: { public_key: raw.toString('base64') } } } }));
    }
    if (req.method === 'POST' && req.url === '/v1/transit/sign/agentid') {
      const sig = nodeSign(null, Buffer.from(JSON.parse(body).input, 'base64'), privateKey);
      return res.end(JSON.stringify({ data: { signature: 'vault:v1:' + sig.toString('base64'), key_version: 1 } }));
    }
    res.statusCode = 404; res.end(JSON.stringify({ errors: ['no handler'] }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, addr: `http://127.0.0.1:${server.address().port}`, seen };
}

test('keystore: vault transit signer', async () => {
  const v = await fakeVault();
  try {
    const signer = await loadAuthoritySigner({ provider: 'vault' }, { VAULT_ADDR: v.addr, VAULT_TOKEN: 'root-token' });
    assert.equal(signer.export(), null, 'no private key material is held locally');
    assert.ok(await verifySealed(await signer.seal({ type: 'Test', n: 1 }), signer.did));
    assert.ok(v.seen.some((r) => r.url === '/v1/transit/sign/agentid' && r.body.key_version === 1));

    // The whole authority runs on the remote key.
    const A = await Authority.create({ signer });
    const p = await Principal.create({ name: 'Acme' });
    await A.registerPrincipal(await p.registration());
    assert.ok((await A.verifyLedger()).ok);
    assert.ok(await verifySealed(await A.checkpoint(), signer.did));
    assert.equal(A.did, signer.did);

    await assert.rejects(loadAuthoritySigner({ provider: 'vault', vault: { addr: v.addr, token: 'bad' } }, {}), /403/);
    await assert.rejects(loadAuthoritySigner({ provider: 'vault' }, {}), /VAULT_ADDR/);
  } finally {
    v.server.close();
  }
});
