// Where the authority's own Ed25519 key lives.
//
// The authority signs every receipt, ledger entry and checkpoint with one key, and its
// DID is that key. Losing it means a new identity; leaking it means forged receipts.
// Providers, from simplest to strongest:
//
//   file   The JWK encrypted at rest with AES-256-GCM under a key derived (scrypt) from
//          AGENTID_KEY_PASSPHRASE. Created on first run. The passphrase comes from the
//          environment or a secrets manager, never from the same disk as the file.
//   vault  HashiCorp Vault's transit engine holds an ed25519 key and signs for us. The
//          private key never leaves Vault; we only read the public key (to build the
//          DID) and call transit/sign. Create it with:
//            vault secrets enable transit
//            vault write -f transit/keys/agentid type=ed25519
//          and give the authority a token whose policy allows only
//            read   transit/keys/agentid
//            update transit/sign/agentid
//   kms    AWS KMS does not offer Ed25519 signing keys (only RSA, NIST ECC and
//          secp256k1), so there is no KMS provider. To use KMS, CloudHSM, GCP KMS or any
//          remote signer that does Ed25519, construct core ExternalSigner yourself:
//            new ExternalSigner(didFromPublicKey(raw32), async (bytes) => sig64)
//          and pass it as the authority's signer. The authority never needs the key itself.
//   ephemeral  a fresh key per process: tests and demos only.

import { randomBytes, scrypt as scryptCb, createCipheriv, createDecipheriv } from 'node:crypto';
import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { Signer, ExternalSigner, didFromPublicKey, verifySealed } from '../core/keys.js';
import { canonical } from '../core/encoding.js';

const scrypt = promisify(scryptCb);
const FORMAT = 'agentid-key/1';
const SCRYPT = { N: 1 << 15, r: 8, p: 1 };

// config = { provider, file: { path, passphrase }, vault: { addr, token, key, mount, namespace } }
// Missing fields fall back to the environment (see envConfig).
export async function loadAuthoritySigner(config = {}, env = process.env) {
  const c = mergeEnv(config, env);
  switch (c.provider) {
    case 'file': return loadFileSigner(c.file);
    case 'vault': return vaultSigner(c.vault);
    case 'ephemeral': return Signer.generate();
    case 'kms': throw new Error('AWS KMS cannot sign with Ed25519. Use the vault provider, or wrap your signer in core ExternalSigner (see server/keystore.js).');
    default: throw new Error(`unknown key provider "${c.provider}" (use file, vault or ephemeral)`);
  }
}

function mergeEnv(config, env) {
  return {
    provider: config.provider || env.AGENTID_KEY_PROVIDER || 'file',
    file: { path: env.AGENTID_KEY_FILE || 'data/authority-key.json', passphrase: env.AGENTID_KEY_PASSPHRASE, ...config.file },
    vault: {
      addr: env.VAULT_ADDR, token: env.VAULT_TOKEN, namespace: env.VAULT_NAMESPACE,
      key: env.AGENTID_VAULT_KEY || 'agentid', mount: env.AGENTID_VAULT_MOUNT || 'transit', ...config.vault,
    },
  };
}

// ---------------------------------------------------------------- encrypted file

// The header (format, kdf params, salt, iv, did) is authenticated as GCM additional data,
// so editing any of it, not just the ciphertext, makes decryption fail.
const aad = (h) => Buffer.from(canonical({ format: h.format, kdf: h.kdf, iv: h.iv, did: h.did }));

async function deriveKey(passphrase, kdf) {
  if (kdf.name !== 'scrypt') throw new Error(`unsupported key derivation ${kdf.name}`);
  return scrypt(passphrase.normalize('NFKC'), Buffer.from(kdf.salt, 'base64'), 32, { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: 256 * kdf.N * kdf.r });
}

export async function encryptJwk(jwk, passphrase, did) {
  if (!passphrase) throw new Error('AGENTID_KEY_PASSPHRASE is required to encrypt the authority key');
  const h = { format: FORMAT, kdf: { name: 'scrypt', ...SCRYPT, salt: randomBytes(16).toString('base64') }, iv: randomBytes(12).toString('base64'), did };
  const cipher = createCipheriv('aes-256-gcm', await deriveKey(passphrase, h.kdf), Buffer.from(h.iv, 'base64'));
  cipher.setAAD(aad(h));
  const ct = Buffer.concat([cipher.update(JSON.stringify(jwk), 'utf8'), cipher.final()]);
  return { ...h, cipher: 'aes-256-gcm', ciphertext: ct.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

export async function decryptJwk(file, passphrase) {
  if (!passphrase) throw new Error('AGENTID_KEY_PASSPHRASE is required to unlock the authority key');
  if (file?.format !== FORMAT || file.cipher !== 'aes-256-gcm') throw new Error('not an AgentID key file (or an unsupported version)');
  try {
    const d = createDecipheriv('aes-256-gcm', await deriveKey(passphrase, file.kdf), Buffer.from(file.iv, 'base64'));
    d.setAAD(aad(file));
    d.setAuthTag(Buffer.from(file.tag, 'base64'));
    return JSON.parse(Buffer.concat([d.update(Buffer.from(file.ciphertext, 'base64')), d.final()]).toString('utf8'));
  } catch {
    throw new Error('could not unlock the authority key: wrong passphrase, or the key file was modified');
  }
}

export async function loadFileSigner({ path: file, passphrase }) {
  let raw = null;
  try { raw = await readFile(file, 'utf8'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (raw === null) {
    const signer = await Signer.generate();
    const enc = await encryptJwk(signer.export(), passphrase, signer.did);
    await mkdir(path.dirname(path.resolve(file)), { recursive: true });
    const tmp = file + '.' + process.pid + '.tmp';
    await writeFile(tmp, JSON.stringify(enc, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    await rename(tmp, file);
    signer.created = true;
    return signer;
  }
  const parsed = JSON.parse(raw);
  const signer = await Signer.fromJwk(await decryptJwk(parsed, passphrase));
  if (signer.did !== parsed.did) throw new Error('key file holds a different key than its header names');
  return signer;
}

// ---------------------------------------------------------------- Vault transit

export async function vaultSigner({ addr, token, key = 'agentid', mount = 'transit', namespace, fetch: fetchFn = globalThis.fetch }) {
  if (!addr || !token) throw new Error('vault provider needs VAULT_ADDR and VAULT_TOKEN');
  const base = addr.replace(/\/$/, '') + '/v1/' + mount;
  const headers = { 'x-vault-token': token, 'content-type': 'application/json', ...(namespace ? { 'x-vault-namespace': namespace } : {}) };
  const call = async (method, p, body) => {
    const res = await fetchFn(base + p, { method, headers, body: body && JSON.stringify(body) });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`vault ${method} ${mount}${p}: ${res.status} ${(json.errors || []).join('; ')}`);
    return json.data;
  };

  const info = await call('GET', `/keys/${encodeURIComponent(key)}`);
  if (info.type !== 'ed25519') throw new Error(`vault key ${key} is ${info.type}, AgentID needs ed25519`);
  // Pin the version we built the DID from: rotating the key in Vault must not silently
  // change what we sign with, since the authority's identity is this public key.
  const version = info.latest_version;
  const pub = Buffer.from(info.keys[version].public_key, 'base64');
  if (pub.length !== 32) throw new Error('vault returned an unexpected public key');
  const did = didFromPublicKey(new Uint8Array(pub));

  const signer = new ExternalSigner(did, async (bytes) => {
    const data = await call('POST', `/sign/${encodeURIComponent(key)}`, { input: Buffer.from(bytes).toString('base64'), key_version: version });
    const m = /^vault:v(\d+):(.+)$/.exec(data.signature || '');
    if (!m || Number(m[1]) !== version) throw new Error('vault returned an unexpected signature format or key version');
    return new Uint8Array(Buffer.from(m[2], 'base64'));
  }, `vault transit ${mount}/${key} v${version}`);

  // A misconfigured mount or key would otherwise surface only as unverifiable receipts.
  if (!(await verifySealed(await signer.seal({ type: 'KeyCheck' }), did))) throw new Error('vault signature does not verify against the key it published');
  return signer;
}
