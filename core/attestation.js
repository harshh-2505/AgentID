// Proof of runtime: evidence that the process holding an agent's key is running the
// code its passport was issued for.
//
// Formats are pluggable. Core ships two that run anywhere:
//   agentid-host  a host the principal endorsed signs the agent's manifest hash, and
//                 optionally the container image digest it launched.
//   + cosign      when the passport pins an image, the image must also carry a valid
//                 cosign (sigstore) signature from a publisher key the principal trusts.
// The server adds aws-nitro (hardware enclave attestation documents), see
// server/attestation/nitro.js.

import { verifySealed } from './keys.js';
import { unb64u } from './encoding.js';
import { derToRaw } from './webauthn.js';

export function pemToDer(pem) {
  const body = pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, '').replace(/\s+/g, '');
  return unb64u(body.replace(/\+/g, '-').replace(/\//g, '_'));
}

// cosign "simple signing" payload, signed with ECDSA P-256 / SHA-256 (keyed mode).
export async function verifyCosignSignature({ payload, signature }, publicKeyPem, expectedDigest) {
  const key = await crypto.subtle.importKey('spki', pemToDer(publicKeyPem), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const payloadBytes = unb64u(payload.replace(/\+/g, '-').replace(/\//g, '_'));
  let sig = unb64u(signature.replace(/\+/g, '-').replace(/\//g, '_'));
  if (sig[0] === 0x30) sig = derToRaw(sig);
  if (!(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, payloadBytes))) return { ok: false, reason: 'image signature is invalid' };
  const doc = JSON.parse(new TextDecoder().decode(payloadBytes));
  const digest = doc?.critical?.image?.['docker-manifest-digest'];
  if (doc?.critical?.type !== 'cosign container image signature') return { ok: false, reason: 'not a cosign image signature' };
  if (digest !== expectedDigest) return { ok: false, reason: `signature covers ${digest}, not ${expectedDigest}` };
  return { ok: true, reference: doc.critical.identity?.['docker-reference'] };
}

export async function verifyHostAttestation(att, { passport, agent, root, tx, now }) {
  const host = await tx.get('attestor', att.iss);
  if (!host || !host.endorsedBy.includes(root)) return { ok: false, reason: 'attested by a host this principal does not trust' };
  if (!(await verifySealed(att, att.iss))) return { ok: false, reason: 'attestation signature is invalid' };
  if (att.sub !== agent) return { ok: false, reason: 'attestation is for a different agent' };
  if (att.exp < now) return { ok: false, reason: 'attestation expired' };
  const rt = passport.runtime;
  if (att.measurement !== rt.measurement) {
    return { ok: false, reason: `runtime changed since the passport was issued (expected ${rt.measurement.slice(0, 10)}…, running ${String(att.measurement).slice(0, 10)}…)` };
  }
  let detail = `${host.name} measured ${att.measurement.slice(0, 12)}…`;
  if (rt.image) {
    if (att.image !== rt.image) return { ok: false, reason: `host launched image ${att.image || 'none'}, passport pins ${rt.image}` };
    if (!att.imageSignature) return { ok: false, reason: 'pinned image has no signature attached' };
    const publishers = (await tx.list('publisher')).filter((p) => p.endorsedBy.includes(root));
    let last = 'no trusted image publisher';
    for (const p of publishers) {
      const r = await verifyCosignSignature(att.imageSignature, p.publicKeyPem, rt.image);
      if (r.ok) { detail += ` · image signed by ${p.name}`; last = null; break; }
      last = r.reason;
    }
    if (last) return { ok: false, reason: last };
  }
  return { ok: true, detail };
}
