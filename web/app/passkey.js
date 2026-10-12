// Passkeys in the console. A real platform passkey (Touch ID, Windows Hello, a phone or
// a security key) is used when the browser allows it here. Inside sandboxed frames it
// usually can't, so the demo falls back to a virtual authenticator that produces the
// same standard WebAuthn bytes, and says so.

import { b64u, unb64u, utf8 } from '../../core/encoding.js';

const canUseReal = () => typeof PublicKeyCredential !== 'undefined' && window.isSecureContext && location.origin !== 'null' && !!navigator.credentials?.create;

// Errors that mean "not possible here", as opposed to the person cancelling.
const unsupported = (e) => ['SecurityError', 'NotSupportedError', 'InvalidStateError', 'TypeError'].includes(e?.name) || /permissions policy|not allowed in this context|feature/i.test(e?.message || '');

export async function enroll(backend, { virtual = false } = {}) {
  if (!virtual && canUseReal()) {
    const wa = backend.webauthn();
    const { nonce, challenge, user } = await backend.passkeyChallenge();
    try {
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: unb64u(challenge),
          rp: { id: wa.rpId, name: 'AgentID' },
          user: { id: utf8(user.id).slice(0, 64), name: user.name, displayName: user.name },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
          timeout: 60_000,
        },
      });
      const response = { clientDataJSON: b64u(new Uint8Array(cred.response.clientDataJSON)), attestationObject: b64u(new Uint8Array(cred.response.attestationObject)) };
      const r = await backend.enrollPasskey({ nonce, response, label: 'This device' });
      return { ...r, virtual: false };
    } catch (e) {
      if (!unsupported(e)) throw e;
    }
  }
  const r = await backend.enrollPasskey({});
  return { ...r, virtual: true };
}

// Decides a held request with the first enrolled passkey this browser can use.
export async function decide(backend, snap, approvalId, decision, { virtual = false } = {}) {
  const p = snap.principals[0];
  const virtualIds = new Set(snap.world.virtualPasskeys || []);
  const real = p.passkeys.find((k) => !virtualIds.has(k.credentialId));
  if (real && !virtual && canUseReal()) {
    const wa = backend.webauthn();
    const { challenge } = await backend.passkeyApprovalChallenge(approvalId, decision);
    try {
      const a = await navigator.credentials.get({
        publicKey: { challenge: unb64u(challenge), rpId: wa.rpId, allowCredentials: [{ type: 'public-key', id: unb64u(real.credentialId) }], userVerification: 'required', timeout: 60_000 },
      });
      return backend.approveWithPasskey(approvalId, decision, {
        credentialId: real.credentialId,
        authenticatorData: b64u(new Uint8Array(a.response.authenticatorData)),
        clientDataJSON: b64u(new Uint8Array(a.response.clientDataJSON)),
        signature: b64u(new Uint8Array(a.response.signature)),
      });
    } catch (e) {
      if (!unsupported(e)) throw e;
    }
  }
  if (!p.passkeys.some((k) => virtualIds.has(k.credentialId))) await backend.enrollPasskey({});
  return backend.approveWithPasskey(approvalId, decision, null);
}
