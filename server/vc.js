// GET /v1/passports/:id/credential — a registered passport as a W3C Verifiable Credential,
// issued by the authority (see core/vc.js for why the authority, not the principal, signs).
// `:id` may be a passport id or the agent's did:agentid.

import { passportToCredential } from '../core/vc.js';

const httpError = (status, message) => Object.assign(new Error(message), { status });

export function routes(ctx) {
  return [
    ['GET', '/v1/passports/:id/credential', async (_b, params) => {
      const A = ctx.authority();
      const snap = await A.snapshot();
      const rec = snap.passports.find((p) => p.id === params.id) || snap.passports.find((p) => p.sub === params.id && p.status === 'active');
      if (!rec) throw httpError(404, 'passport not found');
      // Only attest to what is true now; a revoked or frozen passport gets no credential.
      if (rec.status !== 'active') throw httpError(409, `passport is ${rec.status}`);
      const { status, root, profile, ...passport } = rec;
      return passportToCredential(passport, A.signer, { principal: root, status });
    }],
  ];
}
