// Federation: agents from another organisation's authority acting on your services.
//
// Each authority publishes a signed TrustBundle (its identifier, name and endpoints).
// A principal that wants to accept a partner's agents signs a Federation agreement that
// names the partner's authority and the actions it is trusted for. A relying service,
// or the local authority on its behalf, then accepts the partner's receipts offline,
// but only for those actions, so a partner can never grant more than you agreed to.

import { verifySealed } from './keys.js';
import { globMatch } from './policy.js';

export async function verifyTrustBundle(bundle, nowSec = Math.floor(Date.now() / 1000)) {
  if (bundle?.type !== 'TrustBundle') return { ok: false, reason: 'not a trust bundle' };
  if (!(await verifySealed(bundle, bundle.authority))) return { ok: false, reason: 'bundle is not signed by the authority it names' };
  if (bundle.exp && bundle.exp < nowSec) return { ok: false, reason: 'trust bundle expired' };
  return { ok: true };
}

// `trusted` is a list of { authority, name, actions: [patterns], audiences?: [aud] }.
export async function verifyFederatedReceipt(receipt, trusted, { aud, maxAgeSec = 120, nowSec = Math.floor(Date.now() / 1000) } = {}) {
  if (receipt?.type !== 'Receipt') return { ok: false, reason: 'not a receipt' };
  const t = trusted.find((x) => x.authority === receipt.authority);
  if (!t) return { ok: false, reason: 'receipt comes from an authority you do not federate with' };
  if (!(await verifySealed(receipt, t.authority))) return { ok: false, reason: `receipt is not signed by ${t.name}` };
  if (!t.actions.some((p) => globMatch(p, receipt.action))) return { ok: false, reason: `${t.name} is not trusted for ${receipt.action}` };
  if (t.audiences && !t.audiences.includes(receipt.aud)) return { ok: false, reason: `${t.name} is not trusted for audience ${receipt.aud}` };
  if (aud && receipt.aud !== aud) return { ok: false, reason: 'receipt is for a different service' };
  if (nowSec - receipt.iat > maxAgeSec) return { ok: false, reason: 'receipt is too old' };
  return { ok: true, receipt, via: t.name };
}
