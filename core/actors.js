// The parties that hold keys: principals (people or organisations), attestors
// (the hosts that run agents) and agents. The authority never holds their keys.

import { Signer } from './keys.js';
import { canonical, sha256, randomId, nowSec } from './encoding.js';

// A runtime measurement is the hash of what makes the agent *this* agent:
// model, system prompt, tool list and code. Change any of them and the hash changes.
export async function measure(manifest) {
  return sha256(canonical(manifest));
}

export class Principal {
  // A principal is identified by its first root key forever, but can hold more keys:
  // `operational` keys for day-to-day issuance, `approver` keys (e.g. on a phone) that
  // may only co-sign, and further `root` keys. Lost or stolen keys are rotated out with
  // a KeyUpdate, signed by a root key or by the recovery guardians.
  constructor(signer, { name, kind = 'organization', keys = {}, recovery = null }) {
    this.signer = signer;
    this.did = signer.did;
    this.name = name;
    this.kind = kind;
    this.keys = { root: signer, ...keys };
    this.recovery = recovery;
  }

  static async create(opts) {
    return new Principal(await Signer.generate(), opts);
  }

  static async restore({ jwk, name, kind, keys = {}, recovery = null }) {
    const restored = {};
    for (const [role, k] of Object.entries(keys)) restored[role] = await Signer.fromJwk(k);
    return new Principal(await Signer.fromJwk(jwk), { name, kind, keys: restored, recovery });
  }

  export() {
    const keys = {};
    for (const [role, s] of Object.entries(this.keys)) if (role !== 'root') keys[role] = s.export();
    return { jwk: this.signer.export(), name: this.name, kind: this.kind, keys, recovery: this.recovery };
  }

  // Signs with the operational key when one exists, so the root key can stay offline.
  #issuer() {
    return this.keys.operational || this.keys.root;
  }

  registration() {
    return this.signer.seal({ type: 'PrincipalRegistration', v: 1, did: this.did, name: this.name, kind: this.kind, recovery: this.recovery || undefined, iat: nowSec() });
  }

  endorseAttestor(attestor) {
    return this.#issuer().seal({ type: 'AttestorEndorsement', v: 1, attestor: attestor.did, name: attestor.name, iss: this.did, iat: nowSec() });
  }

  endorsePublisher({ name, publicKeyPem }) {
    return this.#issuer().seal({ type: 'PublisherEndorsement', v: 1, name, publicKeyPem, iss: this.did, iat: nowSec() });
  }

  async issuePassport(agent, { ttlSec = 30 * 86400, depth = 1, supersedes, image } = {}) {
    return this.#issuer().seal(await passportBody(this.did, agent, { ttlSec, depth, parent: null, supersedes, image }));
  }

  issueMandate(opts) {
    return this.#issuer().seal(mandateBody(this.did, { ...opts, parent: null }));
  }

  // `key` picks which of the principal's keys signs: root, operational or approver.
  cosign(approval, decision = 'approve', { key } = {}) {
    const s = (key && this.keys[key]) || this.keys.approver || this.#issuer();
    return s.seal({ type: 'CoSign', v: 1, approval: approval.id, intentHash: approval.intentHash, decision, iss: this.did, iat: nowSec() });
  }

  revoke(target, reason = '') {
    return this.#issuer().seal({ type: 'Revocation', v: 1, target, reason, iss: this.did, iat: nowSec() });
  }

  freeze(frozen = true, reason = '') {
    return this.#issuer().seal({ type: 'Freeze', v: 1, principal: this.did, frozen, reason, iat: nowSec() });
  }

  // Builds an unsigned key update. Sign it with signKeyUpdate (root) or have guardians sign it.
  keyUpdate({ add = [], remove = [] }) {
    return { type: 'KeyUpdate', v: 1, principal: this.did, add, remove, nonce: randomId('ku'), iat: nowSec() };
  }

  signKeyUpdate(update, role = 'root') {
    return this.keys[role].seal(update);
  }

  // Generates a new key for `role`, registers nothing: returns { signer, update } for the caller to submit.
  async newKey(role, { label, maxAmount, exp } = {}) {
    const signer = await Signer.generate();
    const update = this.keyUpdate({ add: [{ kid: signer.did, role, label, maxAmount, exp }] });
    return { signer, update };
  }

  adoptKey(role, signer) {
    this.keys[role] = signer;
  }

  // Accept receipts from a partner authority, for the listed actions only.
  federate(bundle, actions, audiences) {
    return this.keys.root.seal({ type: 'Federation', v: 1, principal: this.did, bundle, actions, audiences, iat: nowSec() });
  }

  passkeyEnrollment({ label, nonce, response }) {
    return this.#issuer().seal({ type: 'PasskeyEnrollment', v: 1, principal: this.did, label, nonce, response, iat: nowSec() });
  }
}

export class Attestor {
  constructor(signer, name) {
    this.signer = signer;
    this.did = signer.did;
    this.name = name;
  }

  static async create(name) {
    return new Attestor(await Signer.generate(), name);
  }

  static async restore({ jwk, name }) {
    return new Attestor(await Signer.fromJwk(jwk), name);
  }

  export() {
    return { jwk: this.signer.export(), name: this.name };
  }

  // The host measures the agent it is actually running. In production this is a
  // TEE quote or a signed container digest; the shape of the evidence is the same.
  // `image` and `imageSignature` carry the container digest the host launched and its
  // cosign signature, for passports that pin a signed image.
  async attest(agentDid, manifest, ttlSec = 600, { image, imageSignature } = {}) {
    const iat = nowSec();
    return this.signer.seal({ type: 'RuntimeAttestation', v: 1, format: 'agentid-host', sub: agentDid, measurement: await measure(manifest), image, imageSignature, iss: this.did, iat, exp: iat + ttlSec });
  }
}

export class AgentRuntime {
  constructor(signer, { name, purpose, model, manifest }) {
    this.signer = signer;
    this.did = signer.did;
    this.name = name;
    this.purpose = purpose;
    this.model = model;
    this.manifest = manifest;
    this.passport = null;
    this.mandate = null;
    this.attestation = null;
  }

  static async create(opts) {
    return new AgentRuntime(await Signer.generate(), opts);
  }

  static async restore({ jwk, ...rest }) {
    const a = new AgentRuntime(await Signer.fromJwk(jwk), rest);
    Object.assign(a, { passport: rest.passport ?? null, mandate: rest.mandate ?? null, attestation: rest.attestation ?? null });
    return a;
  }

  export() {
    const { name, purpose, model, manifest, passport, mandate, attestation } = this;
    return { jwk: this.signer.export(), name, purpose, model, manifest, passport, mandate, attestation };
  }

  measurement() {
    return measure(this.manifest);
  }

  // Short-lived keys: a fresh key pair for the same agent. The issuer then grants the new
  // key a passport with `supersedes` set, which retires the old passport automatically.
  async rotated() {
    const next = new AgentRuntime(await Signer.generate(), { name: this.name, purpose: this.purpose, model: this.model, manifest: this.manifest });
    next.previous = this.passport?.id ?? null;
    return next;
  }

  // Agents can mint passports and mandates for sub-agents. The authority accepts them
  // only if they chain back to a principal and never exceed what this agent holds.
  async issuePassport(subAgent, { ttlSec = 7 * 86400, depth = 0 } = {}) {
    const body = await passportBody(this.did, subAgent, { ttlSec, depth, parent: this.passport?.id ?? null });
    return this.signer.seal(body);
  }

  delegate(opts) {
    if (!this.mandate) throw new Error(`${this.name} holds no mandate to delegate from`);
    return this.signer.seal(mandateBody(this.did, { ...opts, parent: this.mandate.id }));
  }

  // Builds a signed intent: proof that this key is acting, what it wants to do,
  // why, and evidence of the runtime it is running in.
  intent({ action, resource, params = {}, reason = '', aud = 'any', ttlSec = 60 }) {
    const iat = nowSec();
    return this.signer.seal({
      type: 'Intent', v: 1, id: randomId('in'),
      agent: this.did, passport: this.passport?.id, mandate: this.mandate?.id,
      action, resource, params, reason, aud,
      nonce: randomId('n'), iat, exp: iat + ttlSec,
      attestation: this.attestation,
    });
  }
}

async function passportBody(iss, agent, { ttlSec, depth, parent, supersedes, image }) {
  const iat = nowSec();
  return {
    type: 'AgentPassport', v: 1, id: randomId('pp'),
    sub: agent.did, iss, parent,
    name: agent.name, purpose: agent.purpose, model: agent.model,
    runtime: { measurement: await measure(agent.manifest), tools: agent.manifest?.tools ?? [], image },
    depth, iat, exp: iat + ttlSec, supersedes,
  };
}

function mandateBody(iss, { sub, caps, budget = null, rate = null, cosign = null, depth = 0, ttlSec = 7 * 86400, parent, label = '' }) {
  const iat = nowSec();
  return { type: 'Mandate', v: 1, id: randomId('md'), iss, sub, parent, label, caps, budget, rate, cosign, depth, nbf: iat, exp: iat + ttlSec };
}
