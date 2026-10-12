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
  constructor(signer, { name, kind = 'organization' }) {
    this.signer = signer;
    this.did = signer.did;
    this.name = name;
    this.kind = kind;
  }

  static async create(opts) {
    return new Principal(await Signer.generate(), opts);
  }

  static async restore({ jwk, name, kind }) {
    return new Principal(await Signer.fromJwk(jwk), { name, kind });
  }

  export() {
    return { jwk: this.signer.export(), name: this.name, kind: this.kind };
  }

  registration() {
    return this.signer.seal({ type: 'PrincipalRegistration', v: 1, did: this.did, name: this.name, kind: this.kind, iat: nowSec() });
  }

  endorseAttestor(attestor) {
    return this.signer.seal({ type: 'AttestorEndorsement', v: 1, attestor: attestor.did, name: attestor.name, iss: this.did, iat: nowSec() });
  }

  async issuePassport(agent, { ttlSec = 30 * 86400, depth = 1 } = {}) {
    return this.signer.seal(await passportBody(this.did, agent, { ttlSec, depth, parent: null }));
  }

  issueMandate(opts) {
    return this.signer.seal(mandateBody(this.did, { ...opts, parent: null }));
  }

  cosign(approval, decision = 'approve') {
    return this.signer.seal({ type: 'CoSign', v: 1, approval: approval.id, intentHash: approval.intentHash, decision, iss: this.did, iat: nowSec() });
  }

  revoke(target, reason = '') {
    return this.signer.seal({ type: 'Revocation', v: 1, target, reason, iss: this.did, iat: nowSec() });
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
  async attest(agentDid, manifest, ttlSec = 600) {
    const iat = nowSec();
    return this.signer.seal({ type: 'RuntimeAttestation', v: 1, sub: agentDid, measurement: await measure(manifest), iss: this.did, iat, exp: iat + ttlSec });
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

async function passportBody(iss, agent, { ttlSec, depth, parent }) {
  const iat = nowSec();
  return {
    type: 'AgentPassport', v: 1, id: randomId('pp'),
    sub: agent.did, iss, parent,
    name: agent.name, purpose: agent.purpose, model: agent.model,
    runtime: { measurement: await measure(agent.manifest), tools: agent.manifest?.tools ?? [] },
    depth, iat, exp: iat + ttlSec,
  };
}

function mandateBody(iss, { sub, caps, budget = null, rate = null, cosign = null, depth = 0, ttlSec = 7 * 86400, parent, label = '' }) {
  const iat = nowSec();
  return { type: 'Mandate', v: 1, id: randomId('md'), iss, sub, parent, label, caps, budget, rate, cosign, depth, nbf: iat, exp: iat + ttlSec };
}
