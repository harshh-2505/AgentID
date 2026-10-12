// The AgentID authority: registry, verifier, co-sign desk, revocation list and ledger.
//
// It holds exactly one private key, its own, used to sign receipts, ledger entries and
// checkpoints. That key can live in a KMS (see ExternalSigner). Principals and agents
// keep their keys; the authority only ever sees signatures.
//
// All state lives in a Store. Every write runs inside store.transaction(), which is
// what makes nonce, budget and approval checks safe across processes.

import { Signer, verifySealed, isDid, shortDid } from './keys.js';
import { hashObject, randomId, canonical, sha256, b64u, utf8 } from './encoding.js';
import { GENESIS, entryHash, verifyChain } from './ledger.js';
import { authorize, capsWithin, globMatch } from './policy.js';
import { MemoryStore } from './store.js';
import { MerkleTree, verifyConsistency } from './merkle.js';
import { verifyHostAttestation } from './attestation.js';
import { verifyRegistration, verifyAssertion, approvalChallenge } from './webauthn.js';
import { verifyTrustBundle, verifyFederatedReceipt } from './federation.js';

export const CHECKS = [
  ['signature', 'Proof of key'],
  ['freshness', 'Freshness & replay'],
  ['identity', 'Passport chain'],
  ['runtime', 'Proof of runtime'],
  ['mandate', 'Mandate chain'],
  ['scope', 'Scope'],
  ['limits', 'Limits'],
  ['budget', 'Budget & rate'],
  ['risk', 'Behavioral risk'],
  ['cosign', 'Co-sign'],
];

export const RISK_STEP_UP = 50;
const MAX_CHAIN = 8;
const APPROVAL_TTL_MS = 15 * 60 * 1000;
const ISSUE_ROLES = ['root', 'operational'];
const COSIGN_ROLES = ['root', 'operational', 'approver'];
const INJECTION = /(ignore (all |any )?(previous|prior|above|earlier) instructions|disregard (your|the|all) (rules|instructions|policy)|reveal (your|the) system prompt|you are now (in )?|exfiltrat|developer mode|send (all|every) (the )?(data|records|credentials|keys))/i;

const fail = (reason) => ({ ok: false, reason });
const emptyProfile = () => ({ actions: [], resources: [], amounts: [], recent: [] });

export class Authority {
  // options:
  //   store        a Store (default: MemoryStore)
  //   clock        () => ms, for tests
  //   admit        async (registration, evidence) => ({ ok, reason?, subject? }) gate for new principals
  //   webauthn     { rpId, origins } for passkey enrollment and co-sign
  //   attestation  { format: async verifier } extra runtime evidence formats
  constructor(signer, { store, clock, admit, webauthn, attestation } = {}) {
    this.signer = signer;
    this.clock = clock || (() => Date.now());
    this.store = store || new MemoryStore();
    this.admit = admit || null;
    this.webauthn = webauthn || null;
    this.verifiers = { 'agentid-host': verifyHostAttestation, ...(attestation || {}) };
    this.listeners = new Set();
    this.merkle = new MerkleTree();
  }

  static async create(opts = {}) {
    return new Authority(opts.signer || await Signer.generate(), opts);
  }

  // Restores an in-memory authority from export(). Durable deployments use a database store instead.
  static async restore({ jwk, store }, opts = {}) {
    return new Authority(await Signer.fromJwk(jwk), { ...opts, store: new MemoryStore(store) });
  }

  export() {
    if (!(this.store instanceof MemoryStore)) throw new Error('export is only for the in-memory store');
    return { jwk: this.signer.export(), store: this.store.export() };
  }

  get did() { return this.signer.did; }
  nowMs() { return this.clock(); }
  now() { return Math.floor(this.clock() / 1000); }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  emit(type, data) { for (const fn of this.listeners) { try { fn({ type, data }); } catch { /* listener errors stay local */ } } }

  // Runs fn in a store transaction and publishes its events only after it commits.
  async #write(fn) {
    const events = [];
    const result = await this.store.transaction((tx) => {
      tx.emit = (type, data) => events.push([type, data]);
      return fn(tx);
    });
    for (const [type, data] of events) this.emit(type, data);
    return result;
  }

  async #record(tx, kind, data) {
    const ts = this.nowMs();
    const entry = await tx.appendLedger(async (seq, prevHash) => {
      const prev = prevHash || GENESIS;
      const hash = await entryHash({ seq, ts, kind, data, prev });
      const { proof } = await this.signer.seal({ hash });
      return { seq, ts, kind, data, prev, hash, sig: proof.sig };
    });
    tx.emit('ledger', { seq: entry.seq, kind, hash: entry.hash });
    return entry;
  }

  // ---------------------------------------------------------------- principals and their keys

  // `evidence` is whatever the admission gate needs, typically an OIDC ID token
  // proving the caller signed in with the organisation's identity provider.
  registerPrincipal(reg, evidence = null) {
    return this.#write(async (tx) => {
      if (reg?.type !== 'PrincipalRegistration' || !isDid(reg.did)) throw new Error('not a principal registration');
      if (!(await verifySealed(reg, reg.did))) throw new Error('registration is not signed by the key it names');
      if (await tx.get('principal', reg.did)) throw new Error('principal is already registered');
      let admittedAs = null;
      if (this.admit) {
        const verdict = await this.admit(reg, evidence);
        if (!verdict?.ok) throw Object.assign(new Error('registration not admitted: ' + (verdict?.reason || 'no reason given')), { status: 403 });
        admittedAs = verdict.subject || null;
      }
      if (reg.recovery && !(Number.isInteger(reg.recovery.k) && reg.recovery.k >= 1 && reg.recovery.of?.length >= reg.recovery.k && reg.recovery.of.every(isDid))) {
        throw new Error('recovery must be { k, of: [identifiers] } with 1 <= k <= of.length');
      }
      const rec = {
        did: reg.did, name: reg.name, kind: reg.kind, registeredAt: this.nowMs(), admittedAs,
        keys: [{ kid: reg.did, role: 'root', addedAt: this.nowMs() }],
        recovery: reg.recovery || null, passkeys: [], frozen: null,
      };
      await tx.put('principal', reg.did, rec);
      await this.#record(tx, 'principal.registered', { did: rec.did, name: rec.name, admittedAs: admittedAs || undefined });
      tx.emit('registry', { kind: 'principal', id: rec.did });
      return rec;
    });
  }

  // Is `obj` validly signed on behalf of `iss`? For principals, any of their current
  // keys with an allowed role counts; for agents, only the agent's own key.
  async #signedBy(tx, obj, iss, roles = ISSUE_ROLES) {
    const kid = obj?.proof?.kid;
    if (!kid) return false;
    const p = await tx.get('principal', iss);
    if (!p) return kid === iss && verifySealed(obj, iss);
    const key = p.keys.find((k) => k.kid === kid);
    if (!key || !roles.includes(key.role)) return false;
    const signedAtMs = (obj.iat ?? 0) * 1000;
    if (key.removedAt && (key.compromised || !obj.iat || signedAtMs >= key.removedAt)) return false;
    if (key.exp && obj.iat && obj.iat > key.exp) return false;
    return verifySealed(obj, kid);
  }

  async #principalKey(tx, iss, kid) {
    const p = await tx.get('principal', iss);
    return p?.keys.find((k) => k.kid === kid) || null;
  }

  // Adds or removes principal keys. Needs one root signature, or k recovery signatures
  // when the root key is lost. `approvals` are sealed copies of the same `update` body.
  updateKeys({ update, approvals }) {
    return this.#write(async (tx) => {
      if (update?.type !== 'KeyUpdate') throw new Error('not a key update');
      const p = await tx.get('principal', update.principal);
      if (!p) throw new Error('principal not found');
      if (Math.abs(this.now() - update.iat) > 600) throw new Error('key update is stale');
      const body = canonical(update);
      const signers = new Set();
      for (const a of approvals || []) {
        const { proof, ...rest } = a;
        if (canonical(rest) !== body) continue;
        if (await verifySealed(a, proof?.kid)) signers.add(proof.kid);
      }
      const activeRoot = p.keys.filter((k) => k.role === 'root' && !k.removedAt).map((k) => k.kid);
      const byRoot = [...signers].some((s) => activeRoot.includes(s));
      const byRecovery = p.recovery ? [...signers].filter((s) => p.recovery.of.includes(s)).length >= p.recovery.k : false;
      if (!byRoot && !byRecovery) throw new Error('key update needs a root key signature or the recovery quorum');
      for (const r of update.remove || []) {
        const k = p.keys.find((x) => x.kid === r.kid && !x.removedAt);
        if (!k) throw new Error('key to remove is not active');
        Object.assign(k, { removedAt: this.nowMs(), compromised: !!r.compromised });
      }
      for (const a of update.add || []) {
        if (!isDid(a.kid) || !['root', 'operational', 'approver'].includes(a.role)) throw new Error('added keys need an identifier and a role of root, operational or approver');
        if (p.keys.some((k) => k.kid === a.kid && !k.removedAt)) throw new Error('key is already active');
        p.keys.push({ kid: a.kid, role: a.role, label: a.label, exp: a.exp, maxAmount: a.maxAmount, addedAt: this.nowMs() });
      }
      if (!p.keys.some((k) => k.role === 'root' && !k.removedAt)) throw new Error('a principal must keep at least one root key');
      await tx.put('principal', p.did, p);
      await this.#record(tx, 'principal.keys', {
        principal: p.did, by: byRoot ? 'root' : 'recovery',
        added: (update.add || []).map((a) => a.role + ':' + shortDid(a.kid)),
        removed: (update.remove || []).map((r) => (r.compromised ? 'compromised:' : '') + shortDid(r.kid)),
      });
      tx.emit('registry', { kind: 'principal', id: p.did });
      return { principal: p.did, keys: p.keys };
    });
  }

  // The kill switch: while frozen, every request from every agent under the principal is refused.
  setFreeze(statement) {
    return this.#write(async (tx) => {
      if (statement?.type !== 'Freeze') throw new Error('not a freeze statement');
      const p = await tx.get('principal', statement.principal);
      if (!p) throw new Error('principal not found');
      if (!(await this.#signedBy(tx, statement, p.did))) throw new Error('freeze must be signed by a root or operational key');
      if (Math.abs(this.now() - statement.iat) > 600) throw new Error('freeze statement is stale');
      p.frozen = statement.frozen ? { at: this.nowMs(), reason: statement.reason || '', by: statement.proof.kid } : null;
      await tx.put('principal', p.did, p);
      let declined = 0;
      if (statement.frozen) {
        for (const ap of await tx.list('approval')) {
          if (ap.status === 'pending' && ap.principal === p.did) { await this.#closeApproval(tx, ap, 'declined', 'all agents frozen'); declined++; }
        }
      }
      await this.#record(tx, statement.frozen ? 'principal.frozen' : 'principal.unfrozen', { principal: p.did, reason: statement.reason || undefined, declined: declined || undefined });
      tx.emit('freeze', { principal: p.did, frozen: !!statement.frozen });
      return { principal: p.did, frozen: !!statement.frozen, declined };
    });
  }

  // A principal binds a passkey to their account. The registration response proves the
  // device created the key for this site; the principal's signature proves who owns it.
  enrollPasskey(enrollment) {
    return this.#write(async (tx) => {
      if (!this.webauthn) throw new Error('passkeys are not configured on this authority');
      if (enrollment?.type !== 'PasskeyEnrollment') throw new Error('not a passkey enrollment');
      const p = await tx.get('principal', enrollment.principal);
      if (!p) throw new Error('principal not found');
      if (!(await this.#signedBy(tx, enrollment, p.did))) throw new Error('enrollment must be signed by a root or operational key');
      const challenge = await enrollmentChallenge(p.did, enrollment.nonce);
      const cred = await verifyRegistration(enrollment.response, { challenge, ...this.webauthn });
      if (p.passkeys.some((k) => k.credentialId === cred.credentialId)) throw new Error('passkey already enrolled');
      p.passkeys.push({ ...cred, label: enrollment.label || 'Passkey', addedAt: this.nowMs() });
      await tx.put('principal', p.did, p);
      await this.#record(tx, 'principal.passkey', { principal: p.did, credential: cred.credentialId.slice(0, 16), label: enrollment.label });
      tx.emit('registry', { kind: 'principal', id: p.did });
      return { credentialId: cred.credentialId, label: enrollment.label };
    });
  }

  // ---------------------------------------------------------------- endorsements

  endorseAttestor(end) {
    return this.#write(async (tx) => {
      if (end?.type !== 'AttestorEndorsement') throw new Error('not an attestor endorsement');
      if (!(await tx.get('principal', end.iss))) throw new Error('endorsing principal is not registered');
      if (!(await this.#signedBy(tx, end, end.iss))) throw new Error('endorsement signature is invalid');
      const rec = (await tx.get('attestor', end.attestor)) || { did: end.attestor, name: end.name, endorsedBy: [] };
      if (!rec.endorsedBy.includes(end.iss)) rec.endorsedBy.push(end.iss);
      await tx.put('attestor', end.attestor, rec);
      await this.#record(tx, 'attestor.endorsed', { attestor: end.attestor, name: end.name, by: end.iss });
      tx.emit('registry', { kind: 'attestor', id: end.attestor });
      return rec;
    });
  }

  // A software publisher whose cosign key may sign container images the principal runs.
  endorsePublisher(end) {
    return this.#write(async (tx) => {
      if (end?.type !== 'PublisherEndorsement' || !end.publicKeyPem) throw new Error('not a publisher endorsement');
      if (!(await tx.get('principal', end.iss))) throw new Error('endorsing principal is not registered');
      if (!(await this.#signedBy(tx, end, end.iss))) throw new Error('endorsement signature is invalid');
      const id = await sha256(end.publicKeyPem.replace(/\s+/g, ''));
      const rec = (await tx.get('publisher', id)) || { id, name: end.name, publicKeyPem: end.publicKeyPem, endorsedBy: [] };
      if (!rec.endorsedBy.includes(end.iss)) rec.endorsedBy.push(end.iss);
      await tx.put('publisher', id, rec);
      await this.#record(tx, 'publisher.endorsed', { publisher: end.name, key: id.slice(0, 16), by: end.iss });
      return rec;
    });
  }

  // ---------------------------------------------------------------- passports and mandates

  registerPassport(pp) {
    return this.#write(async (tx) => {
      if (pp?.type !== 'AgentPassport') throw new Error('not an agent passport');
      const chain = await this.#passportChain(tx, pp);
      if (!chain.ok) throw new Error('passport rejected: ' + chain.reason);
      if (await tx.get('passport', pp.id)) throw new Error('passport rejected: id already used');
      await tx.put('passport', pp.id, pp);
      await tx.put('passportBySub', pp.sub, pp.id);
      // Key rotation: a passport may supersede an older one from the same issuer.
      if (pp.supersedes) {
        const old = await tx.get('passport', pp.supersedes);
        if (old && old.iss === pp.iss && !(await tx.get('revoked', old.id))) {
          await tx.put('revoked', old.id, { target: old.id, reason: `rotated to ${shortDid(pp.sub)}`, by: pp.iss, at: this.nowMs(), rotation: true });
        }
      }
      await this.#record(tx, 'passport.issued', { id: pp.id, agent: pp.sub, name: pp.name, iss: pp.iss, measurement: pp.runtime.measurement, supersedes: pp.supersedes || undefined });
      tx.emit('registry', { kind: 'passport', id: pp.id });
      return { id: pp.id, root: chain.root, depth: chain.chain.length - 1 };
    });
  }

  registerMandate(m) {
    return this.#write(async (tx) => {
      if (m?.type !== 'Mandate') throw new Error('not a mandate');
      const chain = await this.#mandateChain(tx, m);
      if (!chain.ok) throw new Error('mandate rejected: ' + chain.reason);
      const ppId = await tx.get('passportBySub', m.sub);
      if (!ppId) throw new Error('mandate rejected: the receiving agent has no passport');
      const ppRoot = await this.#rootOfPassport(tx, await tx.get('passport', ppId));
      if (ppRoot !== chain.root) throw new Error('mandate rejected: it comes from a different principal than the agent passport');
      await tx.put('mandate', m.id, m);
      await this.#record(tx, 'mandate.issued', { id: m.id, iss: m.iss, sub: m.sub, parent: m.parent, caps: m.caps.map((c) => c.action + ' ' + c.resource) });
      tx.emit('registry', { kind: 'mandate', id: m.id });
      return { id: m.id, depth: chain.chain.length - 1 };
    });
  }

  async #passportChain(tx, pp) {
    const chain = [];
    let cur = pp;
    for (let i = 0; i < MAX_CHAIN; i++) {
      chain.push(cur);
      if (!(await this.#signedBy(tx, cur, cur.iss))) return fail(`passport ${cur.id} signature is invalid or its signing key was withdrawn`);
      if (cur.exp < this.now()) return fail(`passport ${cur.id} expired`);
      if (await tx.get('principal', cur.iss)) {
        if (cur.parent) return fail('a root passport must not name a parent');
        return { ok: true, chain, root: cur.iss };
      }
      const parent = await tx.get('passport', cur.parent);
      if (!parent) return fail('issuer is neither a registered principal nor an agent with a known passport');
      if (parent.sub !== cur.iss) return fail('parent passport does not belong to the issuer');
      if (parent.depth < 1) return fail(`${parent.name} is not allowed to create sub-agents`);
      if (cur.depth > parent.depth - 1) return fail('asks for more sub-agent depth than its issuer has');
      if (cur.exp > parent.exp) return fail('outlives the passport of its issuer');
      cur = parent;
    }
    return fail('passport chain is too deep');
  }

  async #mandateChain(tx, m) {
    const chain = [];
    let cur = m;
    const now = this.now();
    for (let i = 0; i < MAX_CHAIN; i++) {
      chain.push(cur);
      if (!(await this.#signedBy(tx, cur, cur.iss))) return fail(`mandate ${cur.id} signature is invalid or its signing key was withdrawn`);
      if (cur.exp < now) return fail(`mandate ${cur.id} expired`);
      if (cur.nbf > now + 30) return fail(`mandate ${cur.id} is not valid yet`);
      if (!cur.parent) {
        if (!(await tx.get('principal', cur.iss))) return fail('a root mandate must be issued by a registered principal');
        return { ok: true, chain, root: cur.iss };
      }
      const parent = await tx.get('mandate', cur.parent);
      if (!parent) return fail('parent mandate is unknown');
      if (parent.sub !== cur.iss) return fail('issuer does not hold the parent mandate');
      if (parent.depth < 1) return fail('parent mandate does not allow delegation');
      if (cur.depth > parent.depth - 1) return fail('asks for more delegation depth than the parent allows');
      if (cur.exp > parent.exp) return fail('outlives its parent mandate');
      const widened = capsWithin(cur.caps, parent.caps);
      if (widened.length) return fail('widens scope beyond the parent: ' + widened[0]);
      if (parent.budget && (!cur.budget || cur.budget.currency !== parent.budget.currency || cur.budget.amount > parent.budget.amount)) {
        return fail(`budget must be at most ${parent.budget.amount} ${parent.budget.currency}`);
      }
      cur = parent;
    }
    return fail('mandate chain is too deep');
  }

  // Ancestry walks over already-verified records, for status and cascade.
  async #ancestry(tx, kind, rec) {
    const out = [];
    for (let cur = rec, i = 0; cur && i < MAX_CHAIN; i++) {
      out.push(cur);
      cur = cur.parent ? await tx.get(kind, cur.parent) : null;
    }
    return out;
  }

  async #rootOfPassport(tx, pp) {
    const a = await this.#ancestry(tx, 'passport', pp);
    return a[a.length - 1]?.iss;
  }

  // A record is dead if it, its subject, or the key that signed it was revoked.
  async #revokedHit(tx, records) {
    for (const r of records) {
      const hit = (await tx.get('revoked', r.id)) || (await tx.get('revoked', r.sub)) || (r.proof?.kid && r.proof.kid !== r.iss ? await tx.get('revoked', r.proof.kid) : null);
      if (hit) return { record: r, revocation: hit };
    }
    return null;
  }

  // ---------------------------------------------------------------- verification

  verifyIntent(intent) {
    return this.#write((tx) => this.#verify(tx, intent));
  }

  async #verify(tx, intent) {
    const trace = CHECKS.map(([key, label]) => ({ key, label, status: 'skipped', detail: '' }));
    const mark = (key, status, detail) => Object.assign(trace.find((t) => t.key === key), { status, detail });
    const ctx = { intent, trace, risk: null, passport: null, mandates: [] };
    const deny = (key, detail) => { mark(key, 'fail', detail); return this.#finish(tx, ctx, 'deny', key); };
    const now = this.now();

    // 1. Proof of key: the agent signed this exact request.
    if (intent?.type !== 'Intent' || !isDid(intent.agent)) return deny('signature', 'not a well-formed intent');
    if (!(await verifySealed(intent, intent.agent))) return deny('signature', 'signature does not match the agent key it claims');
    mark('signature', 'pass', `signed by ${shortDid(intent.agent)}`);

    // 2. Freshness: short-lived and single-use, enforced by the store across processes.
    if (intent.iat > now + 30) return deny('freshness', 'issued in the future');
    if (intent.exp < now) return deny('freshness', `expired ${now - intent.exp}s ago`);
    if (intent.exp - intent.iat > 300) return deny('freshness', 'lifetime is longer than 5 minutes');
    if (!(await tx.claimNonce(intent.nonce, intent.exp, now))) return deny('freshness', 'this exact request was already used; replay blocked');
    mark('freshness', 'pass', `single-use nonce, expires in ${intent.exp - now}s`);

    // 3. Identity: a passport that chains to a principal, not revoked, principal not frozen.
    const pp = await tx.get('passport', intent.passport);
    if (!pp) return deny('identity', 'no passport on file for this agent');
    if (pp.sub !== intent.agent) return deny('identity', 'the passport belongs to a different agent');
    const pchain = await this.#passportChain(tx, pp);
    if (!pchain.ok) return deny('identity', pchain.reason);
    const pRevoked = await this.#revokedHit(tx, pchain.chain);
    if (pRevoked) return deny('identity', `${pRevoked.record.name || pRevoked.record.id} was revoked: ${pRevoked.revocation.reason || 'no reason given'}`);
    const principal = await tx.get('principal', pchain.root);
    if (principal.frozen) return deny('identity', `${principal.name} froze all agents${principal.frozen.reason ? ': ' + principal.frozen.reason : ''}`);
    ctx.passport = pp;
    ctx.root = pchain.root;
    mark('identity', 'pass', `${pp.name}, vouched for by ${principal.name}` + (pchain.chain.length > 1 ? ` via ${pchain.chain.length - 1} parent agent(s)` : ''));

    // 4. Proof of runtime: evidence that the running code is the passported code.
    const att = intent.attestation;
    if (!att) return deny('runtime', 'no runtime attestation attached');
    const verifier = this.verifiers[att.format || 'agentid-host'];
    if (!verifier) return deny('runtime', `attestation format ${att.format} is not supported here`);
    const rt = await verifier(att, { passport: pp, agent: intent.agent, root: pchain.root, tx, now, nowMs: this.nowMs() });
    if (!rt.ok) return deny('runtime', rt.reason);
    mark('runtime', 'pass', rt.detail);

    // 5. Mandate: a chain of grants, each narrower than the one above it.
    const m = await tx.get('mandate', intent.mandate);
    if (!m) return deny('mandate', 'no mandate on file for this request');
    if (m.sub !== intent.agent) return deny('mandate', 'the mandate was granted to a different agent');
    const mchain = await this.#mandateChain(tx, m);
    if (!mchain.ok) return deny('mandate', mchain.reason);
    if (mchain.root !== pchain.root) return deny('mandate', 'mandate and passport come from different principals');
    const mRevoked = await this.#revokedHit(tx, mchain.chain);
    if (mRevoked) return deny('mandate', `${mRevoked.record.label || mRevoked.record.id} was revoked: ${mRevoked.revocation.reason || 'no reason given'}`);
    ctx.mandates = mchain.chain;
    mark('mandate', 'pass', mchain.chain.length > 1 ? `${mchain.chain.length} links, each narrower than the last` : `granted directly by ${principal.name}`);

    // 6–7. Scope and limits must hold at every link, not just the leaf.
    let scopeCap = null;
    for (const [i, mm] of mchain.chain.entries()) {
      const r = authorize(mm.caps, intent.action, intent.resource, intent.params || {});
      const where = i === 0 ? '' : ` (at delegation level ${mchain.chain.length - 1 - i})`;
      if (!r.ok && r.stage === 'scope') return deny('scope', r.reason + where);
      if (!r.ok) { mark('scope', 'pass', `${intent.action} on ${intent.resource}`); return deny('limits', r.reason + where); }
      scopeCap ??= r.cap;
    }
    mark('scope', 'pass', `${scopeCap.action} on ${scopeCap.resource}`);
    mark('limits', 'pass', Object.keys(scopeCap.limits || {}).length ? `within ${Object.keys(scopeCap.limits).join(', ')} limits` : 'no limits on this capability');

    // 8. Budget and rate, counted cumulatively across every sub-agent below a mandate.
    const amount = typeof intent.params?.amount === 'number' ? intent.params.amount : 0;
    for (const mm of mchain.chain) {
      const sp = await this.#spend(tx, mm.id);
      if (mm.budget && amount) {
        if (intent.params.currency && intent.params.currency !== mm.budget.currency) return deny('budget', `budget is in ${mm.budget.currency}`);
        if (sp.spent + sp.reserved + amount > mm.budget.amount) {
          return deny('budget', `would reach ${fmt(sp.spent + sp.reserved + amount)} of a ${fmt(mm.budget.amount)} ${mm.budget.currency} budget`);
        }
      }
      if (mm.rate) {
        const recent = sp.events.filter((t) => t > this.nowMs() - mm.rate.windowSec * 1000);
        if (recent.length >= mm.rate.max) return deny('budget', `rate limit of ${mm.rate.max} per ${mm.rate.windowSec}s reached`);
      }
    }
    const leafSpend = await this.#spend(tx, m.id);
    mark('budget', 'pass', m.budget ? `${fmt(leafSpend.spent + amount)} of ${fmt(m.budget.amount)} ${m.budget.currency} after this` : 'no budget on this mandate');

    // 9. Behavior: explainable signals, not a black box.
    ctx.risk = await this.#assessRisk(tx, intent, m, amount);
    mark('risk', ctx.risk.score >= RISK_STEP_UP ? 'warn' : 'pass', `score ${ctx.risk.score}` + (ctx.risk.factors.length ? ': ' + ctx.risk.factors.map((f) => f.label).join('; ') : ''));

    // 10. Co-sign: the agent-native second factor. A person or a guardian quorum signs.
    const reasons = [];
    let quorum = null;
    let passkey = false;
    for (const mm of mchain.chain) {
      if (mm.cosign?.above !== undefined && amount > mm.cosign.above) reasons.push(`amount above ${fmt(mm.cosign.above)}`);
      if (mm.cosign?.actions?.some((p) => globMatch(p, intent.action))) reasons.push(`${intent.action} always needs a co-sign`);
      if (mm.cosign?.quorum && !quorum) quorum = mm.cosign.quorum;
      if (mm.cosign?.passkey) passkey = true;
    }
    if (ctx.risk.score >= RISK_STEP_UP) reasons.push(`risk score ${ctx.risk.score}`);
    if (reasons.length) {
      const unique = [...new Set(reasons)];
      mark('cosign', 'hold', unique.join('; '));
      return this.#hold(tx, ctx, unique, quorum, passkey, amount);
    }
    mark('cosign', 'pass', 'not required for this request');
    return this.#finish(tx, ctx, 'allow');
  }

  async #spend(tx, id) {
    return (await tx.get('spend', id)) || { spent: 0, reserved: 0, events: [] };
  }

  async #assessRisk(tx, intent, mandate, amount) {
    const prof = (await tx.get('profile', intent.agent)) || emptyProfile();
    const factors = [];
    const add = (points, label) => factors.push({ points, label });
    const nowMs = this.nowMs();
    if (!prof.actions.length) add(5, 'no behavioral history yet');
    else if (!prof.actions.includes(intent.action)) add(15, `first use of ${intent.action}`);
    if (prof.resources.length && !prof.resources.includes(intent.resource)) add(10, `first contact with ${intent.resource}`);
    const burst = prof.recent.filter((t) => nowMs - t < 10_000).length;
    if (burst >= 5) add(20, `${burst + 1} actions within 10 seconds`);
    if (amount && prof.amounts.length >= 3) {
      const med = median(prof.amounts);
      if (med > 0 && amount > 2.5 * med) add(20, `amount is ${(amount / med).toFixed(1)}× this agent's typical`);
    }
    if (INJECTION.test(intent.reason || '')) add(50, 'justification contains instruction-override language');
    if (!(intent.reason || '').trim()) add(10, 'no justification given');
    if (mandate.budget && amount) {
      const sp = await this.#spend(tx, mandate.id);
      if ((sp.spent + sp.reserved + amount) / mandate.budget.amount > 0.8) add(10, 'pushes budget use past 80%');
    }
    return { score: Math.min(100, factors.reduce((a, f) => a + f.points, 0)), factors };
  }

  async #hold(tx, ctx, reasons, quorum, passkey, amount) {
    const { intent } = ctx;
    for (const mm of ctx.mandates) {
      const sp = await this.#spend(tx, mm.id);
      sp.reserved += amount;
      await tx.put('spend', mm.id, sp);
    }
    const approval = {
      id: randomId('ap'), status: 'pending',
      intent, intentHash: await hashObject(intent),
      agent: intent.agent, agentName: ctx.passport.name,
      action: intent.action, resource: intent.resource, params: intent.params, reason: intent.reason,
      reasons, risk: ctx.risk, trace: ctx.trace,
      principal: ctx.root, quorum, passkey, signatures: [],
      mandates: ctx.mandates.map((m) => m.id), amount,
      createdAt: this.nowMs(), expiresAt: this.nowMs() + APPROVAL_TTL_MS,
    };
    await tx.put('approval', approval.id, approval);
    return this.#finish(tx, ctx, 'step_up', 'cosign', approval);
  }

  async #finish(tx, ctx, decision, failedAt = null, approval = null) {
    const { intent, trace, risk } = ctx;
    const intentHash = intent ? await hashObject(intent) : null;
    const amount = typeof intent?.params?.amount === 'number' ? intent.params.amount : 0;
    if (decision === 'allow') {
      for (const mm of ctx.mandates) {
        const sp = await this.#spend(tx, mm.id);
        sp.spent += amount;
        sp.events = [...sp.events.filter((t) => this.nowMs() - t < 86_400_000), this.nowMs()];
        await tx.put('spend', mm.id, sp);
      }
    }
    if (ctx.passport) {
      const prof = (await tx.get('profile', intent.agent)) || emptyProfile();
      prof.recent = [...prof.recent.filter((t) => this.nowMs() - t < 60_000), this.nowMs()];
      if (decision === 'allow') {
        if (!prof.actions.includes(intent.action)) prof.actions.push(intent.action);
        if (!prof.resources.includes(intent.resource)) prof.resources = [...prof.resources, intent.resource].slice(-500);
        if (amount) prof.amounts = [...prof.amounts, amount].slice(-50);
      }
      await tx.put('profile', intent.agent, prof);
    }
    const result = {
      id: randomId('dc'), ts: this.nowMs(), decision, failedAt,
      intentId: intent?.id, intentHash,
      agent: intent?.agent, agentName: ctx.passport?.name || (await this.#nameOf(tx, intent?.agent)),
      action: intent?.action, resource: intent?.resource, params: intent?.params, reason: intent?.reason,
      checks: trace, risk, approvalId: approval?.id ?? null, via: ctx.via ?? null,
    };
    const entry = await this.#record(tx, 'intent.' + decision, {
      decision: result.id, intent: intentHash, agent: result.agent, action: result.action, resource: result.resource,
      amount: amount || undefined, failedAt: failedAt || undefined, via: ctx.via || undefined,
    });
    result.ledgerSeq = entry.seq;
    if (decision === 'allow') {
      result.receipt = await this.signer.seal({
        type: 'Receipt', v: 1, authority: this.did, intent: intent.id, intentHash, agent: intent.agent, principal: ctx.root ?? approval?.principal,
        action: intent.action, resource: intent.resource, params: intent.params, aud: intent.aud,
        cosigners: ctx.cosigners || [], ledgerSeq: entry.seq, iat: this.now(),
      });
    }
    const stats = await tx.getMeta('stats', { allowed: 0, denied: 0, stepUp: 0 });
    stats[decision === 'allow' ? 'allowed' : decision === 'deny' ? 'denied' : 'stepUp']++;
    await tx.putMeta('stats', stats);
    const feed = await tx.getMeta('decisions', []);
    await tx.putMeta('decisions', [...feed, stripForFeed(result)].slice(-150));
    tx.emit('decision', result);
    if (approval) tx.emit('approval', { id: approval.id, status: 'pending' });
    return result;
  }

  async #nameOf(tx, did) {
    if (!did) return 'unknown';
    const id = await tx.get('passportBySub', did);
    const pp = id ? await tx.get('passport', id) : null;
    return pp?.name || shortDid(did);
  }

  // ---------------------------------------------------------------- co-sign

  // Accepts a CoSign signed by a principal key (root, operational or approver) or by a
  // guardian, or a PasskeyCoSign produced by navigator.credentials.get().
  resolveApproval(cosign) {
    return this.#write(async (tx) => {
      const ap = await tx.get('approval', cosign?.approval);
      if (!ap) throw new Error('approval not found');
      if (ap.status === 'pending' && ap.expiresAt < this.nowMs()) await this.#expire(tx, ap);
      if (ap.status !== 'pending') throw new Error(`approval is already ${ap.status}`);
      if (!['approve', 'decline'].includes(cosign.decision)) throw new Error('decision must be approve or decline');

      let signer;
      let viaPasskey = false;
      if (cosign.type === 'PasskeyCoSign') {
        if (!this.webauthn) throw new Error('passkeys are not configured on this authority');
        if (cosign.principal !== ap.principal) throw new Error('passkey belongs to a different principal');
        const p = await tx.get('principal', ap.principal);
        const cred = p.passkeys.find((k) => k.credentialId === cosign.credentialId);
        if (!cred) throw new Error('passkey is not enrolled for this principal');
        const challenge = await approvalChallenge({ approval: ap.id, intentHash: ap.intentHash, decision: cosign.decision });
        const { signCount } = await verifyAssertion(cosign, cred, { challenge, ...this.webauthn });
        cred.signCount = signCount;
        await tx.put('principal', p.did, p);
        signer = ap.principal;
        viaPasskey = true;
      } else if (cosign.type === 'CoSign') {
        if (cosign.intentHash !== ap.intentHash || cosign.approval !== ap.id) throw new Error('co-sign is for a different request');
        const isGuardian = ap.quorum?.of?.includes(cosign.iss);
        if (cosign.iss === ap.principal) {
          if (!(await this.#signedBy(tx, cosign, ap.principal, COSIGN_ROLES))) throw new Error('co-sign signature is invalid or the key may not approve');
          const key = await this.#principalKey(tx, ap.principal, cosign.proof.kid);
          if (key.role === 'approver' && key.maxAmount !== undefined && ap.amount > key.maxAmount) throw new Error(`this approver key may approve up to ${fmt(key.maxAmount)} only`);
          if (ap.passkey && cosign.decision === 'approve') throw new Error('this mandate requires a passkey approval');
        } else if (isGuardian) {
          if (!(await verifySealed(cosign, cosign.iss))) throw new Error('co-sign signature is invalid');
        } else {
          throw new Error('signer is not allowed to approve this request');
        }
        signer = cosign.iss;
      } else {
        throw new Error('not a co-sign');
      }

      if (ap.signatures.some((s) => s.iss === signer)) throw new Error('signer already responded');
      ap.signatures.push({ iss: signer, decision: cosign.decision, at: this.nowMs(), passkey: viaPasskey || undefined, kid: cosign.proof?.kid });
      const isPrincipal = signer === ap.principal;
      const guardianApprovals = ap.signatures.filter((s) => s.decision === 'approve' && ap.quorum?.of?.includes(s.iss)).length;
      const principalRec = await tx.get('principal', ap.principal);

      if (cosign.decision === 'decline' && (isPrincipal || !ap.quorum)) return this.#closeApproval(tx, ap, 'declined', `declined by ${isPrincipal ? principalRec.name : shortDid(signer)}`);
      if (cosign.decision === 'decline' && ap.quorum && ap.quorum.of.length - ap.signatures.filter((s) => s.decision === 'decline').length < ap.quorum.k) {
        return this.#closeApproval(tx, ap, 'declined', 'guardian quorum can no longer be reached');
      }
      const approved = (isPrincipal && cosign.decision === 'approve') || (ap.quorum && guardianApprovals >= ap.quorum.k);
      if (!approved) {
        await tx.put('approval', ap.id, ap);
        tx.emit('approval', { id: ap.id, status: 'pending' });
        return { id: ap.id, status: 'pending', signatures: ap.signatures.length };
      }

      // Re-check: the world may have changed while the request waited.
      if (principalRec.frozen) return this.#closeApproval(tx, ap, 'declined', 'all agents were frozen while waiting');
      const ppId = await tx.get('passportBySub', ap.agent);
      const pp = ppId ? await tx.get('passport', ppId) : null;
      const mandates = await Promise.all(ap.mandates.map((id) => tx.get('mandate', id)));
      const hit = (pp && (await this.#revokedHit(tx, await this.#ancestry(tx, 'passport', pp)))) || (await this.#revokedHit(tx, mandates.filter(Boolean)));
      if (hit) return this.#closeApproval(tx, ap, 'declined', 'revoked while waiting for co-sign');
      return this.#closeApproval(tx, ap, 'approved');
    });
  }

  async #releaseReserve(tx, ap) {
    for (const id of ap.mandates) {
      const sp = await this.#spend(tx, id);
      sp.reserved = Math.max(0, sp.reserved - ap.amount);
      await tx.put('spend', id, sp);
    }
  }

  async #expire(tx, ap) {
    ap.status = 'expired';
    ap.closedAt = this.nowMs();
    await this.#releaseReserve(tx, ap);
    await tx.put('approval', ap.id, ap);
  }

  async #closeApproval(tx, ap, status, note = '') {
    ap.status = status;
    ap.closedAt = this.nowMs();
    ap.note = note;
    await this.#releaseReserve(tx, ap);
    const approvers = ap.signatures.filter((s) => s.decision === 'approve');
    const names = [];
    for (const s of approvers) {
      const p = await tx.get('principal', s.iss);
      names.push((p ? p.name : await this.#nameOf(tx, s.iss)) + (s.passkey ? ' (passkey)' : ''));
    }
    const trace = ap.trace.map((t) => (t.key === 'cosign'
      ? { ...t, status: status === 'approved' ? 'pass' : 'fail', detail: status === 'approved' ? `co-signed by ${names.join(', ')}` : note }
      : t));
    const ppId = await tx.get('passportBySub', ap.agent);
    const ctx = {
      intent: ap.intent, trace, risk: ap.risk, passport: ppId ? await tx.get('passport', ppId) : null, root: ap.principal,
      mandates: (await Promise.all(ap.mandates.map((id) => tx.get('mandate', id)))).filter(Boolean),
      via: 'cosign', cosigners: approvers.map((s) => s.iss),
    };
    const result = await this.#finish(tx, ctx, status === 'approved' ? 'allow' : 'deny', status === 'approved' ? null : 'cosign');
    ap.result = result.id;
    ap.receipt = result.receipt ?? null;
    await tx.put('approval', ap.id, ap);
    tx.emit('approval', { id: ap.id, status });
    return { id: ap.id, status, decision: result };
  }

  async approval(id) {
    const ap = await this.store.read((tx) => tx.get('approval', id));
    if (ap?.status === 'pending' && ap.expiresAt < this.nowMs()) return { ...ap, status: 'expired' };
    return ap;
  }

  // ---------------------------------------------------------------- revocation

  revoke(rev) {
    return this.#write(async (tx) => {
      if (rev?.type !== 'Revocation') throw new Error('not a revocation');
      const { target } = rev;
      let issuers = [];
      const ppId = (await tx.get('passport', target)) ? target : await tx.get('passportBySub', target);
      const pp = ppId ? await tx.get('passport', ppId) : null;
      const md = await tx.get('mandate', target);
      if (pp) issuers = (await this.#ancestry(tx, 'passport', pp)).map((p) => p.iss);
      else if (md) issuers = (await this.#ancestry(tx, 'mandate', md)).map((m) => m.iss);
      else throw new Error('nothing to revoke with that id');
      const selfRevocation = rev.iss === target && (await verifySealed(rev, target));
      if (!selfRevocation) {
        if (!issuers.includes(rev.iss)) throw new Error('only an issuer up the chain can revoke this');
        if (!(await this.#signedBy(tx, rev, rev.iss))) throw new Error('revocation signature is invalid');
      }
      await tx.put('revoked', target, { target, reason: rev.reason, by: rev.iss, at: this.nowMs() });

      const affected = await this.#affectedBy(tx, target);
      for (const ap of await tx.list('approval')) {
        if (ap.status === 'pending' && affected.agents.includes(ap.agent)) await this.#closeApproval(tx, ap, 'declined', 'revoked while waiting for co-sign');
      }
      await this.#record(tx, 'revoked', { target, by: rev.iss, reason: rev.reason, agents: affected.agents.length, mandates: affected.mandates.length });
      tx.emit('revoked', { target, ...affected });
      return { target, ...affected };
    });
  }

  async #affectedBy(tx, target) {
    const agents = [];
    const mandates = [];
    for (const pp of await tx.list('passport')) {
      if ((await this.#ancestry(tx, 'passport', pp)).some((p) => p.id === target || p.sub === target)) agents.push(pp.sub);
    }
    for (const m of await tx.list('mandate')) {
      if ((await this.#ancestry(tx, 'mandate', m)).some((x) => x.id === target || x.sub === target || agents.includes(x.sub))) mandates.push(m.id);
    }
    return { agents, mandates };
  }

  // ---------------------------------------------------------------- transparency

  // A signed statement of the log's size, Merkle root and chain head. Witnesses co-sign
  // checkpoints only if each one extends the last, so history cannot be rewritten quietly.
  async checkpoint() {
    return this.store.read(async (tx) => {
      const size = await tx.ledgerHeight();
      const leaves = await tx.ledgerHashes(0, size);
      const root = await this.merkle.root(leaves);
      return this.signer.seal({ type: 'Checkpoint', v: 1, authority: this.did, size, root, head: leaves[size - 1] || GENESIS, ts: this.nowMs() });
    });
  }

  async inclusionProof(seq, size) {
    return this.store.read(async (tx) => {
      const height = await tx.ledgerHeight();
      const n = size ?? height;
      if (n > height) throw new Error('tree size is larger than the log');
      const leaves = await tx.ledgerHashes(0, n);
      return { seq, size: n, leaf: leaves[seq], root: await this.merkle.root(leaves), proof: await this.merkle.inclusionProof(leaves, seq, n) };
    });
  }

  async consistencyProof(first, second) {
    return this.store.read(async (tx) => {
      const height = await tx.ledgerHeight();
      const n = second ?? height;
      if (n > height) throw new Error('tree size is larger than the log');
      const leaves = await tx.ledgerHashes(0, n);
      return { first, second: n, proof: await this.merkle.consistencyProof(leaves, first, n) };
    });
  }

  // Stores a witness's co-signature on one of our checkpoints.
  recordWitness(cosigned) {
    return this.#write(async (tx) => {
      if (cosigned?.type !== 'WitnessCosignature' || cosigned.checkpoint?.authority !== this.did) throw new Error('not a witness co-signature for this authority');
      if (!(await verifySealed(cosigned.checkpoint, this.did))) throw new Error('checkpoint was not signed by this authority');
      if (!(await verifySealed(cosigned, cosigned.witness))) throw new Error('witness signature is invalid');
      const list = await tx.getMeta('witnessed', []);
      await tx.putMeta('witnessed', [...list.filter((w) => w.witness !== cosigned.witness), { witness: cosigned.witness, name: cosigned.name, size: cosigned.checkpoint.size, root: cosigned.checkpoint.root, at: this.nowMs() }]);
      tx.emit('witness', { witness: cosigned.witness, size: cosigned.checkpoint.size });
      return { ok: true };
    });
  }

  // ---------------------------------------------------------------- federation

  trustBundle({ name = 'AgentID authority', endpoints = {}, ttlSec = 30 * 86400 } = {}) {
    return this.signer.seal({ type: 'TrustBundle', v: 1, authority: this.did, name, endpoints, iat: this.now(), exp: this.now() + ttlSec });
  }

  // A principal agrees to accept receipts from a partner authority for some actions.
  federate(agreement) {
    return this.#write(async (tx) => {
      if (agreement?.type !== 'Federation') throw new Error('not a federation agreement');
      if (!(await tx.get('principal', agreement.principal))) throw new Error('principal not found');
      if (!(await this.#signedBy(tx, agreement, agreement.principal, ['root']))) throw new Error('federation must be signed by a root key');
      const b = await verifyTrustBundle(agreement.bundle, this.now());
      if (!b.ok) throw new Error(b.reason);
      if (!agreement.actions?.length) throw new Error('name the actions the partner is trusted for');
      const rec = { authority: agreement.bundle.authority, name: agreement.bundle.name, actions: agreement.actions, audiences: agreement.audiences, principal: agreement.principal, at: this.nowMs() };
      await tx.put('federation', rec.authority, rec);
      await this.#record(tx, 'federation.added', { partner: rec.name, authority: rec.authority, actions: rec.actions, by: agreement.principal });
      tx.emit('registry', { kind: 'federation', id: rec.authority });
      return rec;
    });
  }

  // Checks a partner's receipt against our federation agreements and logs the outcome.
  acceptForeignReceipt(receipt, { aud } = {}) {
    return this.#write(async (tx) => {
      const trusted = await tx.list('federation');
      const r = await verifyFederatedReceipt(receipt, trusted, { aud, nowSec: this.now() });
      await this.#record(tx, r.ok ? 'federated.accepted' : 'federated.rejected', { from: receipt?.authority, action: receipt?.action, resource: receipt?.resource, reason: r.ok ? undefined : r.reason });
      tx.emit('federation', { ok: r.ok, from: r.via || receipt?.authority, action: receipt?.action, reason: r.reason });
      return r;
    });
  }

  // ---------------------------------------------------------------- reads

  async #statusOf(tx, kind, rec) {
    const chain = await this.#ancestry(tx, kind, rec);
    if (await this.#revokedHit(tx, chain)) return 'revoked';
    if (chain.some((r) => r.exp < this.now())) return 'expired';
    if (chain[0]) {
      const root = kind === 'passport' ? chain[chain.length - 1].iss : chain[chain.length - 1].iss;
      const p = await tx.get('principal', root);
      if (p?.frozen) return 'frozen';
    }
    return 'active';
  }

  async snapshot() {
    // Expire stale approvals first, in a transaction, so budgets release correctly.
    await this.#write(async (tx) => {
      for (const ap of await tx.list('approval')) if (ap.status === 'pending' && ap.expiresAt < this.nowMs()) await this.#expire(tx, ap);
    });
    return this.store.read(async (tx) => {
      const passports = [];
      for (const p of await tx.list('passport')) {
        passports.push({ ...p, status: await this.#statusOf(tx, 'passport', p), root: await this.#rootOfPassport(tx, p), profile: await tx.get('profile', p.sub) });
      }
      const mandates = [];
      for (const m of await tx.list('mandate')) {
        const sp = await this.#spend(tx, m.id);
        mandates.push({ ...m, status: await this.#statusOf(tx, 'mandate', m), spent: sp.spent, reserved: sp.reserved });
      }
      const height = await tx.ledgerHeight();
      const head = height ? (await tx.ledgerSlice(height - 1, 1))[0].hash : GENESIS;
      return {
        authority: { did: this.did, passkeys: !!this.webauthn, formats: Object.keys(this.verifiers) },
        principals: (await tx.list('principal')).map(({ passkeys, ...p }) => ({ ...p, passkeys: passkeys.map(({ jwk, ...k }) => k) })),
        attestors: await tx.list('attestor'),
        publishers: (await tx.list('publisher')).map(({ publicKeyPem, ...p }) => p),
        passports,
        mandates,
        revoked: await tx.list('revoked'),
        federation: await tx.list('federation'),
        approvals: (await tx.list('approval')).sort((a, b) => b.createdAt - a.createdAt).slice(0, 40),
        decisions: (await tx.getMeta('decisions', [])).slice(-80),
        stats: await tx.getMeta('stats', { allowed: 0, denied: 0, stepUp: 0 }),
        ledger: { height, head, witnessed: await tx.getMeta('witnessed', []) },
      };
    });
  }

  async decision(id) {
    return this.store.read(async (tx) => (await tx.getMeta('decisions', [])).find((d) => d.id === id) || null);
  }

  async principal(did) {
    return this.store.read((tx) => tx.get('principal', did));
  }

  async ledgerEntries({ from = 0, limit = 200 } = {}) {
    return this.store.read((tx) => tx.ledgerSlice(from, limit));
  }

  async verifyLedger() {
    const entries = await this.store.read(async (tx) => tx.ledgerSlice(0, await tx.ledgerHeight()));
    return verifyChain(entries, this.did);
  }
}

export async function enrollmentChallenge(principal, nonce) {
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(canonical({ principal, nonce, purpose: 'agentid-enroll' })))));
}

// A relying service checks a receipt offline with nothing but the authority identifier.
// Pass `trust` (see federation.js) to also accept receipts from federated authorities.
export async function verifyReceipt(receipt, authorityDid, { aud, maxAgeSec = 120 } = {}) {
  if (receipt?.type !== 'Receipt') return fail('not a receipt');
  if (!(await verifySealed(receipt, authorityDid))) return fail('receipt is not signed by the authority');
  if (aud && receipt.aud !== aud && receipt.aud !== 'any') return fail('receipt is for a different service');
  if (receipt.authority && receipt.authority !== authorityDid) return fail('receipt names a different authority');
  const age = Math.floor(Date.now() / 1000) - receipt.iat;
  if (age > maxAgeSec) return fail('receipt is too old');
  if (age < -30) return fail('receipt is dated in the future');
  return { ok: true, receipt };
}

// Checks a witness co-signature chain: does checkpoint `next` extend `prev`?
export async function checkpointExtends(prev, next, proof) {
  if (!prev) return true;
  if (next.size < prev.size) return false;
  return verifyConsistency(prev.size, next.size, prev.root, next.root, proof);
}

function stripForFeed(r) {
  const { receipt, ...rest } = r;
  return rest;
}

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

function fmt(n) {
  return Number(n).toLocaleString('en-US', { maximumFractionDigits: 2 });
}
