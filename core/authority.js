// The AgentID authority: registry, verifier, co-sign desk, revocation list and ledger.
//
// It holds exactly one private key, its own, used to sign receipts and ledger entries.
// Principals and agents keep their keys; the authority only ever sees signatures.

import { Signer, verifySealed, isDid, shortDid } from './keys.js';
import { hashObject, randomId } from './encoding.js';
import { Ledger, verifyChain } from './ledger.js';
import { authorize, capsWithin, globMatch } from './policy.js';

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
const INJECTION = /(ignore (all |any )?(previous|prior|above|earlier) instructions|disregard (your|the|all) (rules|instructions|policy)|reveal (your|the) system prompt|you are now (in )?|exfiltrat|developer mode|send (all|every) (the )?(data|records|credentials|keys))/i;

const fail = (reason) => ({ ok: false, reason });
const emptyState = () => ({
  principals: {}, attestors: {}, passports: {}, passportBySub: {}, mandates: {},
  revoked: {}, nonces: {}, spend: {}, approvals: {}, profiles: {}, decisions: [],
  stats: { allowed: 0, denied: 0, stepUp: 0 },
});

export class Authority {
  constructor(signer, { state, ledgerEntries, clock } = {}) {
    this.signer = signer;
    this.clock = clock || (() => Date.now());
    this.s = state || emptyState();
    this.ledger = new Ledger(signer, ledgerEntries || []);
    this.listeners = new Set();
    this.queue = Promise.resolve();
  }

  static async create(opts = {}) {
    return new Authority(await Signer.generate(), opts);
  }

  static async restore({ jwk, state, ledger }, opts = {}) {
    return new Authority(await Signer.fromJwk(jwk), { ...opts, state, ledgerEntries: ledger });
  }

  export() {
    return { jwk: this.signer.export(), state: this.s, ledger: this.ledger.entries };
  }

  get did() { return this.signer.did; }
  nowMs() { return this.clock(); }
  now() { return Math.floor(this.clock() / 1000); }

  on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  emit(type, data) { for (const fn of this.listeners) { try { fn({ type, data }); } catch { /* listener errors stay local */ } } }

  // Writes run one at a time so budget and nonce checks cannot race.
  serial(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  async record(kind, data) {
    const entry = await this.ledger.append(kind, data, this.nowMs());
    this.emit('ledger', { seq: entry.seq, kind, hash: entry.hash });
    return entry;
  }

  // ---------------------------------------------------------------- registry

  registerPrincipal(reg) {
    return this.serial(async () => {
      if (reg?.type !== 'PrincipalRegistration' || !isDid(reg.did)) throw new Error('not a principal registration');
      if (!(await verifySealed(reg, reg.did))) throw new Error('registration is not signed by the key it names');
      const rec = { did: reg.did, name: reg.name, kind: reg.kind, registeredAt: this.nowMs() };
      this.s.principals[reg.did] = rec;
      await this.record('principal.registered', { did: rec.did, name: rec.name });
      this.emit('registry', { kind: 'principal', id: rec.did });
      return rec;
    });
  }

  endorseAttestor(end) {
    return this.serial(async () => {
      if (end?.type !== 'AttestorEndorsement') throw new Error('not an attestor endorsement');
      if (!this.s.principals[end.iss]) throw new Error('endorsing principal is not registered');
      if (!(await verifySealed(end, end.iss))) throw new Error('endorsement signature is invalid');
      const rec = this.s.attestors[end.attestor] || { did: end.attestor, name: end.name, endorsedBy: [] };
      if (!rec.endorsedBy.includes(end.iss)) rec.endorsedBy.push(end.iss);
      this.s.attestors[end.attestor] = rec;
      await this.record('attestor.endorsed', { attestor: end.attestor, name: end.name, by: end.iss });
      this.emit('registry', { kind: 'attestor', id: end.attestor });
      return rec;
    });
  }

  registerPassport(pp) {
    return this.serial(async () => {
      if (pp?.type !== 'AgentPassport') throw new Error('not an agent passport');
      const chain = await this.passportChain(pp);
      if (!chain.ok) throw new Error('passport rejected: ' + chain.reason);
      this.s.passports[pp.id] = pp;
      this.s.passportBySub[pp.sub] = pp.id;
      await this.record('passport.issued', { id: pp.id, agent: pp.sub, name: pp.name, iss: pp.iss, measurement: pp.runtime.measurement });
      this.emit('registry', { kind: 'passport', id: pp.id });
      return { id: pp.id, root: chain.root, depth: chain.chain.length - 1 };
    });
  }

  registerMandate(m) {
    return this.serial(async () => {
      if (m?.type !== 'Mandate') throw new Error('not a mandate');
      const chain = await this.mandateChain(m);
      if (!chain.ok) throw new Error('mandate rejected: ' + chain.reason);
      const ppId = this.s.passportBySub[m.sub];
      if (!ppId) throw new Error('mandate rejected: the receiving agent has no passport');
      const ppRoot = this.rootPrincipalOfPassport(this.s.passports[ppId]);
      if (ppRoot !== chain.root) throw new Error('mandate rejected: it comes from a different principal than the agent passport');
      this.s.mandates[m.id] = m;
      await this.record('mandate.issued', { id: m.id, iss: m.iss, sub: m.sub, parent: m.parent, caps: m.caps.map((c) => c.action + ' ' + c.resource) });
      this.emit('registry', { kind: 'mandate', id: m.id });
      return { id: m.id, depth: chain.chain.length - 1 };
    });
  }

  async passportChain(pp) {
    const chain = [];
    let cur = pp;
    for (let i = 0; i < MAX_CHAIN; i++) {
      chain.push(cur);
      if (!(await verifySealed(cur, cur.iss))) return fail(`passport ${cur.id} signature is invalid`);
      if (cur.exp < this.now()) return fail(`passport ${cur.id} expired`);
      if (this.s.principals[cur.iss]) {
        if (cur.parent) return fail('a root passport must not name a parent');
        return { ok: true, chain, root: cur.iss };
      }
      const parent = this.s.passports[cur.parent];
      if (!parent) return fail('issuer is neither a registered principal nor an agent with a known passport');
      if (parent.sub !== cur.iss) return fail('parent passport does not belong to the issuer');
      if (parent.depth < 1) return fail(`${parent.name} is not allowed to create sub-agents`);
      if (cur.depth > parent.depth - 1) return fail('asks for more sub-agent depth than its issuer has');
      if (cur.exp > parent.exp) return fail('outlives the passport of its issuer');
      cur = parent;
    }
    return fail('passport chain is too deep');
  }

  async mandateChain(m) {
    const chain = [];
    let cur = m;
    const now = this.now();
    for (let i = 0; i < MAX_CHAIN; i++) {
      chain.push(cur);
      if (!(await verifySealed(cur, cur.iss))) return fail(`mandate ${cur.id} signature is invalid`);
      if (cur.exp < now) return fail(`mandate ${cur.id} expired`);
      if (cur.nbf > now + 30) return fail(`mandate ${cur.id} is not valid yet`);
      if (!cur.parent) {
        if (!this.s.principals[cur.iss]) return fail('a root mandate must be issued by a registered principal');
        return { ok: true, chain, root: cur.iss };
      }
      const parent = this.s.mandates[cur.parent];
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

  // Synchronous ancestry walks over already-verified records, for status and cascade.
  passportAncestry(pp) {
    const out = [];
    for (let cur = pp, i = 0; cur && i < MAX_CHAIN; cur = this.s.passports[cur.parent], i++) out.push(cur);
    return out;
  }

  mandateAncestry(m) {
    const out = [];
    for (let cur = m, i = 0; cur && i < MAX_CHAIN; cur = this.s.mandates[cur.parent], i++) out.push(cur);
    return out;
  }

  rootPrincipalOfPassport(pp) {
    const a = this.passportAncestry(pp);
    return a[a.length - 1]?.iss;
  }

  revokedHit(records) {
    for (const r of records) {
      const hit = this.s.revoked[r.id] || this.s.revoked[r.sub];
      if (hit) return { record: r, revocation: hit };
    }
    return null;
  }

  // ---------------------------------------------------------------- verification

  verifyIntent(intent) {
    return this.serial(() => this.#verify(intent));
  }

  async #verify(intent) {
    const trace = CHECKS.map(([key, label]) => ({ key, label, status: 'skipped', detail: '' }));
    const mark = (key, status, detail) => Object.assign(trace.find((t) => t.key === key), { status, detail });
    const ctx = { intent, trace, risk: null, passport: null, mandates: [] };
    const deny = (key, detail) => { mark(key, 'fail', detail); return this.#finish(ctx, 'deny', key); };
    const now = this.now();

    // 1. Proof of key: the agent signed this exact request.
    if (intent?.type !== 'Intent' || !isDid(intent.agent)) return deny('signature', 'not a well-formed intent');
    if (!(await verifySealed(intent, intent.agent))) return deny('signature', 'signature does not match the agent key it claims');
    mark('signature', 'pass', `signed by ${shortDid(intent.agent)}`);

    // 2. Freshness: short-lived and single-use.
    if (intent.iat > now + 30) return deny('freshness', 'issued in the future');
    if (intent.exp < now) return deny('freshness', `expired ${now - intent.exp}s ago`);
    if (intent.exp - intent.iat > 300) return deny('freshness', 'lifetime is longer than 5 minutes');
    for (const [n, exp] of Object.entries(this.s.nonces)) if (exp < now) delete this.s.nonces[n];
    if (this.s.nonces[intent.nonce]) return deny('freshness', 'this exact request was already used; replay blocked');
    this.s.nonces[intent.nonce] = intent.exp;
    mark('freshness', 'pass', `single-use nonce, expires in ${intent.exp - now}s`);

    // 3. Identity: a passport that chains to a principal and has not been revoked.
    const pp = this.s.passports[intent.passport];
    if (!pp) return deny('identity', 'no passport on file for this agent');
    if (pp.sub !== intent.agent) return deny('identity', 'the passport belongs to a different agent');
    const pchain = await this.passportChain(pp);
    if (!pchain.ok) return deny('identity', pchain.reason);
    const pRevoked = this.revokedHit(pchain.chain);
    if (pRevoked) return deny('identity', `${pRevoked.record.name || pRevoked.record.id} was revoked: ${pRevoked.revocation.reason || 'no reason given'}`);
    ctx.passport = pp;
    ctx.root = pchain.root;
    const principal = this.s.principals[pchain.root];
    mark('identity', 'pass', `${pp.name}, vouched for by ${principal?.name}` + (pchain.chain.length > 1 ? ` via ${pchain.chain.length - 1} parent agent(s)` : ''));

    // 4. Proof of runtime: a trusted host says the running code is the passported code.
    const att = intent.attestation;
    if (!att) return deny('runtime', 'no runtime attestation attached');
    const host = this.s.attestors[att.iss];
    if (!host || !host.endorsedBy.includes(pchain.root)) return deny('runtime', 'attested by a host this principal does not trust');
    if (!(await verifySealed(att, att.iss))) return deny('runtime', 'attestation signature is invalid');
    if (att.sub !== intent.agent) return deny('runtime', 'attestation is for a different agent');
    if (att.exp < now) return deny('runtime', 'attestation expired');
    if (att.measurement !== pp.runtime.measurement) {
      return deny('runtime', `runtime changed since the passport was issued (expected ${pp.runtime.measurement.slice(0, 10)}…, running ${att.measurement.slice(0, 10)}…)`);
    }
    mark('runtime', 'pass', `${host.name} measured ${att.measurement.slice(0, 12)}…`);

    // 5. Mandate: a chain of grants, each narrower than the one above it.
    const m = this.s.mandates[intent.mandate];
    if (!m) return deny('mandate', 'no mandate on file for this request');
    if (m.sub !== intent.agent) return deny('mandate', 'the mandate was granted to a different agent');
    const mchain = await this.mandateChain(m);
    if (!mchain.ok) return deny('mandate', mchain.reason);
    if (mchain.root !== pchain.root) return deny('mandate', 'mandate and passport come from different principals');
    const mRevoked = this.revokedHit(mchain.chain);
    if (mRevoked) return deny('mandate', `${mRevoked.record.label || mRevoked.record.id} was revoked: ${mRevoked.revocation.reason || 'no reason given'}`);
    ctx.mandates = mchain.chain;
    mark('mandate', 'pass', mchain.chain.length > 1 ? `${mchain.chain.length} links, each narrower than the last` : `granted directly by ${principal?.name}`);

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
      const sp = this.spendOf(mm.id);
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
    const leafBudget = m.budget ? `${fmt(this.spendOf(m.id).spent + amount)} of ${fmt(m.budget.amount)} ${m.budget.currency} after this` : 'no budget on this mandate';
    mark('budget', 'pass', leafBudget);

    // 9. Behavior: explainable signals, not a black box.
    ctx.risk = this.assessRisk(intent, m, amount);
    mark('risk', ctx.risk.score >= RISK_STEP_UP ? 'warn' : 'pass', `score ${ctx.risk.score}` + (ctx.risk.factors.length ? ': ' + ctx.risk.factors.map((f) => f.label).join('; ') : ''));

    // 10. Co-sign: the agent-native second factor. A human or a guardian quorum signs.
    const reasons = [];
    let quorum = null;
    for (const mm of mchain.chain) {
      if (mm.cosign?.above !== undefined && amount > mm.cosign.above) reasons.push(`amount above ${fmt(mm.cosign.above)}`);
      if (mm.cosign?.actions?.some((p) => globMatch(p, intent.action))) reasons.push(`${intent.action} always needs a co-sign`);
      if (mm.cosign?.quorum && !quorum) quorum = mm.cosign.quorum;
    }
    if (ctx.risk.score >= RISK_STEP_UP) reasons.push(`risk score ${ctx.risk.score}`);
    if (reasons.length) {
      mark('cosign', 'hold', [...new Set(reasons)].join('; '));
      return this.#hold(ctx, [...new Set(reasons)], quorum, amount);
    }
    mark('cosign', 'pass', 'not required for this request');
    return this.#finish(ctx, 'allow');
  }

  spendOf(id) {
    return (this.s.spend[id] ||= { spent: 0, reserved: 0, events: [] });
  }

  assessRisk(intent, mandate, amount) {
    const prof = this.s.profiles[intent.agent] || { actions: [], resources: [], amounts: [], recent: [] };
    const factors = [];
    const add = (points, label) => factors.push({ points, label });
    const nowMs = this.nowMs();
    if (!prof.actions.length) add(5, 'no behavioral history yet');
    else if (!prof.actions.includes(intent.action)) add(15, `first use of ${intent.action}`);
    if (prof.resources.length && !prof.resources.includes(intent.resource)) add(20, `first contact with ${intent.resource}`);
    const burst = prof.recent.filter((t) => nowMs - t < 10_000).length;
    if (burst >= 5) add(25, `${burst + 1} actions within 10 seconds`);
    if (amount && prof.amounts.length >= 3) {
      const med = median(prof.amounts);
      if (med > 0 && amount > 2.5 * med) add(20, `amount is ${(amount / med).toFixed(1)}× this agent's typical`);
    }
    if (INJECTION.test(intent.reason || '')) add(50, 'justification contains instruction-override language');
    if (!(intent.reason || '').trim()) add(10, 'no justification given');
    if (mandate.budget && amount) {
      const sp = this.spendOf(mandate.id);
      if ((sp.spent + sp.reserved + amount) / mandate.budget.amount > 0.8) add(10, 'pushes budget use past 80%');
    }
    return { score: Math.min(100, factors.reduce((a, f) => a + f.points, 0)), factors };
  }

  learn(intent, amount) {
    const prof = (this.s.profiles[intent.agent] ||= { actions: [], resources: [], amounts: [], recent: [] });
    if (!prof.actions.includes(intent.action)) prof.actions.push(intent.action);
    if (!prof.resources.includes(intent.resource)) prof.resources.push(intent.resource);
    if (amount) prof.amounts = [...prof.amounts, amount].slice(-50);
  }

  touch(agent) {
    const prof = (this.s.profiles[agent] ||= { actions: [], resources: [], amounts: [], recent: [] });
    prof.recent = [...prof.recent.filter((t) => this.nowMs() - t < 60_000), this.nowMs()];
  }

  async #hold(ctx, reasons, quorum, amount) {
    const { intent } = ctx;
    for (const mm of ctx.mandates) this.spendOf(mm.id).reserved += amount;
    const approval = {
      id: randomId('ap'), status: 'pending',
      intent, intentHash: await hashObject(intent),
      agent: intent.agent, agentName: ctx.passport.name,
      action: intent.action, resource: intent.resource, params: intent.params, reason: intent.reason,
      reasons, risk: ctx.risk, trace: ctx.trace,
      principal: ctx.root, quorum, signatures: [],
      mandates: ctx.mandates.map((m) => m.id), amount,
      createdAt: this.nowMs(), expiresAt: this.nowMs() + APPROVAL_TTL_MS,
    };
    this.s.approvals[approval.id] = approval;
    return this.#finish(ctx, 'step_up', 'cosign', approval);
  }

  async #finish(ctx, decision, failedAt = null, approval = null) {
    const { intent, trace, risk } = ctx;
    const intentHash = intent ? await hashObject(intent) : null;
    const amount = typeof intent?.params?.amount === 'number' ? intent.params.amount : 0;
    if (decision === 'allow') {
      for (const mm of ctx.mandates) {
        const sp = this.spendOf(mm.id);
        sp.spent += amount;
        sp.events = [...sp.events.filter((t) => this.nowMs() - t < 86_400_000), this.nowMs()];
      }
      this.learn(intent, amount);
    }
    if (ctx.passport) this.touch(intent.agent);
    const result = {
      id: randomId('dc'), ts: this.nowMs(), decision, failedAt,
      intentId: intent?.id, intentHash,
      agent: intent?.agent, agentName: ctx.passport?.name || this.nameOf(intent?.agent),
      action: intent?.action, resource: intent?.resource, params: intent?.params, reason: intent?.reason,
      checks: trace, risk, approvalId: approval?.id ?? null, via: ctx.via ?? null,
    };
    const entry = await this.record('intent.' + decision, {
      decision: result.id, intent: intentHash, agent: result.agent, action: result.action, resource: result.resource,
      amount: amount || undefined, failedAt: failedAt || undefined, via: ctx.via || undefined,
    });
    result.ledgerSeq = entry.seq;
    if (decision === 'allow') {
      result.receipt = await this.signer.seal({
        type: 'Receipt', v: 1, intent: intent.id, intentHash, agent: intent.agent,
        action: intent.action, resource: intent.resource, params: intent.params, aud: intent.aud,
        cosigners: ctx.cosigners || [], ledgerSeq: entry.seq, iat: this.now(),
      });
    }
    this.s.stats[decision === 'allow' ? 'allowed' : decision === 'deny' ? 'denied' : 'stepUp']++;
    this.s.decisions = [...this.s.decisions, stripForFeed(result)].slice(-150);
    this.emit('decision', result);
    if (approval) this.emit('approval', { id: approval.id, status: 'pending' });
    return result;
  }

  nameOf(did) {
    const pp = this.s.passports[this.s.passportBySub[did]];
    return pp?.name || (did ? shortDid(did) : 'unknown');
  }

  // ---------------------------------------------------------------- co-sign

  resolveApproval(cosign) {
    return this.serial(async () => {
      const ap = this.s.approvals[cosign?.approval];
      if (!ap) throw new Error('approval not found');
      this.expireApprovals();
      if (ap.status !== 'pending') throw new Error(`approval is already ${ap.status}`);
      if (cosign.type !== 'CoSign' || !(await verifySealed(cosign, cosign.iss))) throw new Error('co-sign signature is invalid');
      if (cosign.intentHash !== ap.intentHash) throw new Error('co-sign is for a different request');
      const isPrincipal = cosign.iss === ap.principal;
      const isGuardian = ap.quorum?.of?.includes(cosign.iss);
      if (!isPrincipal && !isGuardian) throw new Error('signer is not allowed to approve this request');
      if (ap.signatures.some((s) => s.iss === cosign.iss)) throw new Error('signer already responded');
      ap.signatures.push({ iss: cosign.iss, decision: cosign.decision, at: this.nowMs() });

      const approvals = ap.signatures.filter((s) => s.decision === 'approve');
      const guardianApprovals = approvals.filter((s) => ap.quorum?.of?.includes(s.iss)).length;
      if (cosign.decision === 'decline' && (isPrincipal || !ap.quorum)) return this.#closeApproval(ap, 'declined', `declined by ${this.s.principals[cosign.iss]?.name || shortDid(cosign.iss)}`);
      if (cosign.decision === 'decline' && ap.quorum && ap.quorum.of.length - ap.signatures.filter((s) => s.decision === 'decline').length < ap.quorum.k) {
        return this.#closeApproval(ap, 'declined', 'guardian quorum can no longer be reached');
      }
      const approved = (isPrincipal && cosign.decision === 'approve') || (ap.quorum && guardianApprovals >= ap.quorum.k);
      if (!approved) { this.emit('approval', { id: ap.id, status: 'pending' }); return { id: ap.id, status: 'pending', signatures: ap.signatures.length }; }

      // Re-check revocation: the world may have changed while the request waited.
      const pp = this.s.passports[this.s.passportBySub[ap.agent]];
      const hit = this.revokedHit(this.passportAncestry(pp)) || this.revokedHit(ap.mandates.map((id) => this.s.mandates[id]));
      if (hit) return this.#closeApproval(ap, 'declined', 'revoked while waiting for co-sign');
      return this.#closeApproval(ap, 'approved');
    });
  }

  async #closeApproval(ap, status, note = '') {
    ap.status = status;
    ap.closedAt = this.nowMs();
    ap.note = note;
    for (const id of ap.mandates) this.spendOf(id).reserved = Math.max(0, this.spendOf(id).reserved - ap.amount);
    const trace = ap.trace.map((t) => (t.key === 'cosign'
      ? { ...t, status: status === 'approved' ? 'pass' : 'fail', detail: status === 'approved' ? `co-signed by ${ap.signatures.filter((s) => s.decision === 'approve').map((s) => this.s.principals[s.iss]?.name || this.nameOf(s.iss)).join(', ')}` : note }
      : t));
    const pp = this.s.passports[this.s.passportBySub[ap.agent]];
    const ctx = {
      intent: ap.intent, trace, risk: ap.risk, passport: pp,
      mandates: ap.mandates.map((id) => this.s.mandates[id]),
      via: 'cosign', cosigners: ap.signatures.filter((s) => s.decision === 'approve').map((s) => s.iss),
    };
    const result = await this.#finish(ctx, status === 'approved' ? 'allow' : 'deny', status === 'approved' ? null : 'cosign');
    ap.result = result.id;
    ap.receipt = result.receipt ?? null;
    this.emit('approval', { id: ap.id, status });
    return { id: ap.id, status, decision: result };
  }

  expireApprovals() {
    for (const ap of Object.values(this.s.approvals)) {
      if (ap.status === 'pending' && ap.expiresAt < this.nowMs()) {
        ap.status = 'expired';
        for (const id of ap.mandates) this.spendOf(id).reserved = Math.max(0, this.spendOf(id).reserved - ap.amount);
      }
    }
  }

  // ---------------------------------------------------------------- revocation

  revoke(rev) {
    return this.serial(async () => {
      if (rev?.type !== 'Revocation') throw new Error('not a revocation');
      if (!(await verifySealed(rev, rev.iss))) throw new Error('revocation signature is invalid');
      const { target } = rev;
      let issuers = [];
      const pp = this.s.passports[target] || this.s.passports[this.s.passportBySub[target]];
      const md = this.s.mandates[target];
      if (pp) issuers = this.passportAncestry(pp).map((p) => p.iss);
      else if (md) issuers = this.mandateAncestry(md).map((m) => m.iss);
      else throw new Error('nothing to revoke with that id');
      if (!issuers.includes(rev.iss) && rev.iss !== target) throw new Error('only an issuer up the chain can revoke this');
      this.s.revoked[target] = { target, reason: rev.reason, by: rev.iss, at: this.nowMs() };

      const affected = this.affectedBy(target);
      for (const ap of Object.values(this.s.approvals)) {
        if (ap.status === 'pending' && affected.agents.includes(ap.agent)) await this.#closeApproval(ap, 'declined', 'revoked while waiting for co-sign');
      }
      await this.record('revoked', { target, by: rev.iss, reason: rev.reason, agents: affected.agents.length, mandates: affected.mandates.length });
      this.emit('revoked', { target, ...affected });
      return { target, ...affected };
    });
  }

  affectedBy(target) {
    const agents = [];
    const mandates = [];
    for (const pp of Object.values(this.s.passports)) {
      if (this.passportAncestry(pp).some((p) => p.id === target || p.sub === target)) agents.push(pp.sub);
    }
    for (const m of Object.values(this.s.mandates)) {
      if (this.mandateAncestry(m).some((x) => x.id === target || x.sub === target || agents.includes(x.sub))) mandates.push(m.id);
    }
    return { agents, mandates };
  }

  // ---------------------------------------------------------------- reads

  statusOf(record, kind) {
    const chain = kind === 'passport' ? this.passportAncestry(record) : this.mandateAncestry(record);
    if (this.revokedHit(chain)) return 'revoked';
    if (chain.some((r) => r.exp < this.now())) return 'expired';
    return 'active';
  }

  snapshot() {
    this.expireApprovals();
    const s = this.s;
    return {
      authority: { did: this.did },
      principals: Object.values(s.principals),
      attestors: Object.values(s.attestors),
      passports: Object.values(s.passports).map((p) => ({ ...p, status: this.statusOf(p, 'passport'), root: this.rootPrincipalOfPassport(p), profile: s.profiles[p.sub] || null })),
      mandates: Object.values(s.mandates).map((m) => ({ ...m, status: this.statusOf(m, 'mandate'), spent: this.spendOf(m.id).spent, reserved: this.spendOf(m.id).reserved })),
      revoked: Object.values(s.revoked),
      approvals: Object.values(s.approvals).sort((a, b) => b.createdAt - a.createdAt).slice(0, 40),
      decisions: s.decisions.slice(-80),
      stats: { ...s.stats },
      ledger: { height: this.ledger.entries.length, head: this.ledger.head },
    };
  }

  ledgerEntries({ from = 0, limit = 200 } = {}) {
    return this.ledger.entries.slice(from, from + limit);
  }

  verifyLedger() {
    return verifyChain(this.ledger.entries, this.did);
  }
}

// A relying service checks a receipt offline with nothing but the authority identifier.
export async function verifyReceipt(receipt, authorityDid, { aud, maxAgeSec = 120 } = {}) {
  if (receipt?.type !== 'Receipt') return fail('not a receipt');
  if (!(await verifySealed(receipt, authorityDid))) return fail('receipt is not signed by the authority');
  if (aud && receipt.aud !== aud && receipt.aud !== 'any') return fail('receipt is for a different service');
  if (Math.floor(Date.now() / 1000) - receipt.iat > maxAgeSec) return fail('receipt is too old');
  return { ok: true, receipt };
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
