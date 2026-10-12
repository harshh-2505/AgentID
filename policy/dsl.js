// Policy as code: a small, readable language that compiles to mandate specs.
//
//   mandate "Accounts payable" for ledgerline
//     allow payments.send on vendor:* where amount <= 1500 and currency in [USD]
//     allow invoices.* on erp:northwind/*
//     budget 250000 USD
//     rate 120 per 60s
//     cosign above 750
//     cosign always for payroll.*
//     cosign quorum 2 of [did:agentid:..., did:agentid:...]
//     passkey required
//     delegate depth 1
//     expires in 30d
//
// A spec is { label, subject, caps, budget, rate, cosign, depth, ttlSec }, the same
// fields Principal.issueMandate takes (with `subject` resolved to `sub` at issue time).
// The language only says what a mandate can already say, so nothing is lost either way.

import { capsWithin } from '../core/policy.js';
import { canonical } from '../core/encoding.js';

export class PolicyError extends Error {
  constructor(message, line, col) {
    super(`${line}:${col}: ${message}`);
    this.line = line;
    this.col = col;
    this.detail = message;
  }
}

// ---------------------------------------------------------------- lexer

const DUR = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
const NUM = /^-?\d[\d_]*(\.\d+)?$/;

// One line at a time: statements never span lines.
function lex(text, line) {
  const toks = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue; }
    if (c === '#') break;
    const col = i + 1;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (j >= text.length) throw new PolicyError('unterminated string', line, col);
      let value;
      try { value = JSON.parse(text.slice(i, j + 1)); } catch { throw new PolicyError('invalid escape in string', line, col); }
      toks.push({ kind: 'str', value, line, col });
      i = j + 1;
    } else if ('[],'.includes(c)) {
      toks.push({ kind: c, value: c, line, col });
      i++;
    } else if (c === '<' || c === '>' || c === '=' || c === '!') {
      let j = i + 1;
      while (j < text.length && '<>=!'.includes(text[j])) j++;
      toks.push({ kind: 'op', value: text.slice(i, j), line, col });
      i = j;
    } else {
      let j = i;
      while (j < text.length && !' \t\r[],"<>=!'.includes(text[j])) j++;
      toks.push({ kind: 'word', value: text.slice(i, j), line, col });
      i = j;
    }
  }
  return toks;
}

// ---------------------------------------------------------------- parser

class Cursor {
  constructor(toks, line, len) { this.toks = toks; this.i = 0; this.line = line; this.len = len; }
  peek() { return this.toks[this.i]; }
  at() { const t = this.peek(); return t ? [t.line, t.col] : [this.line, this.len + 1]; }
  fail(msg) { throw new PolicyError(msg, ...this.at()); }
  next(what) { const t = this.toks[this.i]; if (!t) this.fail(`expected ${what} but the line ended`); this.i++; return t; }
  word(what) {
    const t = this.next(what);
    if (t.kind !== 'word' && t.kind !== 'str') { this.i--; this.fail(`expected ${what}, found "${t.value}"`); }
    return t.value;
  }
  keyword(kw) {
    const t = this.next(`"${kw}"`);
    if (t.kind !== 'word' || t.value !== kw) { this.i--; this.fail(`expected "${kw}", found "${t.value}"`); }
  }
  is(kw) { const t = this.peek(); return t && t.kind === 'word' && t.value === kw; }
  number(what, { int = false, min } = {}) {
    const t = this.next(what);
    if (t.kind !== 'word' || !NUM.test(t.value)) { this.i--; this.fail(`expected ${what} (a number), found "${t.value}"`); }
    const n = Number(t.value.replace(/_/g, ''));
    if (int && !Number.isInteger(n)) { this.i--; this.fail(`${what} must be a whole number`); }
    if (min !== undefined && n < min) { this.i--; this.fail(`${what} must be at least ${min}`); }
    return n;
  }
  duration(what) {
    const t = this.next(what);
    const m = t.kind === 'word' && /^(\d+)([smhdw])$/.exec(t.value);
    if (!m) { this.i--; this.fail(`expected ${what} like 60s, 15m, 12h, 30d or 2w, found "${t.value}"`); }
    if (Number(m[1]) <= 0) { this.i--; this.fail(`${what} must be positive`); }
    return Number(m[1]) * DUR[m[2]];
  }
  // [a, b, "c d", 3]: unquoted numbers are numbers, everything else a string.
  list(what, { numbers = true } = {}) {
    const open = this.next(what);
    if (open.kind !== '[') { this.i--; this.fail(`expected [ to start ${what}`); }
    const items = [];
    for (;;) {
      const t = this.next(`a value or ]`);
      if (t.kind === ']' && !items.length) break;
      if (t.kind === 'str') items.push(t.value);
      else if (t.kind === 'word') items.push(numbers && NUM.test(t.value) ? Number(t.value.replace(/_/g, '')) : t.value);
      else { this.i--; this.fail(`expected a value in ${what}, found "${t.value}"`); }
      const sep = this.next(', or ]');
      if (sep.kind === ']') break;
      if (sep.kind !== ',') { this.i--; this.fail(`expected , or ] in ${what}, found "${sep.value}"`); }
    }
    if (!items.length) { this.i--; this.fail(`${what} is empty`); }
    return items;
  }
  end() { const t = this.peek(); if (t) this.fail(`unexpected "${t.value}"`); }
}

function parseWhere(cur, cap) {
  const limits = {};
  do {
    const [line, col] = cur.at();
    const param = cur.word('a parameter name');
    const t = cur.next('an operator (<=, >=, in, matches)');
    const rule = (limits[param] ??= {});
    const set = (k, v) => {
      if (rule[k] !== undefined) throw new PolicyError(`${param} already has a ${k} limit`, line, col);
      rule[k] = v;
    };
    if (t.kind === 'op' && t.value === '<=') set('max', cur.number(`the max for ${param}`));
    else if (t.kind === 'op' && t.value === '>=') set('min', cur.number(`the min for ${param}`));
    else if (t.kind === 'op') throw new PolicyError(`unsupported operator "${t.value}"; limits are inclusive, use <= or >=`, t.line, t.col);
    else if (t.kind === 'word' && t.value === 'in') set('in', cur.list(`the allowed values of ${param}`));
    else if (t.kind === 'word' && t.value === 'matches') set('match', cur.list(`the patterns for ${param}`, { numbers: false }).map(String));
    else throw new PolicyError(`expected <=, >=, in or matches after ${param}, found "${t.value}"`, t.line, t.col);
    if (rule.max !== undefined && rule.min !== undefined && rule.min > rule.max) throw new PolicyError(`${param} min ${rule.min} is above its max ${rule.max}: nothing could pass`, line, col);
  } while (cur.is('and') && cur.next('and'));
  cap.limits = limits;
}

// Mandate statements. Each one fills one field and may appear once (allow, cosign always: many).
const STATEMENTS = {
  allow(cur, m) {
    const cap = { action: cur.word('an action pattern') };
    cur.keyword('on');
    cap.resource = cur.word('a resource pattern');
    if (cur.is('where')) { cur.next(); parseWhere(cur, cap); }
    m.caps.push(cap);
  },
  budget(cur, m) {
    once(cur, m, 'budget');
    const amount = cur.number('the budget amount', { min: 0 });
    const at = cur.at();
    const currency = cur.word('a currency code');
    if (!/^[A-Z]{3}$/.test(currency)) throw new PolicyError(`currency should be a 3-letter code like USD, found "${currency}"`, ...at);
    m.budget = { amount, currency };
  },
  rate(cur, m) {
    once(cur, m, 'rate');
    const max = cur.number('the rate count', { int: true, min: 1 });
    cur.keyword('per');
    m.rate = { max, windowSec: cur.duration('the rate window') };
  },
  cosign(cur, m) {
    const c = (m.cosign ??= {});
    const [line, col] = cur.at();
    const kind = cur.word('above, always or quorum');
    const dup = (k) => { if (c[k] !== undefined) throw new PolicyError(`cosign ${kind} is already set for this mandate`, line, col); };
    if (kind === 'above') { dup('above'); c.above = cur.number('the co-sign threshold', { min: 0 }); }
    else if (kind === 'always') {
      cur.keyword('for');
      const acts = [cur.word('an action pattern')];
      while (cur.peek()?.kind === ',') { cur.next(); acts.push(cur.word('an action pattern')); }
      c.actions = [...(c.actions || []), ...acts];
    } else if (kind === 'quorum') {
      dup('quorum');
      const k = cur.number('the quorum size', { int: true, min: 1 });
      cur.keyword('of');
      const of = cur.list('the guardians', { numbers: false }).map(String);
      if (k > of.length) throw new PolicyError(`quorum of ${k} can never be met by ${of.length} guardian(s)`, line, col);
      if (new Set(of).size !== of.length) throw new PolicyError('a guardian is listed twice', line, col);
      c.quorum = { k, of };
    } else throw new PolicyError(`expected above, always or quorum after cosign, found "${kind}"`, line, col);
  },
  passkey(cur, m) {
    cur.keyword('required');
    if (m.cosign?.passkey) cur.fail('passkey required is already set');
    (m.cosign ??= {}).passkey = true;
  },
  delegate(cur, m) {
    once(cur, m, 'depth');
    cur.keyword('depth');
    m.depth = cur.number('the delegation depth', { int: true, min: 0 });
  },
  expires(cur, m) {
    once(cur, m, 'ttlSec');
    cur.keyword('in');
    m.ttlSec = cur.duration('the lifetime');
  },
};

function once(cur, m, field) {
  if (m.seen.has(field)) cur.fail(`${field === 'ttlSec' ? 'expires' : field === 'depth' ? 'delegate depth' : field} is already set for this mandate`);
  m.seen.add(field);
}

export function parse(text) {
  const specs = [];
  let m = null;
  const finish = () => {
    if (!m) return;
    if (!m.caps.length) throw new PolicyError(`mandate "${m.label}" grants nothing: add at least one allow line`, m.line, 1);
    specs.push(toSpec(m));
  };
  text.split('\n').forEach((raw, idx) => {
    const line = idx + 1;
    const toks = lex(raw, line);
    if (!toks.length) return;
    const cur = new Cursor(toks, line, raw.replace(/\s+$/, '').length);
    const head = cur.word('a statement');
    if (head === 'mandate') {
      finish();
      const label = cur.next('the mandate name in quotes');
      if (label.kind !== 'str') { cur.i--; cur.fail('the mandate name must be in double quotes'); }
      cur.keyword('for');
      m = { label: label.value, subject: cur.word('the agent this mandate is for'), caps: [], budget: null, rate: null, cosign: null, depth: 0, ttlSec: null, seen: new Set(), line };
      if (specs.some((s) => s.label === m.label && s.subject === m.subject)) throw new PolicyError(`mandate "${m.label}" for ${m.subject} is defined twice`, line, toks[1].col);
    } else {
      const fn = Object.hasOwn(STATEMENTS, head) ? STATEMENTS[head] : null;
      if (!fn) { cur.i--; cur.fail(`unknown statement "${head}"; expected mandate, ${Object.keys(STATEMENTS).join(', ')}`); }
      if (!m) { cur.i--; cur.fail(`"${head}" must come after a mandate line`); }
      fn(cur, m);
    }
    cur.end();
  });
  finish();
  return specs;
}

function toSpec({ label, subject, caps, budget, rate, cosign, depth, ttlSec }) {
  return { label, subject, caps, budget, rate, cosign, depth, ttlSec };
}

// ---------------------------------------------------------------- formatter

const KEYWORD = new Set(['where', 'and', 'on', 'in', 'matches', 'for', 'of']);
const word = (v) => (typeof v === 'string' && v && !/[\s[\],"<>=!#]/.test(v) && !NUM.test(v) && !KEYWORD.has(v) ? v : JSON.stringify(String(v)));
const value = (v) => (typeof v === 'number' ? String(v) : word(v));
const list = (xs) => `[${xs.map(value).join(', ')}]`;
const dur = (s) => (s % 86400 === 0 ? `${s / 86400}d` : s % 3600 === 0 ? `${s / 3600}h` : `${s}s`);

function formatOne(s) {
  const out = [`mandate ${JSON.stringify(s.label ?? '')} for ${word(s.subject)}`];
  for (const cap of s.caps) {
    const conds = [];
    for (const [k, r] of Object.entries(cap.limits || {})) {
      if (r.min !== undefined) conds.push(`${word(k)} >= ${r.min}`);
      if (r.max !== undefined) conds.push(`${word(k)} <= ${r.max}`);
      if (r.in) conds.push(`${word(k)} in ${list(r.in)}`);
      if (r.match) conds.push(`${word(k)} matches ${list(r.match.map(String))}`);
    }
    out.push(`  allow ${word(cap.action)} on ${word(cap.resource)}${conds.length ? ' where ' + conds.join(' and ') : ''}`);
  }
  if (s.budget) out.push(`  budget ${s.budget.amount} ${s.budget.currency}`);
  if (s.rate) out.push(`  rate ${s.rate.max} per ${dur(s.rate.windowSec)}`);
  const c = s.cosign || {};
  if (c.above !== undefined) out.push(`  cosign above ${c.above}`);
  if (c.actions?.length) out.push(`  cosign always for ${c.actions.map(word).join(', ')}`);
  if (c.quorum) out.push(`  cosign quorum ${c.quorum.k} of ${list(c.quorum.of.map(String))}`);
  if (c.passkey) out.push('  passkey required');
  if (s.depth) out.push(`  delegate depth ${s.depth}`);
  if (s.ttlSec) out.push(`  expires in ${dur(s.ttlSec)}`);
  return out.join('\n');
}

export function format(specs) {
  return (Array.isArray(specs) ? specs : [specs]).map(formatOne).join('\n\n') + '\n';
}

// ---------------------------------------------------------------- lint

// Name-based guesses: good enough to prompt a second look, never used to decide anything.
const MONEY = /(^|[.:/_-])(pay|payments?|payroll|transfers?|refunds?|purchases?|charges?|wires?|book|buy|orders?)($|[.:/_*-])/i;
const WRITE = /(^|[.:/_-])(send|write|delete|create|update|put|post|remove|drop|exec|run|book|pay|transfer|refund|purchase|charge|wire|buy|order)($|[.:/_*-])|\*$/i;
const money = (a) => MONEY.test(a);
// "vendor:*", "*", "https://*": a wildcard straight after the scheme reaches every instance.
const broadResource = (r) => /^[^/*]*?(:\/*)?\*$/.test(r) || r === '*';

export function lint(specs) {
  const warnings = [];
  for (const s of specs) {
    const warn = (code, message) => warnings.push({ mandate: s.label, subject: s.subject, code, message });
    const moneyCaps = s.caps.filter((c) => money(c.action));
    for (const c of s.caps) {
      const where = `${c.action} on ${c.resource}`;
      if (c.action === '*') warn('every-action', `${where} grants every action`);
      if (money(c.action) && c.limits?.amount?.max === undefined) warn('unbounded-amount', `${where} moves money with no amount <= limit`);
      if (money(c.action) && s.budget && !c.limits?.currency?.in) warn('no-currency', `${where} does not pin currency; payments in another currency are refused by the budget check, so say so in policy`);
      if (WRITE.test(c.action) && broadResource(c.resource)) warn('wildcard-write', `${where} lets a write-like action reach any ${c.resource === '*' ? 'resource' : c.resource.replace(/\*$/, '') + '…'}`);
    }
    if (moneyCaps.length && !s.budget) warn('no-budget', `moves money (${moneyCaps.map((c) => c.action).join(', ')}) with no budget`);
    const above = s.cosign?.above;
    if (above !== undefined && moneyCaps.length && moneyCaps.every((c) => c.limits?.amount?.max !== undefined)) {
      const top = Math.max(...moneyCaps.map((c) => c.limits.amount.max));
      if (above >= top) warn('unreachable-cosign', `cosign above ${above} can never trigger: no capability allows an amount over ${top}`);
    }
    if (s.budget && above !== undefined && above >= s.budget.amount) warn('unreachable-cosign', `cosign above ${above} is at or over the whole budget of ${s.budget.amount}`);
    if (s.depth > 0 && !s.ttlSec) warn('delegable-default-ttl', `delegate depth ${s.depth} with no expires line: this mandate, and everything delegated under it, runs on the 7-day default`);
  }
  return warnings;
}

// ---------------------------------------------------------------- diff

const DEFAULT_TTL = 7 * 86400;
const key = (s) => `${s.label}\u0000${s.subject}`;
const capKey = (c) => canonical({ action: c.action, resource: c.resource, limits: c.limits || {} });
const capName = (c) => `${c.action} on ${c.resource}`;
const fmtLimit = (r) => (r === undefined ? 'none' : JSON.stringify(r));

// Compares two policy versions mandate by mandate. Scope changes are judged with the
// authority's own attenuation check, so "narrowed" here means what it means at runtime.
export function diff(oldSpecs, newSpecs) {
  const before = new Map(oldSpecs.map((s) => [key(s), s]));
  const after = new Map(newSpecs.map((s) => [key(s), s]));
  const mandates = [];
  for (const [k, n] of after) {
    const o = before.get(k);
    if (!o) mandates.push({ label: n.label, subject: n.subject, status: 'added', widens: true, changes: [{ widens: true, detail: `new mandate with ${n.caps.length} capability(ies)` }], capsAdded: n.caps, capsRemoved: [] });
    else mandates.push(compare(o, n));
  }
  for (const [k, o] of before) {
    if (!after.has(k)) mandates.push({ label: o.label, subject: o.subject, status: 'removed', widens: false, changes: [{ widens: false, detail: 'mandate removed' }], capsAdded: [], capsRemoved: o.caps });
  }
  return { widened: mandates.some((m) => m.widens), mandates };
}

function compare(o, n) {
  const changes = [];
  const add = (widens, detail, narrows = !widens) => changes.push({ widens, narrows, detail });

  const oldKeys = new Set(o.caps.map(capKey));
  const newKeys = new Set(n.caps.map(capKey));
  const capsAdded = n.caps.filter((c) => !oldKeys.has(capKey(c)));
  const capsRemoved = o.caps.filter((c) => !newKeys.has(capKey(c)));
  // Limit edits on the same action+resource read better as a change than add+remove.
  const paired = new Set();
  for (const c of capsAdded) {
    const prev = capsRemoved.find((p) => p.action === c.action && p.resource === c.resource && !paired.has(p));
    if (!prev) continue;
    paired.add(prev).add(c);
    for (const param of new Set([...Object.keys(prev.limits || {}), ...Object.keys(c.limits || {})])) {
      const a = prev.limits?.[param];
      const b = c.limits?.[param];
      if (canonical(a ?? null) === canonical(b ?? null)) continue;
      const wider = capsWithin([{ ...c, limits: b ? { [param]: b } : {} }], [{ ...c, limits: a ? { [param]: a } : {} }]).length > 0;
      const narrower = capsWithin([{ ...c, limits: a ? { [param]: a } : {} }], [{ ...c, limits: b ? { [param]: b } : {} }]).length > 0;
      add(wider, `${capName(c)}: ${param} ${fmtLimit(a)} → ${fmtLimit(b)}`, narrower);
    }
  }
  // Unchanged caps fit trivially, so only the edited ones need the attenuation check.
  for (const p of capsWithin(capsAdded.filter((c) => !paired.has(c)), o.caps)) add(true, `grants more: ${p}`, false);
  for (const p of capsWithin(capsRemoved.filter((c) => !paired.has(c)), n.caps)) add(false, `grants less: ${p}`, true);

  const ob = o.budget;
  const nb = n.budget;
  if (ob && !nb) add(true, `budget ${ob.amount} ${ob.currency} removed`);
  else if (!ob && nb) add(false, `budget ${nb.amount} ${nb.currency} added`);
  else if (ob && nb && ob.currency !== nb.currency) add(true, `budget currency ${ob.currency} → ${nb.currency}`, true);
  else if (ob && nb && ob.amount !== nb.amount) add(nb.amount > ob.amount, `budget ${ob.amount} → ${nb.amount} ${nb.currency}`);

  const or = o.rate;
  const nr = n.rate;
  if (or && !nr) add(true, `rate ${or.max}/${or.windowSec}s removed`);
  else if (!or && nr) add(false, `rate ${nr.max}/${nr.windowSec}s added`);
  else if (or && nr && (or.max !== nr.max || or.windowSec !== nr.windowSec)) {
    add(nr.max > or.max || nr.windowSec < or.windowSec, `rate ${or.max}/${or.windowSec}s → ${nr.max}/${nr.windowSec}s`, nr.max < or.max || nr.windowSec > or.windowSec);
  }

  const oc = o.cosign || {};
  const nc = n.cosign || {};
  if (oc.above !== nc.above) {
    const w = nc.above === undefined || (oc.above !== undefined && nc.above > oc.above);
    add(w, `cosign above ${oc.above ?? 'none'} → ${nc.above ?? 'none'}`);
  }
  for (const a of oc.actions || []) if (!(nc.actions || []).includes(a)) add(true, `cosign always for ${a} removed`);
  for (const a of nc.actions || []) if (!(oc.actions || []).includes(a)) add(false, `cosign always for ${a} added`);
  if (canonical(oc.quorum ?? null) !== canonical(nc.quorum ?? null)) {
    // A quorum is another way to approve, so more guardians or a smaller k widens.
    const oq = oc.quorum;
    const nq = nc.quorum;
    const w = !!nq && (!oq || nq.k < oq.k || nq.of.some((g) => !oq.of.includes(g)));
    const nar = !nq || (!!oq && (nq.k > oq.k || oq.of.some((g) => !nq.of.includes(g))));
    add(w, `cosign quorum ${oq ? `${oq.k} of ${oq.of.length}` : 'none'} → ${nq ? `${nq.k} of ${nq.of.length}` : 'none'}`, nar);
  }
  if (!!oc.passkey !== !!nc.passkey) add(!nc.passkey, `passkey ${nc.passkey ? 'now required' : 'no longer required'}`);

  if ((o.depth || 0) !== (n.depth || 0)) add((n.depth || 0) > (o.depth || 0), `delegate depth ${o.depth || 0} → ${n.depth || 0}`);
  const ot = o.ttlSec || DEFAULT_TTL;
  const nt = n.ttlSec || DEFAULT_TTL;
  if (ot !== nt) add(nt > ot, `lifetime ${dur(ot)} → ${dur(nt)}`);

  const widens = changes.some((c) => c.widens);
  const narrows = changes.some((c) => c.narrows);
  const status = widens && narrows ? 'changed' : widens ? 'widened' : narrows ? 'narrowed' : capsAdded.length || capsRemoved.length ? 'changed' : 'unchanged';
  return { label: n.label, subject: n.subject, status, widens, changes, capsAdded, capsRemoved };
}

export function formatDiff(result) {
  const out = [];
  for (const m of result.mandates) {
    const flag = m.widens ? '  !! WIDENS AUTHORITY' : '';
    out.push(`${m.status.toUpperCase().padEnd(9)} "${m.label}" for ${m.subject}${flag}`);
    if (m.status === 'unchanged') continue;
    for (const c of m.capsAdded) out.push(`    + allow ${capName(c)}${Object.keys(c.limits || {}).length ? ' ' + JSON.stringify(c.limits) : ''}`);
    for (const c of m.capsRemoved) out.push(`    - allow ${capName(c)}${Object.keys(c.limits || {}).length ? ' ' + JSON.stringify(c.limits) : ''}`);
    for (const c of m.changes) out.push(`    ${c.widens ? '!!' : '  '} ${c.detail}`);
  }
  out.push(result.widened ? '\nAuthority WIDENS in this change. Review before merging.' : '\nNo mandate gains authority.');
  return out.join('\n');
}
