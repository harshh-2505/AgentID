// Property tests: seeded random cases, no dependencies. A failure prints the seed and
// the case, so it can be replayed with AGENTID_SEED=<seed>.

import test from 'node:test';
import assert from 'node:assert/strict';
import { globMatch, authorize, capsWithin } from '../core/policy.js';
import { canonical, utf8, b64u, unb64u } from '../core/encoding.js';
import { Signer, verifySealed } from '../core/keys.js';

const SEED = Number(process.env.AGENTID_SEED ?? 0x5eed);
const CASES = 2000;

// mulberry32: tiny, fast, good enough to explore small spaces deterministically.
function prng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (lo, hi) => lo + Math.floor(next() * (hi - lo + 1));
  const pick = (xs) => xs[int(0, xs.length - 1)];
  const chance = (p) => next() < p;
  const str = (alpha, max) => Array.from({ length: int(0, max) }, () => pick(alpha)).join('');
  const subset = (xs) => xs.filter(() => chance(0.5));
  const shuffle = (xs) => { const out = [...xs]; for (let i = out.length - 1; i > 0; i--) { const j = int(0, i); [out[i], out[j]] = [out[j], out[i]]; } return out; };
  return { next, int, pick, chance, str, subset, shuffle };
}

const forAll = (name, fn) => {
  const r = prng(SEED ^ [...name].reduce((h, c) => Math.imul(h, 31) + c.charCodeAt(0), 7));
  for (let i = 0; i < CASES; i++) fn(r, i);
};

// ---------------------------------------------------------------- caps

const ALPHA = ['a', 'b', '.'];
const CURRENCIES = ['USD', 'EUR', 'GBP'];
const pattern = (r, alpha = ALPHA) => Array.from({ length: r.int(0, 4) }, () => (r.chance(0.25) ? '*' : r.pick(alpha))).join('');
const concrete = (r, p, alpha = ALPHA) => p.replace(/\*/g, () => r.str(alpha, 3));

function limits(r) {
  const l = {};
  if (r.chance(0.5)) {
    const rule = {};
    if (r.chance(0.6)) rule.max = r.int(0, 10);
    if (r.chance(0.4)) rule.min = r.int(0, 10);
    l.amount = rule;
  }
  if (r.chance(0.4)) l.cur = { in: r.subset(CURRENCIES) };
  if (r.chance(0.3)) l.to = { match: Array.from({ length: r.int(1, 2) }, () => pattern(r, ['a', 'b', '@'])) };
  return l;
}

const cap = (r) => ({ action: pattern(r), resource: pattern(r), limits: limits(r) });

// A child derived from a parent: stars specialised, limits tightened. Often (not always)
// within the parent, which is what makes the soundness property bite.
function attenuate(r, p) {
  const narrow = (pat) => pat.replace(/\*/g, () => (r.chance(0.5) ? '*' : r.str(ALPHA, 2) + (r.chance(0.5) ? '*' : '')));
  const l = {};
  for (const [k, rule] of Object.entries(p.limits)) {
    const c = {};
    if (rule.max !== undefined) c.max = rule.max - r.int(0, 2);
    if (rule.min !== undefined) c.min = rule.min + r.int(0, 2);
    if (rule.in) c.in = r.subset(rule.in);
    if (rule.match) c.match = rule.match.map(narrow);
    l[k] = c;
  }
  if (r.chance(0.2)) Object.assign(l, limits(r));
  return { action: narrow(p.action), resource: narrow(p.resource), limits: l };
}

function params(r) {
  const p = {};
  if (r.chance(0.85)) p.amount = r.chance(0.9) ? r.int(-1, 12) : String(r.int(0, 10));
  if (r.chance(0.85)) p.cur = r.pick([...CURRENCIES, 'JPY']);
  if (r.chance(0.85)) p.to = r.str(['a', 'b', '@'], 4);
  return p;
}

test('property: attenuation is sound (capsWithin empty ⇒ child allows only what parent allows)', () => {
  let within = 0;
  let allowedByChild = 0;
  forAll('attenuation', (r, i) => {
    const parent = Array.from({ length: r.int(1, 3) }, () => cap(r));
    const child = Array.from({ length: r.int(1, 2) }, () => (r.chance(0.8) ? attenuate(r, r.pick(parent)) : cap(r)));
    if (capsWithin(child, parent).length) return;
    within++;
    for (let j = 0; j < 20; j++) {
      const target = r.pick(child);
      const action = r.chance(0.8) ? concrete(r, target.action) : r.str(ALPHA, 4);
      const resource = r.chance(0.8) ? concrete(r, target.resource) : r.str(ALPHA, 4);
      const ps = params(r);
      if (!authorize(child, action, resource, ps).ok) continue;
      allowedByChild++;
      assert.ok(authorize(parent, action, resource, ps).ok, `seed ${SEED} case ${i}: child allows what parent refuses\n${JSON.stringify({ parent, child, action, resource, params: ps }, null, 1)}`);
    }
  });
  // Guard against a vacuous pass: the generators must actually produce in-bounds children.
  assert.ok(within > CASES / 4, `only ${within} of ${CASES} cases were attenuations`);
  assert.ok(allowedByChild > CASES, `only ${allowedByChild} requests were allowed by a child`);
});

// ---------------------------------------------------------------- globMatch

// The reference: textbook recursive wildcard matching, '*' = any (possibly empty) run.
function refGlob(p, s) {
  if (!p.length) return !s.length;
  if (p[0] === '*') return refGlob(p.slice(1), s) || (s.length > 0 && refGlob(p, s.slice(1)));
  return s.length > 0 && p[0] === s[0] && refGlob(p.slice(1), s.slice(1));
}

// Regex metacharacters are in the alphabet on purpose: globMatch must escape them.
// Line terminators are left out: see the report on globMatch and '\n'.
const GLOB_ALPHA = ['a', 'b', '.', '+', '?', '(', ')', '[', ']', '^', '$', '\\', '|', '{', '}', '-', ' ', 'é'];

test('property: globMatch agrees with a reference matcher', () => {
  forAll('glob', (r, i) => {
    const p = Array.from({ length: r.int(0, 6) }, () => (r.chance(0.3) ? '*' : r.pick(GLOB_ALPHA))).join('');
    const s = r.chance(0.5) ? concrete(r, p, [...GLOB_ALPHA, '*']) : r.str([...GLOB_ALPHA, '*'], 6);
    assert.equal(globMatch(p, s), refGlob(p, s), `seed ${SEED} case ${i}: globMatch(${JSON.stringify(p)}, ${JSON.stringify(s)})`);
  });
  assert.equal(globMatch('a*', 5), false, 'non-strings never match');
});

// ---------------------------------------------------------------- canonical

const KEYS = ['a', 'b', 'id', 'type', 'é', 'with space', '"q"', '10', '2', 'constructor', 'toString', ''];

function value(r, depth = 0) {
  const kind = depth > 3 ? r.int(0, 3) : r.int(0, 5);
  switch (kind) {
    case 0: return r.pick([null, true, false]);
    case 1: return r.pick([0, -0, 1, -7, 3.25, 1e21, 2 ** 53 + 2, 1 / 3]);
    case 2: return r.str(['a', '"', '\\', '\n', 'é', '😀', ' ', '\u0000'], 4);
    case 3: return r.int(-100, 100);
    // Arrays never hold undefined: see the report on canonical([undefined]).
    case 4: return Array.from({ length: r.int(0, 3) }, () => value(r, depth + 1));
    default: {
      const o = {};
      for (const k of r.subset(KEYS)) o[k] = r.chance(0.1) ? undefined : value(r, depth + 1);
      return o;
    }
  }
}

function reorder(r, v) {
  if (Array.isArray(v)) return v.map((x) => reorder(r, x));
  if (v === null || typeof v !== 'object') return v;
  const o = {};
  for (const k of r.shuffle(Object.keys(v))) o[k] = reorder(r, v[k]);
  return o;
}

test('property: canonical() is stable under key order and a JSON round trip', () => {
  forAll('canonical', (r, i) => {
    const v = value(r);
    const c = canonical(v);
    const why = `seed ${SEED} case ${i}: ${c}`;
    assert.equal(canonical(reorder(r, v)), c, why);
    assert.equal(canonical(JSON.parse(JSON.stringify(v))), c, why);
    assert.equal(canonical(JSON.parse(c)), c, why);
  });
});

// ---------------------------------------------------------------- signatures

test('property: flipping any byte of a sealed body or its signature breaks verifySealed', async () => {
  const signer = await Signer.generate();
  const r0 = prng(SEED);
  const sealed = [];
  for (let i = 0; i < 8; i++) {
    const body = { type: 'Intent', n: i, params: { amount: r0.int(0, 9999), note: r0.str(['a', 'é', '"', ' '], 6) }, list: [1, 'two', null, { x: true }] };
    sealed.push(await signer.seal(body));
  }
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let bodyTried = 0;
  const r = prng(SEED ^ 0xb17);
  for (let i = 0; i < CASES; i++) {
    const obj = r.pick(sealed);
    const { proof, ...body } = obj;
    const xor = r.int(1, 255);
    if (r.chance(0.5)) {
      const sig = unb64u(proof.sig);
      sig[r.int(0, sig.length - 1)] ^= xor;
      assert.equal(await verifySealed({ ...body, proof: { ...proof, sig: b64u(sig) } }), false, `seed ${SEED} case ${i}: flipped signature byte still verifies`);
      continue;
    }
    const bytes = utf8(canonical(body));
    bytes[r.int(0, bytes.length - 1)] ^= xor;
    let forged;
    try { forged = JSON.parse(decoder.decode(bytes)); } catch { continue; } // not even an object any more
    if (forged === null || typeof forged !== 'object' || Array.isArray(forged)) continue;
    bodyTried++;
    assert.notEqual(canonical(forged), canonical(body), 'a one-byte change must change the canonical form');
    assert.equal(await verifySealed({ ...forged, proof }), false, `seed ${SEED} case ${i}: ${canonical(forged)} verifies under the original signature`);
  }
  assert.ok(bodyTried > 100, `only ${bodyTried} body flips produced parseable objects`);
});
