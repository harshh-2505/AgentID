// Capabilities, limits and attenuation.
//
// A capability is { action, resource, limits }. `action` and `resource` are patterns
// where a trailing `*` matches any suffix ("payments.*", "vendor:acme/*").
// `limits` constrain the intent's params, one rule per param:
//   { max: n } { min: n } { in: [..] } { match: ["*@acme.example", ..] }
// A param named in limits but missing from the intent fails closed.

const regexCache = new Map();
function globRegex(pattern) {
  let re = regexCache.get(pattern);
  if (!re) {
    re = new RegExp('^' + pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
    regexCache.set(pattern, re);
  }
  return re;
}

export function globMatch(pattern, value) {
  if (typeof value !== 'string') return false;
  if (pattern === '*') return true;
  return globRegex(pattern).test(value);
}

// Is every value `child` can match also matched by `parent`? Treating the child's
// own stars as literal text is sound here: a parent star can absorb them, a parent
// literal character never can.
export function patternWithin(child, parent) {
  return globMatch(parent, child);
}

export function checkLimits(limits = {}, params = {}) {
  const violations = [];
  for (const [key, rule] of Object.entries(limits)) {
    const v = params[key];
    if (v === undefined || v === null) {
      violations.push(`${key} is required but missing`);
      continue;
    }
    if (rule.max !== undefined && !(typeof v === 'number' && v <= rule.max)) violations.push(`${key} ${v} exceeds max ${rule.max}`);
    if (rule.min !== undefined && !(typeof v === 'number' && v >= rule.min)) violations.push(`${key} ${v} is below min ${rule.min}`);
    if (rule.in && !rule.in.includes(v)) violations.push(`${key} "${v}" is not one of ${rule.in.join(', ')}`);
    if (rule.match && !rule.match.some((p) => globMatch(p, String(v)))) violations.push(`${key} "${v}" does not match ${rule.match.join(', ')}`);
  }
  return violations;
}

// Child limits must be at least as strict as the parent's, rule by rule.
export function limitsWithin(child = {}, parent = {}) {
  const problems = [];
  for (const [key, p] of Object.entries(parent)) {
    const c = child[key];
    if (!c) { problems.push(`drops the "${key}" limit`); continue; }
    if (p.max !== undefined && !(c.max !== undefined && c.max <= p.max)) problems.push(`raises ${key} max above ${p.max}`);
    if (p.min !== undefined && !(c.min !== undefined && c.min >= p.min)) problems.push(`lowers ${key} min below ${p.min}`);
    if (p.in && !(c.in && c.in.every((x) => p.in.includes(x)))) problems.push(`widens ${key} beyond ${p.in.join(', ')}`);
    if (p.match && !(c.match && c.match.every((cp) => p.match.some((pp) => patternWithin(cp, pp))))) problems.push(`widens ${key} pattern beyond ${p.match.join(', ')}`);
  }
  return problems;
}

export function capWithin(child, parent) {
  if (!patternWithin(child.action, parent.action)) return [`action ${child.action} is outside ${parent.action}`];
  if (!patternWithin(child.resource, parent.resource)) return [`resource ${child.resource} is outside ${parent.resource}`];
  return limitsWithin(child.limits, parent.limits);
}

// Every child capability must fit inside at least one parent capability.
export function capsWithin(childCaps, parentCaps) {
  const problems = [];
  for (const c of childCaps) {
    let best = null;
    for (const p of parentCaps) {
      const issues = capWithin(c, p);
      if (!issues.length) { best = null; break; }
      if (!best || issues.length < best.length) best = issues;
    }
    if (best) problems.push(`${c.action} on ${c.resource}: ${best[0]}`);
  }
  return problems;
}

// Finds the capability that authorises an action. Distinguishes "nothing in scope"
// from "in scope but a limit failed" so the verifier can explain itself.
export function authorize(caps, action, resource, params) {
  const inScope = caps.filter((c) => globMatch(c.action, action) && globMatch(c.resource, resource));
  if (!inScope.length) return { ok: false, stage: 'scope', reason: `no capability covers ${action} on ${resource}` };
  let firstViolations = null;
  for (const cap of inScope) {
    const v = checkLimits(cap.limits, params);
    if (!v.length) return { ok: true, cap };
    firstViolations ??= v;
  }
  return { ok: false, stage: 'limits', reason: firstViolations.join('; '), violations: firstViolations };
}
