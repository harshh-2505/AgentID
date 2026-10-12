// Tiny DOM helpers. No framework: views are functions that return elements.

export const gsap = window.gsap;
if (gsap) {
  gsap.registerPlugin(...[window.ScrambleTextPlugin, window.Flip, window.DrawSVGPlugin, window.SplitText].filter(Boolean));
}

export const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export function h(tag, props, ...children) {
  const [name, ...cls] = tag.split('.');
  const el = document.createElement(name || 'div');
  if (cls.length) el.className = cls.join(' ');
  applyProps(el, props);
  append(el, isProps(props) ? children : [props, ...children]);
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
export function s(tag, props, ...children) {
  const [name, ...cls] = tag.split('.');
  const el = document.createElementNS(SVG_NS, name);
  if (cls.length) el.setAttribute('class', cls.join(' '));
  applyProps(el, props);
  append(el, isProps(props) ? children : [props, ...children]);
  return el;
}

function applyProps(el, props) {
  if (!isProps(props)) return;
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'text') el.textContent = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
}

// The second argument may be props or already the first child.
function isProps(p) {
  return p !== null && p !== undefined && typeof p === 'object' && !Array.isArray(p) && !(p instanceof Node);
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export const money = (n, cur = 'USD') => (cur === 'USD' ? '$' : '') + Number(n).toLocaleString('en-US', { maximumFractionDigits: 0 }) + (cur === 'USD' ? '' : ' ' + cur);
export const clock = (ms) => new Date(ms).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
export const ago = (ms) => {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.round(s / 60) + 'm ago';
  return Math.round(s / 3600) + 'h ago';
};
export const short = (did) => (did ? did.slice(12, 16) + '·' + did.slice(16, 20) + '·' + did.slice(-4) : '—');

export const VERDICT = { allow: 'Cleared', step_up: 'Held', deny: 'Refused' };

export function paramsLine(params = {}) {
  const p = { ...params };
  const parts = [];
  if (typeof p.amount === 'number') { parts.push(money(p.amount, p.currency)); delete p.amount; delete p.currency; }
  for (const [k, v] of Object.entries(p)) parts.push(`${k}=${v}`);
  return parts.join(' · ');
}

let toastTimer;
export function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  clearTimeout(toastTimer);
  if (gsap && !reducedMotion()) gsap.to(el, { y: '0%', yPercent: 0, opacity: 1, duration: 0.35, ease: 'power3.out', x: '-50%', transform: 'translate(-50%, 0)' });
  else Object.assign(el.style, { opacity: 1, transform: 'translate(-50%, 0)' });
  toastTimer = setTimeout(() => {
    if (gsap && !reducedMotion()) gsap.to(el, { opacity: 0, duration: 0.3, transform: 'translate(-50%, 140%)' });
    else el.style.opacity = 0;
  }, 3200);
}

// replaceChildren that skips null/false, like h() does.
export function fill(el, ...children) {
  el.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
  return el;
}
