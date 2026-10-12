import { connect } from './backend.js';
import { $, $$, gsap, toast, reducedMotion, short, cssVar } from './dom.js';
import { drawGuilloche, keyBytes, repaintSigils } from './sigil.js';
import * as checkpoint from './views/checkpoint.js';
import * as registry from './views/registry.js';
import * as mandates from './views/mandates.js';
import * as cosign from './views/cosign.js';
import * as ledger from './views/ledger.js';
import * as reasoning from './views/reasoning.js';
import * as keys from './views/keys.js';
import * as integrations from './views/integrations.js';
import { createTour } from './tour.js';

const VIEWS = { checkpoint, registry, mandates, cosign, ledger, keys, integrations, reasoning };
const TICK_MS = 2600;

const app = {
  backend: null,
  snap: null,
  view: null,
  viewEl: null,
  live: true,
  busy: false,
  decisions: [], // full decision records, newest last, for the desk and feed
  listeners: new Set(),
};

const ctx = {
  app,
  toast,
  go: (name) => { location.hash = '#' + name; },
  refresh: () => refreshSnapshot(true),
  onDecision: (fn) => { app.listeners.add(fn); return () => app.listeners.delete(fn); },
  agentByDid: (did) => app.snap?.world.agents.find((a) => a.did === did),
  agentByKey: (key) => app.snap?.world.agents.find((a) => a.key === key),
  nameOf: (did) => {
    if (!did) return 'unknown';
    const a = app.snap?.world.agents.find((x) => x.did === did);
    if (a) return a.name;
    const p = app.snap?.principals.find((x) => x.did === did);
    return p ? p.name : short(did);
  },
  tour: (from) => app.tour?.start(from),
  touring: () => !!app.tour?.active,
  setLive: (on) => {
    app.live = on;
    $('#liveToggle').setAttribute('aria-pressed', String(on));
  },
  // Runs a backend call with the live loop paused, so the result isn't buried.
  async run(fn) {
    app.busy = true;
    try { return await fn(app.backend); } finally { app.busy = false; refreshSnapshot(); }
  },
};

async function boot() {
  applySavedTheme();
  app.backend = await connect();
  app.backend.on(onEvent);
  await refreshSnapshot(true);
  // Seed the desk with a little real traffic so the first view shows the system working.
  for (let i = 0; i < 6; i++) await app.backend.tick();
  await refreshSnapshot(true);
  paintChrome();
  wireChrome();
  route();
  window.addEventListener('hashchange', route);
  app.tour = createTour(ctx);
  if (new URLSearchParams(location.search).has('tour')) app.tour.start();
  setInterval(liveTick, TICK_MS);
}

async function liveTick() {
  if (!app.live || app.busy || document.hidden) return;
  app.busy = true;
  try { await app.backend.tick(); } catch (e) { console.warn(e); } finally { app.busy = false; }
}

function onEvent(ev) {
  if (ev.type === 'decision') {
    app.decisions.push(ev.data);
    if (app.decisions.length > 200) app.decisions.shift();
    app.listeners.forEach((fn) => fn(ev.data));
  }
  if (ev.type === 'reset') {
    app.decisions = [];
    refreshSnapshot(true).then(() => { paintChrome(); route(); });
    return;
  }
  refreshSnapshot();
}

let snapTimer = null;
let snapInflight = null;
function refreshSnapshot(now = false) {
  clearTimeout(snapTimer);
  const run = async () => {
    snapInflight = (async () => {
      app.snap = await app.backend.snapshot();
      updateChrome();
      app.viewEl?.refresh?.(app.snap);
    })();
    return snapInflight;
  };
  if (now) return run();
  snapTimer = setTimeout(run, 180);
  return Promise.resolve();
}

function route() {
  const name = (location.hash.slice(1) || 'checkpoint').split('/')[0];
  const mod = VIEWS[name] || checkpoint;
  const key = VIEWS[name] ? name : 'checkpoint';
  app.viewEl?.destroy?.();
  const main = $('#view');
  const el = mod.render(ctx);
  main.replaceChildren(el);
  app.view = key;
  app.viewEl = el;
  for (const a of $$('.spine a')) a.classList.toggle('active', a.dataset.view === key);
  if (gsap && !reducedMotion()) gsap.fromTo(el, { y: 14, opacity: 0.35 }, { y: 0, opacity: 1, duration: 0.45, ease: 'power3.out', clearProps: 'transform' });
  el.mounted?.();
  main.focus({ preventScroll: true });
  window.scrollTo({ top: 0 });
}

// ---------------------------------------------------------------- chrome

let lastHeight = -1;
function updateChrome() {
  const s = app.snap;
  if (!s) return;
  const authEl = $('#authDid');
  authEl.textContent = short(s.authority.did);
  authEl.title = s.authority.did;
  if (s.ledger.height !== lastHeight) {
    lastHeight = s.ledger.height;
    $('#ledgerHeight').textContent = '#' + s.ledger.height;
    const head = $('#ledgerHead');
    if (gsap?.plugins?.scrambleText && !reducedMotion()) gsap.to(head, { duration: 0.5, scrambleText: { text: s.ledger.head.slice(0, 12), chars: '0123456789abcdef', speed: 0.6 } });
    else head.textContent = s.ledger.head.slice(0, 12);
  }
  const pending = s.approvals.filter((a) => a.status === 'pending').length;
  const badge = $('#cosignBadge');
  badge.hidden = pending === 0;
  if (badge.textContent !== String(pending) && pending && gsap && !reducedMotion()) gsap.fromTo(badge, { scale: 1.6 }, { scale: 1, duration: 0.4, ease: 'back.out(3)' });
  badge.textContent = pending;
  const p = s.principals.find((x) => x.did === s.world?.principal.did);
  const frozen = !!p?.frozen;
  if ($('#app').classList.contains('is-frozen') !== frozen) {
    $('#app').classList.toggle('is-frozen', frozen);
    if (frozen && gsap && !reducedMotion()) gsap.fromTo('#freezeBanner', { scale: 1.4 }, { scale: 1, duration: 0.5, ease: 'back.out(3)' });
  }
  $('#modeLabel').textContent = app.backend.mode === 'server' ? 'Node server' : 'In this tab';
  $('#modeChip').title = app.backend.mode === 'server'
    ? 'The authority runs in the Node server; this console talks to it over HTTP and server-sent events.'
    : 'No server found, so the full authority runs inside this tab with real Ed25519 keys. Run npm start for the server version.';
}

function paintChrome() {
  const did = app.snap.authority.did;
  const bytes = keyBytes(did);
  const ink = cssVar('--intaglio');
  const accent = cssVar('--rosette');

  const mark = $('#brandMark');
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  mark.width = mark.height = 44 * dpr;
  const mctx = mark.getContext('2d');
  mctx.clearRect(0, 0, mark.width, mark.height);
  drawGuilloche(mctx, mark.width / 2, mark.height / 2, mark.width / 2 - 1, bytes, { ink, accent, detail: 0.45 });

  const ros = $('#paperRosette');
  const size = Math.round(Math.min(900, Math.max(window.innerWidth, window.innerHeight) * 0.78) * dpr);
  ros.width = ros.height = size;
  const rctx = ros.getContext('2d');
  rctx.clearRect(0, 0, size, size);
  drawGuilloche(rctx, size / 2, size / 2, size / 2 - 2, bytes, { ink, accent, detail: 1.4, alpha: 0.16 });
  if (gsap && !reducedMotion() && !ros.dataset.spinning) {
    ros.dataset.spinning = '1';
    gsap.to(ros, { rotation: 360, duration: 360, ease: 'none', repeat: -1 });
  }
}

function wireChrome() {
  const live = $('#liveToggle');
  live.addEventListener('click', () => {
    app.live = !app.live;
    live.setAttribute('aria-pressed', String(app.live));
    toast(app.live ? 'Live traffic resumed.' : 'Live traffic paused. Attacks still run on demand.');
  });
  $('#tourBtn').addEventListener('click', () => (app.tour.active ? app.tour.stop() : app.tour.start()));
  $('#freezeBanner').addEventListener('click', () => ctx.go('keys'));
  const uv = $('#uvToggle');
  uv.setAttribute('aria-pressed', String(isDark()));
  uv.addEventListener('click', () => {
    const next = isDark() ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('agentid-theme', next); } catch { /* storage may be blocked */ }
    uv.setAttribute('aria-pressed', String(next === 'dark'));
    if (gsap && !reducedMotion()) gsap.fromTo('#app', { filter: 'brightness(1.8) saturate(0)' }, { filter: 'brightness(1) saturate(1)', duration: 0.6, ease: 'power2.out', clearProps: 'filter' });
    requestAnimationFrame(() => { paintChrome(); repaintSigils(); app.viewEl?.themeChanged?.(); });
  });
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { paintChrome(); repaintSigils(); });
}

function isDark() {
  const t = document.documentElement.dataset.theme;
  if (t) return t === 'dark';
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function applySavedTheme() {
  try {
    const t = localStorage.getItem('agentid-theme');
    if (t === 'dark' || t === 'light') document.documentElement.dataset.theme = t;
  } catch { /* storage may be blocked */ }
}

boot().catch((e) => {
  console.error(e);
  $('#boot').innerHTML = '';
  const p = document.createElement('p');
  p.className = 'boot-line';
  p.textContent = e?.name === 'NotSupportedError' || /Ed25519/i.test(String(e))
    ? 'This browser cannot generate Ed25519 keys with WebCrypto. Open the console in a current Chrome, Edge, Firefox or Safari.'
    : 'The console could not start: ' + (e?.message || e);
  $('#boot').append(p);
});
