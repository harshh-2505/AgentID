// The guided tour: a scripted walk through what AgentID does, driving the real console.
// Every step runs a real action against the authority; the spotlight shows the result.

import { h, gsap, reducedMotion, $ } from './dom.js';
import * as passkey from './passkey.js';

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(fn, timeout = 4000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const v = fn();
    if (v) return v;
    await wait(60);
  }
  return null;
}

// Each step: chapter, title, body, optional view, run (async action), target (selector).
function steps(ctx) {
  const view = () => ctx.app.viewEl;
  const attack = (id) => async () => { await until(() => view()?.api?.runAttack); return view().api.runAttack(id); };
  return [
    { chapter: 'Welcome', title: 'Software is starting to act on its own.', body: 'Northwind Labs runs four AI agents: Ledgerline pays invoices, Quill reads them, Courier books travel and Scout does research. Today most agents borrow a human’s login and API keys. This tour shows the alternative: agents with their own identity, their own limits, and a human second factor only where it matters. Every step runs for real in this page.', next: 'Start the tour' },
    { chapter: 'Identity', view: 'registry', target: '.graph-wrap', title: 'Every agent gets its own identity.', body: 'Each agent generated its own Ed25519 key pair. Northwind Labs vouches for it with a signed passport, and Ledgerline vouched for its sub-agent Quill. No shared passwords, no human session cookies: the chain of trust is visible and every link is a signature.' },
    { chapter: 'Identity', view: 'registry', target: '.passport', title: 'A passport, not a borrowed login.', body: 'The passport binds the agent’s key to who is accountable for it and to the exact runtime it was issued for: model, system prompt, tools and code, hashed into one measurement. If any of those change, the passport no longer matches.' },
    { chapter: 'Authority', view: 'mandates', target: '.visa', title: 'A mandate says exactly what it may do.', body: 'Ledgerline may send payments to vendors, up to $1,500 each, $250,000 in total, 120 per minute, and anything above $750 needs a co-sign. When it delegates to Quill, the authority checks that Quill’s mandate is strictly narrower. Authority can only shrink as it is handed down.' },
    { chapter: 'The checkpoint', view: 'checkpoint', run: async () => { await until(() => view()?.api?.runNormal); return view().api.runNormal(); }, target: '.desk', title: 'Every action passes ten checks first.', body: 'Here an agent asked to do something routine. Before anything executes, the authority checks the signature, freshness, passport chain, runtime, mandate chain, scope, limits, budget, behaviour and whether a co-sign is needed. It clears, and the agent gets a signed receipt the target service verifies offline.' },
    { chapter: 'Attacks', view: 'checkpoint', run: attack('forged'), target: '.desk .check[data-status="fail"]', title: 'A stolen name is not a stolen key.', body: 'Someone claims to be Ledgerline and asks to pay an offshore account. They know its identifier but not its private key, so the very first check fails. Nothing to phish, no password to reuse.' },
    { chapter: 'Attacks', view: 'checkpoint', run: attack('injection'), target: '.desk .check[data-status="fail"]', title: 'Prompt injection can’t widen permissions.', body: 'A poisoned web page told Scout to email the customer table outside the company. Scout really did sign the request, so identity passes, but its mandate only allows mail to @northwind.example. The model can be fooled; the mandate can’t.' },
    { chapter: 'Attacks', view: 'checkpoint', run: attack('tamper'), target: '.desk .check[data-status="fail"]', title: 'Changed code means a changed identity.', body: 'Courier’s host quietly loaded an extra shell tool. The runtime measurement no longer matches the one on the passport, so the request is refused even though the key and the mandate are fine.' },
    { chapter: 'Second factor', view: 'checkpoint', run: attack('cosign'), target: '.desk', title: 'Risky requests wait for a human.', body: 'Ledgerline wants to pay $1,180, above its $750 co-sign line. The authority holds it. This is two-factor authentication rebuilt for agents: the agent can’t approve itself, and nothing runs until a person signs this exact request.' },
    { chapter: 'Second factor', view: 'cosign', target: '.request', title: 'The co-sign desk.', body: 'The held request shows what, why, and the risk signals behind it. An approval is a signature over the hash of this one request, so it can’t be replayed for a different amount or payee.' },
    { chapter: 'Second factor', view: 'cosign', run: async () => {
      const ap = ctx.app.snap.approvals.find((a) => a.status === 'pending' && a.agentName === 'Ledgerline') || ctx.app.snap.approvals.find((a) => a.status === 'pending');
      if (!ap) return null;
      const r = await ctx.run((b) => passkey.decide(b, ctx.app.snap, ap.id, 'approve', { virtual: true }));
      await ctx.refresh();
      return r;
    }, target: '.history', title: 'Approved with a passkey.', body: 'The approval was signed by a passkey with user verification: the same WebAuthn standard as Face ID or a YubiKey. An agent can read a one-time code from your inbox; it cannot press your fingerprint. (In this demo the passkey is a virtual authenticator, verified by exactly the same code.)' },
    { chapter: 'Control', view: 'keys', run: async () => { await ctx.run((b) => b.freeze(true, 'Tour: suspicious activity')); await ctx.refresh(); }, target: '.killswitch', title: 'One signature freezes every agent.', body: 'Something looks wrong at 3 a.m. One signed Freeze statement makes the authority refuse every request from every agent and sub-agent Northwind vouches for, and declines anything waiting. No servers to find, no keys to hunt down.' },
    { chapter: 'Control', view: 'keys', run: async () => { await ctx.run((b) => b.freeze(false, 'Tour: all clear')); await ctx.run((b) => b.recoverRoot()); await ctx.refresh(); await wait(200); view()?.api?.animateRecovery(); }, target: '.guardians', title: 'Lost keys are recoverable, safely.', body: 'Agents are thawed. Now suppose Northwind’s root key is lost. Two of three guardians sign a key update: the old root is marked compromised, a new one takes over, and the organisation keeps the same identity. Everything the lost key signed is distrusted.' },
    { chapter: 'Control', view: 'keys', target: '.agentkeys', title: 'Agent keys are short-lived.', body: 'Rotating an agent’s key issues a new passport that supersedes the old one. The old key is retired automatically, so a key leaked in a log file is useless. Try “Leaked old key” on the Checkpoint afterwards.' },
    { chapter: 'Accountability', view: 'ledger', target: '.chain', title: 'A ledger nobody can edit quietly.', body: 'Every decision, approval, freeze and key change is a signed entry chained to the one before. Edit one character and the verifier names the exact entry where the chain breaks.' },
    { chapter: 'Accountability', view: 'keys', run: async () => { const r = await ctx.app.backend.witness(); const { inclusion } = await ctx.app.backend.checkpoint(); await ctx.refresh(); view()?.api?.drawTransparency({ ...r, inclusion }); }, target: '.transparency', title: 'And witnesses keep the authority honest.', body: 'The ledger is also a Merkle tree, like Certificate Transparency. The authority signs a checkpoint; an independent witness co-signs it only if it extends the history it saw before. A service proves its receipt is in the log with a few hashes.' },
    { chapter: 'Fits your stack', view: 'integrations', target: '.int-grid', title: 'It plugs into what you already run.', body: 'An MCP gateway puts every tool call through the checkpoint. Receipts exchange for standard OAuth tokens, passports export as W3C Verifiable Credentials, approvals arrive in Slack, decisions stream to your SIEM, and partner organisations’ agents are trusted only for what you agreed.' },
    { chapter: 'Done', title: 'That’s AgentID.', body: 'Agents prove who they are with their own keys, act only within signed mandates, run only the code they were approved for, and ask a human only when it matters. Everything is signed, logged and revocable in one step. Explore any section freely, or try the attacks yourself on the Checkpoint.', next: 'Explore on my own' },
  ];
}

export function createTour(ctx) {
  let i = 0;
  let list = [];
  let active = false;
  let running = false;
  let target = null;
  let wasLive = true;

  const spot = h('div.tour-spot');
  const chapterEl = h('span.label');
  const countEl = h('span.tour-count.mono');
  const titleEl = h('h2');
  const bodyEl = h('p');
  const prev = h('button.btn.ghost', { type: 'button' }, 'Back');
  const next = h('button.btn', { type: 'button' }, 'Next');
  const exit = h('button.tour-x', { type: 'button', 'aria-label': 'Exit tour' }, '×');
  const bar = h('div.tour-bar');
  const card = h('div.tour-card', { role: 'dialog', 'aria-modal': 'false', 'aria-label': 'Guided tour' },
    h('div.tour-meta', chapterEl, countEl, exit),
    titleEl, bodyEl,
    h('div.tour-actions', prev, next),
    bar,
  );
  const shade = h('div.tour-shade');
  const layer = h('div.tour', { hidden: true }, shade, spot, card);
  document.body.append(layer);

  prev.addEventListener('click', () => go(i - 1));
  next.addEventListener('click', () => (i >= list.length - 1 ? stop() : go(i + 1)));
  exit.addEventListener('click', () => stop());
  window.addEventListener('keydown', (e) => {
    if (!active) return;
    if (e.key === 'Escape') stop();
    else if (e.key === 'ArrowRight' && !running) next.click();
    else if (e.key === 'ArrowLeft' && !running && i > 0) prev.click();
  });
  const follow = () => { if (active) place(false); };
  window.addEventListener('resize', follow);
  window.addEventListener('scroll', follow, { passive: true });

  function drawBar() {
    bar.replaceChildren(...list.map((_, k) => h('i' + (k < i ? '.done' : k === i ? '.now' : ''))));
  }

  async function go(n) {
    if (running || n < 0 || n >= list.length) return;
    running = true;
    i = n;
    const st = list[i];
    chapterEl.textContent = st.chapter;
    countEl.textContent = `${String(i + 1).padStart(2, '0')} / ${list.length}`;
    prev.disabled = i === 0;
    next.disabled = true;
    next.textContent = st.run ? 'Running…' : st.next || (i === list.length - 1 ? 'Finish' : 'Next');
    drawBar();
    if (gsap && !reducedMotion()) gsap.to([titleEl, bodyEl], { opacity: 0, y: -6, duration: 0.15 });
    try {
      if (st.view && ctx.app.view !== st.view) {
        ctx.go(st.view);
        await until(() => ctx.app.view === st.view && ctx.app.viewEl?.isConnected);
        await wait(450);
      }
      if (st.run) await st.run();
      target = st.target ? await until(() => $(st.target), 3000) : null;
      if (target) {
        // On phones the card covers the bottom of the screen, so put the target just under the top bar.
        if (window.innerWidth < 760) window.scrollTo({ top: window.scrollY + target.getBoundingClientRect().top - 120, behavior: reducedMotion() ? 'auto' : 'smooth' });
        else target.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'center' });
        await wait(reducedMotion() ? 50 : 420);
      }
    } catch (e) {
      console.warn('tour step failed', e);
    }
    titleEl.textContent = st.title;
    bodyEl.textContent = st.body;
    next.textContent = st.next || (i === list.length - 1 ? 'Finish' : 'Next');
    next.disabled = false;
    place(true);
    if (gsap && !reducedMotion()) gsap.fromTo([titleEl, bodyEl], { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.35, stagger: 0.06, ease: 'power2.out' });
    else Object.assign(titleEl.style, { opacity: 1 }), Object.assign(bodyEl.style, { opacity: 1 });
    running = false;
    next.focus({ preventScroll: true });
  }

  function place(animate) {
    const mobile = window.innerWidth < 760;
    const pad = 10;
    let rect = null;
    if (target?.isConnected) {
      const r = target.getBoundingClientRect();
      const vh = window.innerHeight;
      rect = { x: r.left - pad, y: Math.max(8, r.top - pad), w: r.width + pad * 2, h: Math.min(r.height + pad * 2, vh - 16) };
    }
    layer.classList.toggle('centered', !rect);
    const spotTo = rect
      ? { left: rect.x, top: rect.y, width: rect.w, height: rect.h, opacity: 1 }
      : { left: window.innerWidth / 2, top: window.innerHeight / 2, width: 0, height: 0, opacity: 0 };
    // Card: beside the target when there is room, otherwise along the bottom.
    const cw = Math.min(400, window.innerWidth - 32);
    let cardTo;
    if (mobile || !rect) {
      cardTo = rect || mobile ? { left: (window.innerWidth - cw) / 2, top: window.innerHeight - card.offsetHeight - 16 } : { left: (window.innerWidth - cw) / 2, top: Math.max(16, (window.innerHeight - card.offsetHeight) / 2) };
    } else {
      const right = rect.x + rect.w + 18;
      const left = rect.x - cw - 18;
      const top = Math.min(Math.max(16, rect.y), window.innerHeight - card.offsetHeight - 16);
      if (right + cw < window.innerWidth - 12) cardTo = { left: right, top };
      else if (left > 12) cardTo = { left, top };
      else cardTo = { left: (window.innerWidth - cw) / 2, top: rect.y + rect.h + 16 + card.offsetHeight < window.innerHeight ? rect.y + rect.h + 16 : Math.max(16, rect.y - card.offsetHeight - 16) };
    }
    card.style.width = cw + 'px';
    if (gsap && !reducedMotion() && animate) {
      gsap.to(spot, { ...px(spotTo), duration: 0.55, ease: 'power3.inOut' });
      gsap.to(card, { ...px(cardTo), duration: 0.55, ease: 'power3.inOut' });
    } else {
      Object.assign(spot.style, pxs(spotTo));
      Object.assign(card.style, pxs(cardTo));
    }
  }

  const px = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, k === 'opacity' ? v : v + 'px']));
  const pxs = px;

  function start(from = 0) {
    if (active) return;
    active = true;
    list = steps(ctx);
    wasLive = ctx.app.live;
    ctx.setLive(false);
    layer.hidden = false;
    document.documentElement.classList.add('touring');
    if (gsap && !reducedMotion()) gsap.fromTo(card, { opacity: 0, y: 20 }, { opacity: 1, y: 0, duration: 0.4 });
    i = -1;
    running = false;
    go(from);
  }

  function stop() {
    if (!active) return;
    active = false;
    target = null;
    const done = () => { layer.hidden = true; document.documentElement.classList.remove('touring'); };
    if (gsap && !reducedMotion()) gsap.to([card, spot], { opacity: 0, duration: 0.25, onComplete: () => { done(); gsap.set([card, spot], { opacity: 1 }); } });
    else done();
    ctx.setLive(wasLive);
  }

  return { start, stop, get active() { return active; } };
}
