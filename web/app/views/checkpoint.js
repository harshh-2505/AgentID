// I. Checkpoint: the inspection desk, live traffic, and a deck of attacks to try.

import { h, gsap, reducedMotion, short, clock, paramsLine, VERDICT, toast } from '../dom.js';
import { sigil } from '../sigil.js';

const PIN_MS = 9000;
const LIVE_DESK_MS = 5200; // the desk follows live traffic, but lets each inspection settle
const STATUS_TEXT = { pass: 'pass', fail: 'fail', hold: 'hold', warn: 'flag', skipped: '—' };

export function render(ctx) {
  const { app } = ctx;
  let selectedId = null;
  let pinnedUntil = 0;
  let deskTl = null;
  let deskShownAt = 0;

  const deskEl = h('section.sheet.desk', { 'aria-live': 'polite', 'aria-label': 'Inspection desk' });
  const feedEl = h('ul.feed', { 'aria-label': 'Recent decisions' });
  const tallyEl = h('div.tally');

  const root = h('div.checkpoint',
    h('div.hero',
      h('div',
        h('span.label.kicker', {}, 'AgentID · identity and authority for autonomous agents'),
        h('h1', {}, 'Passport control for ', h('em', {}, 'software that acts on its own.')),
        h('p.lede', {}, 'Every request an agent makes stops here first. The authority checks which key signed it, what code is running, who allowed it and within what limits, and holds anything risky for a human co-sign. Watch the live traffic, or try to break it below.'),
        h('div.hero-cta',
          h('button.btn.tour-cta', { type: 'button', onClick: () => ctx.tour() }, h('span.play', { 'aria-hidden': 'true' }), 'Take the guided tour'),
          h('span.dim', {}, '17 stops · about 3 minutes · arrow keys to move'),
        ),
      ),
      h('div.factors',
        factor('Proof of key', 'Each request is signed by a key only the agent holds. Nothing to phish, nothing to replay.'),
        factor('Proof of runtime', 'The host attests the exact model, prompt, tools and code the passport was issued for.'),
        factor('Proof of mandate', 'Signed grants that only ever narrow: scope, limits, budget, rate, expiry.'),
      ),
    ),
    h('div.desk-grid',
      deskEl,
      h('section.sheet.traffic',
        h('div.traffic-head', h('span.label', {}, 'Live traffic'), tallyEl),
        feedEl,
      ),
    ),
    h('div.attacks-head',
      h('div',
        h('span.label.kicker', {}, 'Red team'),
        h('h2', {}, 'Try to ', h('em', {}, 'break it.')),
      ),
      h('p', { style: { color: 'var(--ink-2)', maxWidth: '52ch' } }, 'Each card stages a real attack with real signatures against the same authority. The desk shows exactly which check stops it.'),
    ),
    h('div.attacks', (app.snap?.world.attacks || []).map((a) => attackCard(a))),
  );

  function factor(title, text) {
    return h('div.factor', h('b', {}, title), h('span', {}, text));
  }

  function attackCard(a) {
    const expect = h('span.a-expect', {}, a.expect);
    const btn = h('button.attack', { type: 'button', 'data-attack': a.id },
      h('span.a-title', {}, a.title),
      h('span.a-summary', {}, a.summary),
      expect,
    );
    btn.addEventListener('click', () => runAttack(a.id));
    return btn;
  }

  async function runAttack(id) {
    const a = app.snap.world.attacks.find((x) => x.id === id);
    const btn = root.querySelector(`[data-attack="${id}"]`);
    const expect = btn?.querySelector('.a-expect');
    if (btn?.disabled) return null;
    if (btn) btn.disabled = true;
    if (expect) expect.textContent = 'Running…';
    pinnedUntil = Date.now() + PIN_MS;
    try {
      const result = await ctx.run((b) => b.attack(id));
      pinnedUntil = Date.now() + PIN_MS;
      showDecision(result, true);
      const where = result.checks.find((c) => c.status === 'fail' || c.status === 'hold');
      if (expect) expect.textContent = `${VERDICT[result.decision]}${where ? ' at ' + where.label.toLowerCase() : ''} · ✓`;
      btn?.classList.add('ran');
      if (result.decision === 'step_up' && !ctx.touring()) toast(`${result.agentName}’s request is waiting in Co-sign.`);
      if (!ctx.touring()) deskEl.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
      return result;
    } catch (e) {
      if (expect) expect.textContent = 'Error: ' + e.message;
      throw e;
    } finally {
      if (btn) btn.disabled = false;
      if (expect && a && !btn?.classList.contains('ran')) expect.textContent = a.expect;
    }
  }

  // A routine, in-policy request, pinned to the desk.
  async function runNormal() {
    pinnedUntil = Date.now() + PIN_MS * 3;
    let r = null;
    for (let i = 0; i < 6 && r?.decision !== 'allow'; i++) r = await ctx.run((b) => b.tick());
    pinnedUntil = Date.now() + PIN_MS * 3;
    if (r) showDecision(r, true);
    return r;
  }

  // ------------------------------------------------------------ desk

  function showDecision(d, animate) {
    if (!d) {
      deskEl.replaceChildren(h('p.empty', {}, 'Waiting for the first request…'));
      return;
    }
    selectedId = d.id;
    deskShownAt = Date.now();
    for (const row of feedEl.children) row.classList.toggle('selected', row.dataset.id === d.id);
    deskTl?.kill();

    const agent = ctx.agentByDid(d.agent);
    const checks = d.checks.map((c) => h('li.check', { 'data-status': c.status, 'data-key': c.key },
      h('span.ck-label', {}, c.label),
      h('span.ck-detail', {}, c.detail || (c.status === 'skipped' ? 'not reached' : '')),
      h('span.ck-mark', {}, STATUS_TEXT[c.status] || c.status),
    ));
    const stamp = h('div.stamp.' + d.decision, {}, VERDICT[d.decision], h('small', {}, `ledger #${d.ledgerSeq ?? '—'} · ${clock(d.ts)}`));
    const pinned = Date.now() < pinnedUntil;
    const foot = h('div.desk-foot',
      d.decision === 'step_up'
        ? [h('span', {}, 'Nothing has executed. The request waits for a co-sign.'), h('button.btn', { type: 'button', onClick: () => ctx.go('cosign') }, 'Open co-sign desk')]
        : d.decision === 'allow'
          ? h('span', {}, `Cleared. The authority signed a receipt the ${d.action?.split('.')[0] || 'target'} service can verify offline.`)
          : h('span', {}, `Refused before anything executed. The attempt is recorded at ledger #${d.ledgerSeq}.`),
      pinned ? h('button.btn.ghost', { type: 'button', onClick: () => { pinnedUntil = 0; const last = app.decisions.at(-1); if (last) showDecision(last, true); } }, 'Resume live view') : null,
    );

    deskEl.replaceChildren(
      h('div.desk-top',
        d.agent ? sigil(d.agent, 58) : null,
        h('div.desk-agent',
          h('span.label', {}, d.via === 'cosign' ? 'Co-signed request' : 'Request under inspection'),
          h('h2', {}, d.agentName || 'Unknown agent'),
          h('div.meta', {}, [short(d.agent), agent?.model].filter(Boolean).join(' · ')),
        ),
      ),
      h('div.desk-request',
        h('span', {}, d.action || '?'), h('span.arrow', {}, '→'), h('span', {}, d.resource || '?'),
        d.params && Object.keys(d.params).length ? h('span.params', {}, paramsLine(d.params)) : null,
      ),
      d.reason ? h('p.desk-reason', {}, d.reason) : null,
      h('ol.checks', {}, checks),
      stamp,
      foot,
    );

    if (!animate || !gsap || reducedMotion()) return;
    const tl = gsap.timeline();
    deskTl = tl;
    tl.from(deskEl.querySelector('.desk-top'), { opacity: 0.2, x: -10, duration: 0.25, ease: 'power2.out' });
    tl.from(deskEl.querySelector('.desk-request'), { opacity: 0, duration: 0.2 }, '<0.05');
    checks.forEach((row, i) => {
      const c = d.checks[i];
      const mark = row.querySelector('.ck-mark');
      const detail = row.querySelector('.ck-detail');
      tl.fromTo(row, { opacity: 0.12 }, { opacity: c.status === 'skipped' ? 0.38 : 1, duration: 0.08 }, 0.25 + i * 0.085);
      if (c.status !== 'skipped' && gsap.plugins.scrambleText) {
        tl.from(mark, { duration: 0.22, scrambleText: { text: '····', chars: '01', speed: 1 } }, '<');
        if (c.detail) tl.to(detail, { duration: 0.3, scrambleText: { text: c.detail, chars: 'abcdef0123456789', revealDelay: 0.05, speed: 1.2 } }, '<');
      }
    });
    tl.fromTo(stamp, { scale: 2.6, rotation: -26, opacity: 0, filter: 'blur(3px)' }, { scale: 1, rotation: -9, opacity: 0.9, filter: 'blur(0px)', duration: 0.26, ease: 'power4.in' }, '+=0.05');
    tl.to(deskEl, { x: 3, duration: 0.05, yoyo: true, repeat: 3, ease: 'none', clearProps: 'x' });
  }

  // ------------------------------------------------------------ feed

  function feedRow(d) {
    const row = h('li.feed-row', { 'data-id': d.id, tabindex: '0', role: 'button', 'aria-label': `${d.agentName} ${d.action} ${VERDICT[d.decision]}` },
      d.agent ? sigil(d.agent, 24) : h('span'),
      h('div.fr-main',
        h('div', {}, h('span.fr-agent', {}, d.agentName || '?'), h('span.fr-time', {}, clock(d.ts))),
        h('div.fr-action', {}, `${d.action} → ${d.resource}${d.params?.amount ? ' · ' + paramsLine({ amount: d.params.amount, currency: d.params.currency }) : ''}`),
      ),
      h('span.verdict.v-' + d.decision, {}, VERDICT[d.decision]),
    );
    const open = () => { pinnedUntil = Date.now() + PIN_MS; showDecision(d, true); };
    row.addEventListener('click', open);
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
    return row;
  }

  function addToFeed(d, animate) {
    const row = feedRow(d);
    feedEl.prepend(row);
    while (feedEl.children.length > 60) feedEl.lastElementChild.remove();
    if (animate && gsap && !reducedMotion()) {
      gsap.from(row, { height: 0, opacity: 0, paddingTop: 0, paddingBottom: 0, duration: 0.35, ease: 'power2.out', clearProps: 'all' });
      gsap.fromTo(row, { backgroundColor: 'color-mix(in srgb, var(--intaglio) 18%, transparent)' }, { backgroundColor: 'transparent', duration: 1.4, clearProps: 'backgroundColor', delay: 0.2 });
    }
  }

  function updateTally() {
    const s = app.snap?.stats;
    if (!s) return;
    tallyEl.replaceChildren(
      h('span.v-allow', {}, `${s.allowed} cleared`),
      h('span.v-step_up', {}, `${s.stepUp} held`),
      h('span.v-deny', {}, `${s.denied} refused`),
    );
  }

  // Initial fill from what has already happened.
  for (const d of app.decisions.slice(-40)) addToFeed(d, false);
  showDecision(app.decisions.at(-1), false);
  updateTally();

  const off = ctx.onDecision((d) => {
    addToFeed(d, true);
    const settled = Date.now() - deskShownAt > LIVE_DESK_MS || d.decision !== 'allow';
    if (Date.now() >= pinnedUntil && settled) showDecision(d, true);
  });

  root.mounted = () => {
    if (!gsap || reducedMotion() || !window.SplitText) return;
    const title = root.querySelector('.hero h1');
    (document.fonts?.ready || Promise.resolve()).then(() => {
      const split = new window.SplitText(title, { type: 'words' });
      gsap.from(split.words, { yPercent: 60, opacity: 0, duration: 0.7, ease: 'power3.out', stagger: 0.04, onComplete: () => split.revert() });
    });
    gsap.from(root.querySelectorAll('.factor'), { y: 10, opacity: 0, duration: 0.5, stagger: 0.08, delay: 0.2, ease: 'power2.out', clearProps: 'all' });
    gsap.from(root.querySelectorAll('.attack'), { y: 16, opacity: 0, duration: 0.5, stagger: 0.05, delay: 0.3, ease: 'power2.out', clearProps: 'all' });
    const last = app.decisions.at(-1);
    if (last) showDecision(last, true);
  };
  root.refresh = () => updateTally();
  root.api = { runAttack, runNormal, desk: deskEl };
  root.destroy = () => { off(); deskTl?.kill(); };
  return root;
}
