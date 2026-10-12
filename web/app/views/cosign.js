// IV. Co-sign: the agent-native second factor. Held requests wait for a principal's signature.

import { h, gsap, reducedMotion, money, ago, paramsLine, short, toast } from '../dom.js';
import { sigil } from '../sigil.js';

export function render(ctx) {
  const { app } = ctx;
  const listEl = h('div.cosign-grid');
  const histEl = h('div');
  let lastSig = '';
  let animating = false;

  const root = h('div.cosign',
    h('div.section-head',
      h('div',
        h('span.label.kicker', {}, 'Step-up'),
        h('h1', {}, 'A second factor ', h('em', {}, 'for software.')),
      ),
      h('p', {}, 'An agent can’t be trusted to read a code off your phone: anything it can read, an injected prompt can read too. So risky requests wait here instead, and the agent gets a receipt only after a principal signs this exact request with their own key, or a quorum of guardian agents does.'),
    ),
    listEl,
    h('section.history', h('h2', {}, 'Recently decided'), histEl),
  );

  function draw(animate) {
    const snap = app.snap;
    const pending = snap.approvals.filter((a) => a.status === 'pending');
    const done = snap.approvals.filter((a) => a.status !== 'pending').slice(0, 12);
    lastSig = snap.approvals.map((a) => a.id + a.status).join('|');

    if (!pending.length) {
      listEl.replaceChildren(h('div.sheet.empty', {},
        'Nothing is waiting for you. ',
        h('button.btn.ghost', { type: 'button', onClick: stageHold, style: { marginLeft: '8px', fontStyle: 'normal' } }, 'Stage a large payment'),
      ));
    } else {
      listEl.replaceChildren(...pending.map(card));
      if (animate && gsap && !reducedMotion()) gsap.from(listEl.children, { y: 18, opacity: 0, duration: 0.45, stagger: 0.07, ease: 'power2.out', clearProps: 'all' });
    }
    histEl.replaceChildren(...(done.length ? done.map((a) => h('div.hist-row',
      h('span.mono', { style: { color: 'var(--ink-3)' } }, ago(a.closedAt || a.createdAt)),
      h('span', {}, h('b', {}, a.agentName), ` ${a.action} → ${a.resource}${a.amount ? ' · ' + money(a.amount) : ''}${a.note ? ' · ' + a.note : ''}`),
      h('span.verdict.v-' + a.status, {}, a.status),
    )) : [h('p', { style: { color: 'var(--ink-3)' } }, 'No decisions yet.')]));
  }

  function card(ap) {
    const principal = app.snap.world.principal;
    const actions = h('div.request-actions');
    const sign = h('button.btn', { type: 'button' }, 'Co-sign');
    const decline = h('button.btn.ghost', { type: 'button' }, 'Decline');
    actions.append(sign, decline);
    const el = h('article.sheet.request', { 'data-id': ap.id },
      h('div.request-head',
        sigil(ap.agent, 44),
        h('div', {},
          h('span.label', {}, `Held ${ago(ap.createdAt)}`),
          h('h3', {}, ap.agentName),
        ),
      ),
      h('div.mono', {}, `${ap.action} → ${ap.resource}`),
      ap.amount ? h('div.amount', {}, money(ap.amount)) : (ap.params && Object.keys(ap.params).length ? h('div.mono', { style: { color: 'var(--ink-2)' } }, paramsLine(ap.params)) : null),
      ap.reason ? h('p.desk-reason', {}, ap.reason) : null,
      h('div', h('span.label', {}, 'Held because'), h('div.why', { style: { marginTop: '6px' } }, ap.reasons.map((r) => h('span', {}, r)))),
      ap.risk?.factors?.length ? h('div.risk-bars',
        h('span.label', {}, `Risk signals · score ${ap.risk.score}`),
        ap.risk.factors.map((f) => h('div.risk-bar',
          h('span', {}, f.label),
          h('span.track', h('i', { style: { width: Math.min(100, f.points * 2) + '%' } })),
          h('span.pts', {}, '+' + f.points),
        )),
      ) : null,
      h('p.signing-note', {}, `Co-signing creates an Ed25519 signature by ${principal.name} (key ${short(principal.did)}) over request hash ${ap.intentHash.slice(0, 16)}…. It cannot be reused for any other request.`),
      actions,
    );
    const go = async (decision) => {
      sign.disabled = decline.disabled = true;
      animating = true;
      try {
        const r = await ctx.run((b) => b.approve(ap.id, decision));
        const stamp = h('div.stamp.' + (r.status === 'approved' ? 'allow' : 'deny'), {}, r.status === 'approved' ? 'Co-signed' : 'Declined');
        el.append(stamp);
        if (gsap && !reducedMotion()) {
          await gsap.fromTo(stamp, { scale: 2.4, opacity: 0, rotation: -24 }, { scale: 1, opacity: 0.9, rotation: -9, duration: 0.26, ease: 'power4.in' });
          await gsap.to(el, { opacity: 0, y: -10, duration: 0.35, delay: 0.5 });
        }
        toast(r.status === 'approved' ? `${ap.agentName} received a signed receipt and the action ran.` : `Declined. ${ap.agentName} was told no, and the held budget was released.`);
        animating = false;
        await ctx.refresh();
        draw(false);
      } catch (e) {
        animating = false;
        toast(e.message);
        sign.disabled = decline.disabled = false;
      }
    };
    sign.addEventListener('click', () => go('approve'));
    decline.addEventListener('click', () => go('decline'));
    return el;
  }

  async function stageHold() {
    await ctx.run((b) => b.attack('cosign'));
    await ctx.refresh();
    draw(true);
  }

  root.mounted = () => draw(true);
  root.refresh = (snap) => {
    const next = snap.approvals.map((a) => a.id + a.status).join('|');
    if (next !== lastSig && !animating) draw(true);
  };
  return root;
}
