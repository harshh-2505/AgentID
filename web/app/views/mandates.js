// III. Mandates: what each agent may do, how much is spent, and live delegation.

import { h, gsap, reducedMotion, money, toast } from '../dom.js';

const OPTIONS = [
  { id: 'read', title: 'Read invoices', cap: { action: 'invoices.read', resource: 'erp:northwind/*' } },
  { id: 'payOne', title: 'Pay Acme Supply, up to $200 a payment', cap: { action: 'payments.send', resource: 'vendor:acme-supply', limits: { amount: { max: 200 }, currency: { in: ['USD'] } } } },
  { id: 'payAny', title: 'Pay any vendor, up to $5,000 a payment', tag: 'wider than Ledgerline', cap: { action: 'payments.send', resource: 'vendor:*', limits: { amount: { max: 5000 }, currency: { in: ['USD'] } } } },
  { id: 'payroll', title: 'Run payroll', tag: 'outside Ledgerline’s mandate', cap: { action: 'payroll.run', resource: 'hr:*' } },
];

const form = { picked: new Set(['read', 'payOne']), budget: 1000, result: null };

export function render(ctx) {
  const { app } = ctx;
  const treeEl = h('div.mandate-tree');
  const resultSlot = h('div', { 'aria-live': 'polite' });

  const root = h('div.mandates',
    h('div.section-head',
      h('div',
        h('span.label.kicker', {}, 'Authorization'),
        h('h1', {}, 'Authority is ', h('em', {}, 'granted,'), ' never assumed.'),
      ),
      h('p', {}, 'A mandate is a signed grant: which actions, on which resources, within which limits, budget, rate and time. An agent can hand part of its mandate to a sub-agent, never more. Budgets count every sub-agent’s spending against every mandate above it.'),
    ),
    h('div.mandates-grid', treeEl, delegatePanel()),
  );

  function drawTree(animate) {
    const snap = app.snap;
    const byParent = new Map();
    for (const m of snap.mandates) {
      const k = m.parent || 'root';
      if (!byParent.has(k)) byParent.set(k, []);
      byParent.get(k).push(m);
    }
    const out = [];
    const walk = (m, depth) => {
      out.push(visa(m, depth));
      for (const c of byParent.get(m.id) || []) walk(c, depth + 1);
    };
    for (const m of byParent.get('root') || []) walk(m, 0);
    treeEl.replaceChildren(...out);
    if (animate && gsap && !reducedMotion()) {
      gsap.from(out, { y: 14, opacity: 0, duration: 0.45, stagger: 0.06, ease: 'power2.out', clearProps: 'all' });
      for (const bar of treeEl.querySelectorAll('.meter i')) gsap.from(bar, { width: 0, duration: 0.9, ease: 'power3.out', delay: 0.2 });
    }
  }

  function visa(m, depth) {
    const holder = ctx.nameOf(m.sub);
    const issuer = ctx.nameOf(m.iss);
    const now = Date.now() / 1000;
    const budget = m.budget
      ? h('div',
        h('span.label', {}, 'Budget'),
        h('span.v', {}, `${money(m.spent)} spent${m.reserved ? ` · ${money(m.reserved)} held` : ''} of ${money(m.budget.amount)}`),
        h('div.meter', { title: 'Spent, then held for co-sign' },
          h('i', { style: { width: pct(m.spent, m.budget.amount) } }),
          h('i.reserved', { style: { left: pct(m.spent, m.budget.amount), width: pct(m.reserved, m.budget.amount) } }),
        ))
      : h('div', h('span.label', {}, 'Budget'), h('span.v', {}, 'No spending allowed'));
    return h('section.sheet.visa' + (depth ? '.child' : ''), { 'data-id': m.id },
      h('div.visa-head',
        h('div',
          h('h3', {}, m.label || m.id),
          h('div.who', {}, `${issuer} → ${holder}`, depth ? ' · delegated' : ''),
        ),
        h('span.verdict.v-' + m.status, {}, m.status),
      ),
      h('div.table-wrap',
        h('table.caps',
          h('thead', h('tr', h('th.label', {}, 'Action'), h('th.label', {}, 'Resource'), h('th.label', {}, 'Limits'))),
          h('tbody', m.caps.map((c) => h('tr', h('td', {}, c.action), h('td', {}, c.resource), h('td', {}, limitsText(c.limits))))),
        ),
      ),
      h('div.visa-meta',
        budget,
        h('div', h('span.label', {}, 'Rate'), h('span.v', {}, m.rate ? `${m.rate.max} per ${m.rate.windowSec}s` : 'unlimited')),
        h('div', h('span.label', {}, 'Co-sign'), h('span.v', {}, cosignText(m.cosign))),
        h('div', h('span.label', {}, 'Expires'), h('span.v', {}, `in ${Math.max(0, Math.round((m.exp - now) / 86400))} days${m.depth ? ` · may delegate ${m.depth} level` : ''}`)),
      ),
    );
  }

  function delegatePanel() {
    const opts = OPTIONS.map((o) => {
      const input = h('input', { type: 'checkbox', id: 'opt-' + o.id, checked: form.picked.has(o.id) });
      input.addEventListener('change', () => { input.checked ? form.picked.add(o.id) : form.picked.delete(o.id); });
      return h('label.opt', { for: 'opt-' + o.id },
        input,
        h('span', {},
          h('b', {}, o.title, o.tag ? h('span.tag', {}, o.tag) : null),
          h('code', {}, `${o.cap.action} on ${o.cap.resource}${o.cap.limits ? ' · ' + limitsText(o.cap.limits) : ''}`),
        ),
      );
    });
    const budgetInput = h('input', { id: 'delegate-budget', type: 'number', min: '0', step: '100', value: String(form.budget), inputmode: 'numeric' });
    budgetInput.addEventListener('input', () => { form.budget = Number(budgetInput.value || 0); });
    const submit = h('button.btn', { type: 'submit' }, 'Sign and submit as Ledgerline');
    const f = h('form.sheet.delegate',
      h('span.label', {}, 'Try a delegation'),
      h('h2', {}, 'Ledgerline → Quill'),
      h('p', { style: { color: 'var(--ink-2)', fontSize: 'var(--step--1)' } }, 'Ledgerline signs a new mandate for its sub-agent with its own key. The authority accepts it only if every capability fits inside what Ledgerline holds.'),
      h('div.opts', opts),
      h('div.field', h('label.label', { for: 'delegate-budget' }, 'Budget (USD)'), budgetInput),
      h('div', submit),
      resultSlot,
    );
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      const caps = OPTIONS.filter((o) => form.picked.has(o.id)).map((o) => o.cap);
      if (!caps.length) { showResult({ ok: false, reason: 'Pick at least one capability.' }); return; }
      submit.disabled = true;
      try {
        const r = await ctx.run((b) => b.delegate({ from: 'ledgerline', to: 'quill', caps, budget: { amount: form.budget, currency: 'USD' }, label: 'Delegated from console' }));
        showResult(r);
        if (r.ok) toast('Quill now holds the new mandate.');
      } catch (err) {
        showResult({ ok: false, reason: err.message });
      } finally {
        submit.disabled = false;
      }
    });
    if (form.result) showResult(form.result, false);
    return f;
  }

  function showResult(r, animate = true) {
    form.result = r;
    const el = r.ok
      ? h('div.result.ok', h('b', {}, 'Accepted'), h('span', {}, `Mandate ${r.id} is on the ledger. Quill’s requests are now checked against it, and against every mandate above it.`))
      : h('div.result.bad', h('b', {}, 'Refused by the authority'), h('span', {}, cleanReason(r.reason)));
    resultSlot.replaceChildren(el);
    if (animate && gsap && !reducedMotion()) {
      gsap.fromTo(el, { y: 8, opacity: 0 }, { y: 0, opacity: 1, duration: 0.35, ease: 'power2.out' });
      if (!r.ok) gsap.fromTo(el, { x: -6 }, { x: 0, duration: 0.5, ease: 'elastic.out(1, 0.3)' });
    }
  }

  let lastSig = '';
  const sig = (snap) => snap.mandates.map((m) => m.id + m.status + m.spent + m.reserved).join('|');
  root.mounted = () => { lastSig = sig(app.snap); drawTree(true); };
  root.refresh = (snap) => {
    const next = sig(snap);
    if (next === lastSig) return;
    const structural = next.split('|').length !== lastSig.split('|').length;
    lastSig = next;
    drawTree(structural);
  };
  return root;
}

function pct(n, d) { return d ? Math.min(100, (n / d) * 100).toFixed(2) + '%' : '0%'; }

function limitsText(limits) {
  if (!limits || !Object.keys(limits).length) return '—';
  return Object.entries(limits).map(([k, r]) => {
    if (r.max !== undefined) return `${k} ≤ ${r.max.toLocaleString('en-US')}`;
    if (r.min !== undefined) return `${k} ≥ ${r.min}`;
    if (r.in) return `${k} ∈ {${r.in.join(', ')}}`;
    if (r.match) return `${k} ~ ${r.match.join(' | ')}`;
    return k;
  }).join(' · ');
}

function cosignText(c) {
  if (!c) return 'only when risk is high';
  const parts = [];
  if (c.above !== undefined) parts.push(`above ${money(c.above)}`);
  if (c.actions) parts.push(c.actions.join(', '));
  if (c.quorum) parts.push(`${c.quorum.k} of ${c.quorum.of.length} guardians`);
  return parts.join(' · ');
}

function cleanReason(r = '') {
  return r.replace(/^mandate rejected: /, '').replace(/^./, (c) => c.toUpperCase()) + '.';
}
