// V. Ledger: the hash chain, a real verifier, and a tamper experiment.

import { h, gsap, reducedMotion, clock, toast } from '../dom.js';
import { verifyChain } from '../../core/ledger.js';

const SHOW = 36;

export function render(ctx) {
  const { app } = ctx;
  let entries = [];      // full chain as fetched
  let tampered = null;   // { seq, copy } when the operator edits an entry
  let selected = null;
  let verifying = false;

  const chainEl = h('div.chain', { role: 'list', 'aria-label': 'Ledger entries' });
  const statusEl = h('span.ledger-status', { 'aria-live': 'polite' }, 'Not verified yet in this view.');
  const detailEl = h('section.sheet.entry-detail');
  const verifyBtn = h('button.btn', { type: 'button' }, 'Verify the whole chain');
  const tamperBtn = h('button.btn.ghost', { type: 'button' }, 'Edit an entry');
  const restoreBtn = h('button.btn.ghost', { type: 'button', hidden: true }, 'Undo my edit');

  const root = h('div.ledger',
    h('div.section-head',
      h('div',
        h('span.label.kicker', {}, 'Accountability'),
        h('h1', {}, 'Every decision, ', h('em', {}, 'chained.')),
      ),
      h('p', {}, 'Each entry carries the hash of the entry before it and the authority’s signature. Change one character anywhere and the verifier names the exact entry where the chain stops matching. Try it: edit an entry, then verify.'),
    ),
    h('div.ledger-tools', verifyBtn, tamperBtn, restoreBtn, statusEl),
    chainEl,
    detailEl,
  );

  async function load() {
    const height = app.snap.ledger.height;
    entries = await app.backend.ledger({ from: 0, limit: Math.max(500, height) });
    if (entries.length < height) {
      // Pull the rest in pages; the verifier needs the full chain.
      while (entries.length < height) entries = entries.concat(await app.backend.ledger({ from: entries.length, limit: 500 }));
    }
  }

  const working = () => tampered?.copy || entries;

  function drawChain(animate) {
    const list = working().slice(-SHOW);
    chainEl.replaceChildren(...list.map((e) => {
      const b = h('div.block' + (tampered?.seq === e.seq ? '.tampered' : '') + (selected === e.seq ? '.scanning' : ''), { role: 'listitem', tabindex: '0', 'data-seq': e.seq },
        h('span.b-seq', {}, '#' + e.seq),
        h('span.b-kind', {}, e.kind.replace('.', ' ')),
        h('span', { style: { color: 'var(--ink-2)' } }, summary(e)),
        h('span.b-hash', {}, 'hash ' + e.hash.slice(0, 16)),
        h('span.b-hash', {}, 'prev ' + e.prev.slice(0, 16)),
      );
      const pick = () => { selected = e.seq; drawDetail(); for (const x of chainEl.children) x.classList.toggle('scanning', Number(x.dataset.seq) === e.seq); };
      b.addEventListener('click', pick);
      b.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') pick(); });
      return b;
    }));
    chainEl.scrollLeft = chainEl.scrollWidth;
    if (animate && gsap && !reducedMotion()) gsap.from(chainEl.children, { x: 30, opacity: 0, duration: 0.4, stagger: 0.015, ease: 'power2.out', clearProps: 'all' });
  }

  function summary(e) {
    const d = e.data || {};
    if (e.kind.startsWith('intent.')) return `${ctx.nameOf(d.agent)} · ${d.action}${d.amount ? ' · $' + d.amount : ''}`;
    if (e.kind === 'revoked') return `${ctx.nameOf(d.target)} · ${d.agents} agent(s)`;
    return d.name || ctx.nameOf(d.agent || d.sub || d.did) || '';
  }

  function drawDetail() {
    const e = working().find((x) => x.seq === selected) || working().at(-1);
    if (!e) { detailEl.replaceChildren(h('p.empty', {}, 'The ledger is empty.')); return; }
    detailEl.replaceChildren(
      h('span.label', {}, `Entry #${e.seq} · ${clock(e.ts)}${tampered?.seq === e.seq ? ' · edited in this view' : ''}`),
      h('pre', {}, JSON.stringify(e, null, 2)),
    );
  }

  verifyBtn.addEventListener('click', async () => {
    if (verifying) return;
    verifying = true;
    verifyBtn.disabled = tamperBtn.disabled = true;
    try {
      if (!tampered) await load();
      const chain = working();
      const result = await verifyChain(chain, app.snap.authority.did);
      if (!tampered) drawChain(false);
      const blocks = [...chainEl.children];
      const first = chain.length - blocks.length;
      blocks.forEach((b) => b.classList.remove('verified', 'broken', 'scanning'));
      const brokenIdx = result.ok ? -1 : result.brokenAt - first;
      if (gsap && !reducedMotion()) {
        const tl = gsap.timeline();
        blocks.forEach((b, i) => {
          tl.call(() => {
            b.classList.add('scanning');
            b.scrollIntoView({ block: 'nearest', inline: 'nearest' });
          }, null, i * 0.045);
          tl.call(() => {
            b.classList.remove('scanning');
            b.classList.add(brokenIdx >= 0 && i >= brokenIdx ? 'broken' : 'verified');
          }, null, i * 0.045 + 0.06);
        });
        await tl;
        if (brokenIdx >= 0) gsap.fromTo(blocks[brokenIdx], { x: -6 }, { x: 0, duration: 0.6, ease: 'elastic.out(1, 0.25)' });
      } else {
        blocks.forEach((b, i) => b.classList.add(brokenIdx >= 0 && i >= brokenIdx ? 'broken' : 'verified'));
      }
      statusEl.style.color = result.ok ? 'var(--ok)' : 'var(--deny)';
      statusEl.textContent = result.ok
        ? `Intact. ${result.checked} entries recomputed and every authority signature checked.`
        : `Broken at entry #${result.brokenAt}: ${result.reason}. Every entry after it is no longer trustworthy.`;
    } finally {
      verifying = false;
      verifyBtn.disabled = false;
      tamperBtn.disabled = Boolean(tampered);
    }
  });

  tamperBtn.addEventListener('click', async () => {
    if (verifying) return;
    verifying = true;
    verifyBtn.disabled = tamperBtn.disabled = true;
    try { await load(); } finally { verifying = false; verifyBtn.disabled = false; }
    const copy = structuredClone(entries);
    const candidates = copy.filter((e) => e.kind === 'intent.allow' && e.data.amount);
    const target = candidates.length > 3 ? candidates[candidates.length - 4] : copy[Math.max(0, copy.length - 6)];
    if (target.data.amount) target.data.amount = Math.round(target.data.amount / 10);
    else target.data.note = 'edited';
    tampered = { seq: target.seq, copy };
    selected = target.seq;
    restoreBtn.hidden = false;
    tamperBtn.disabled = true;
    drawChain(false);
    drawDetail();
    statusEl.style.color = 'var(--hold)';
    statusEl.textContent = `You lowered the amount in entry #${target.seq} (a local copy only). Now verify.`;
    toast(`Entry #${target.seq} edited in this view. The real ledger is untouched.`);
  });

  restoreBtn.addEventListener('click', async () => {
    tampered = null;
    restoreBtn.hidden = true;
    tamperBtn.disabled = false;
    await load();
    drawChain(false);
    drawDetail();
    statusEl.style.color = '';
    statusEl.textContent = 'Edit discarded. Showing the authority’s ledger.';
  });

  root.mounted = async () => {
    await load();
    drawChain(true);
    drawDetail();
  };
  let lastHeight = 0;
  root.refresh = async (snap) => {
    if (tampered || verifying || snap.ledger.height === lastHeight) return;
    lastHeight = snap.ledger.height;
    await load();
    drawChain(false);
    if (selected === null) drawDetail();
  };
  return root;
}
