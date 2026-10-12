// II. Passports: the trust graph and each agent's passport, with revocation.

import { h, s, gsap, reducedMotion, short, toast } from '../dom.js';
import { sigil } from '../sigil.js';

let selectedKey = 'ledgerline';

export function render(ctx) {
  const { app } = ctx;
  let confirming = false;
  let lastSig = '';
  const graphWrap = h('div.sheet.graph-wrap');
  const listEl = h('div.agent-list');
  const cardSlot = h('div');

  const root = h('div.registry',
    h('div.section-head',
      h('div',
        h('span.label.kicker', {}, 'Identity'),
        h('h1', {}, 'Every agent carries a ', h('em', {}, 'passport.')),
      ),
      h('p', {}, 'A passport binds an agent’s public key to the organisation that vouches for it and to the exact runtime it was issued for. Sub-agents get passports from their parent agent, so every identity chains back to a principal. The engraved face is drawn from the agent’s key.'),
    ),
    h('div.registry-grid',
      h('div', graphWrap, listEl),
      cardSlot,
    ),
  );

  function signature(snap) {
    return snap.world.agents.map((a) => a.key + a.status).join('|') + snap.passports.length;
  }

  function draw(animate) {
    const snap = app.snap;
    lastSig = signature(snap);
    drawGraph(animate);
    listEl.replaceChildren(...snap.world.agents.map((a) => {
      const pp = snap.passports.find((p) => p.id === a.passport);
      const row = h('button.agent-row' + (a.key === selectedKey ? '.selected' : ''), { type: 'button' },
        sigil(a.did, 34),
        h('div', {}, h('div.ar-name', {}, a.name), h('div.ar-sub', {}, a.purpose)),
        h('span.verdict.v-' + a.status, {}, a.status === 'active' ? (pp?.parent ? 'sub-agent' : 'active') : a.status),
      );
      row.addEventListener('click', () => { selectedKey = a.key; confirming = false; draw(false); animateCard(); });
      return row;
    }));
    cardSlot.replaceChildren(passportCard());
  }

  function drawGraph(animate) {
    const snap = app.snap;
    const W = 640, H = 330;
    const principal = snap.world.principal;
    const host = snap.world.host;
    const agents = snap.world.agents;
    const ppOf = (a) => snap.passports.find((p) => p.id === a.passport);
    const top = agents.filter((a) => !ppOf(a)?.parent);
    const subs = agents.filter((a) => ppOf(a)?.parent);
    const pos = {};
    pos[principal.did] = { x: 90, y: 120 };
    pos[host.did] = { x: 90, y: 262 };
    top.forEach((a, i) => { pos[a.did] = { x: 330, y: 50 + i * ((H - 90) / Math.max(1, top.length - 1)) }; });
    subs.forEach((a, i) => {
      const parentDid = snap.passports.find((p) => p.id === ppOf(a).parent)?.sub;
      pos[a.did] = { x: 545, y: (pos[parentDid]?.y ?? 80) + i * 60 };
    });

    const edges = [];
    const curve = (a, b) => `M${a.x + 26},${a.y} C${(a.x + b.x) / 2},${a.y} ${(a.x + b.x) / 2},${b.y} ${b.x - 26},${b.y}`;
    for (const a of agents) {
      const pp = ppOf(a);
      if (!pp) continue;
      const from = pos[pp.iss];
      if (!from) continue;
      const revoked = a.status === 'revoked';
      edges.push(s('path.edge' + (revoked ? '.revoked' : ''), { d: curve(from, pos[a.did]) }));
      edges.push(s('path.edge.mandate' + (revoked ? '.revoked' : ''), { d: curve({ x: from.x, y: from.y + 5 }, { x: pos[a.did].x, y: pos[a.did].y + 5 }) }));
    }
    edges.push(s('path.edge', { d: `M90,146 L90,236`, 'stroke-dasharray': '2 4' }));

    const node = (did, label, sub, cls, onClick) => {
      const p = pos[did];
      const img = sigil(did, 48).toDataURL();
      const g = s('g.node' + cls, { transform: `translate(${p.x},${p.y})`, 'data-did': did, tabindex: '0', role: 'button', 'aria-label': label },
        s('circle.ring', { r: 26 }),
        s('image', { href: img, x: -22, y: -22, width: 44, height: 44 }),
        s('text.node-label', { x: 0, y: 44, 'text-anchor': 'middle' }, label),
        s('text.node-sub', { x: 0, y: 58, 'text-anchor': 'middle' }, sub),
      );
      if (onClick) {
        g.addEventListener('click', onClick);
        g.addEventListener('keydown', (e) => { if (e.key === 'Enter') onClick(); });
      }
      return g;
    };

    const svg = s('svg.graph', { viewBox: `0 0 ${W} ${H + 40}`, role: 'img', 'aria-label': 'Trust graph from Northwind Labs to its agents' },
      s('text.col-label', { x: 90, y: 14, 'text-anchor': 'middle' }, 'PRINCIPAL'),
      s('text.col-label', { x: 330, y: 14, 'text-anchor': 'middle' }, 'AGENTS'),
      s('text.col-label', { x: 545, y: 14, 'text-anchor': 'middle' }, 'SUB-AGENTS'),
      ...edges,
      node(principal.did, principal.name, short(principal.did), '', null),
      node(host.did, 'Runtime host', 'attests code', '', null),
      ...agents.map((a) => node(a.did, a.name, a.model, (a.key === selectedKey ? '.selected' : '') + (a.status === 'revoked' ? '.revoked' : ''), () => { selectedKey = a.key; confirming = false; draw(false); animateCard(); })),
    );
    graphWrap.replaceChildren(svg);
    root._pos = pos;
    if (animate && gsap && !reducedMotion() && gsap.plugins.drawSVG) {
      gsap.from(svg.querySelectorAll('.edge'), { drawSVG: '0%', duration: 1.1, ease: 'power2.inOut', stagger: 0.06 });
      gsap.from(svg.querySelectorAll('.node'), { scale: 0.4, opacity: 0, transformOrigin: '50% 50%', duration: 0.5, ease: 'back.out(2)', stagger: 0.05 });
    }
  }

  function pulse(d) {
    const svg = graphWrap.querySelector('svg');
    const p = root._pos?.[d.agent];
    if (!svg || !p || !gsap || reducedMotion()) return;
    const color = d.decision === 'allow' ? 'var(--ok)' : d.decision === 'deny' ? 'var(--deny)' : 'var(--hold)';
    const ring = s('circle.pulse', { cx: p.x, cy: p.y, r: 26, style: `stroke:${color}` });
    svg.append(ring);
    gsap.to(ring, { attr: { r: 52 }, opacity: 0, duration: 1.1, ease: 'power2.out', onComplete: () => ring.remove() });
  }

  function passportCard() {
    const snap = app.snap;
    const a = snap.world.agents.find((x) => x.key === selectedKey) || snap.world.agents[0];
    const pp = snap.passports.find((p) => p.id === a.passport);
    if (!pp) return h('p.empty', {}, 'No passport on file.');
    const issuer = ctx.nameOf(pp.iss);
    const revoked = a.status === 'revoked';
    const children = snap.passports.filter((p) => p.parent === pp.id);

    const card = h('article.passport', { 'aria-label': `Passport of ${a.name}` },
      h('div.foil', { 'aria-hidden': 'true' }),
      h('div.pp-head',
        h('h3', {}, 'Agent passport', h('br'), 'Northwind Labs · AgentID'),
        h('span.pp-no', {}, pp.id.toUpperCase()),
      ),
      h('div.pp-body',
        sigil(a.did, 136, { detail: 1 }),
        h('div.pp-fields',
          h('div.f.wide', h('span.label', {}, 'Name'), h('div.pp-name', {}, a.name)),
          field('Purpose', a.purpose, true),
          field('Model', a.model),
          field('Issued by', issuer + (pp.parent ? ' (parent agent)' : '')),
          field('Date of issue', new Date(pp.iat * 1000).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })),
          field('Expiry', new Date(pp.exp * 1000).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })),
          field('Runtime measurement', pp.runtime.measurement.slice(0, 24) + '…', true, true),
          h('div.f.wide', h('span.label', {}, 'Declared tools'), h('div.pp-tools', pp.runtime.tools.map((t) => h('code', {}, t)))),
          field('Identifier', a.did, true, true),
        ),
      ),
      h('div.mrz', { 'aria-label': 'Machine readable zone' }, mrz(pp, a).split('\n').map((l) => h('div.mrz-line', {}, l))),
      revoked ? h('div.void-mark', { 'aria-hidden': 'true' }, h('span', {}, 'VOID')) : null,
    );

    const actions = h('div.pp-actions');
    if (revoked) {
      const rev = snap.revoked.find((r) => r.target === a.did || r.target === pp.id || snap.passports.some((p) => p.id === pp.parent && (r.target === p.sub || r.target === p.id)));
      actions.append(h('span', { style: { color: 'var(--deny)', fontSize: 'var(--step--1)' } }, `Revoked${rev?.reason ? ': ' + rev.reason : ''}. Every request from this key now fails at the passport check.`));
      actions.append(h('button.btn.ghost', { type: 'button', onClick: () => resetDemo() }, 'Reset demo organisation'));
    } else if (confirming) {
      actions.append(h('div.confirm-row',
        h('span', {}, children.length ? `This also voids ${children.map((c) => c.name).join(', ')}, which ${a.name} issued.` : `${a.name} stops working everywhere at once.`),
        h('button.btn.danger', { type: 'button', onClick: () => doRevoke(a) }, `Revoke ${a.name}`),
        h('button.btn.ghost', { type: 'button', onClick: () => { confirming = false; draw(false); } }, 'Cancel'),
      ));
    } else {
      actions.append(h('button.btn.ghost', { type: 'button', onClick: () => { confirming = true; draw(false); } }, 'Revoke passport'));
      actions.append(h('span', { style: { color: 'var(--ink-3)', fontSize: 'var(--step--1)' } }, 'Signed by the principal key; takes effect on the next request.'));
    }

    attachFoil(card);
    return h('div', {}, card, actions);
  }

  function field(label, value, wide = false, mono = false) {
    return h('div.f' + (wide ? '.wide' : ''), h('span.label', {}, label), h('span.v' + (mono ? '.mono' : ''), {}, value));
  }

  function attachFoil(card) {
    if (reducedMotion() || !gsap) return;
    const rx = gsap.quickTo(card, 'rotationX', { duration: 0.5, ease: 'power3.out' });
    const ry = gsap.quickTo(card, 'rotationY', { duration: 0.5, ease: 'power3.out' });
    gsap.set(card, { transformPerspective: 900 });
    card.addEventListener('pointermove', (e) => {
      const r = card.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width;
      const py = (e.clientY - r.top) / r.height;
      card.style.setProperty('--fx', px * 100 + '%');
      card.style.setProperty('--fy', py * 100 + '%');
      card.style.setProperty('--foil-angle', Math.round(px * 220) + 'deg');
      rx((0.5 - py) * 7);
      ry((px - 0.5) * 9);
    });
    card.addEventListener('pointerleave', () => { rx(0); ry(0); });
  }

  function animateCard() {
    if (!gsap || reducedMotion()) return;
    const card = cardSlot.querySelector('.passport');
    gsap.fromTo(card, { rotationY: -14, opacity: 0.4 }, { rotationY: 0, opacity: 1, duration: 0.55, ease: 'power3.out' });
    gsap.from(card.querySelectorAll('.pp-fields .f'), { opacity: 0, y: 6, stagger: 0.03, duration: 0.3, delay: 0.1 });
    if (gsap.plugins.scrambleText) {
      for (const line of card.querySelectorAll('.mrz-line')) {
        gsap.from(line, { duration: 0.9, scrambleText: { text: '<'.repeat(line.textContent.length), chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<', speed: 0.8 } });
      }
    }
  }

  async function doRevoke(a) {
    try {
      const res = await ctx.run((b) => b.revoke(a.key, 'Revoked by operator from the console'));
      confirming = false;
      await ctx.refresh();
      draw(false);
      const others = res.agents.length - 1;
      toast(`Revoked ${a.name}${others > 0 ? ` and ${others} sub-agent${others > 1 ? 's' : ''}` : ''}. Logged on the ledger.`);
      const mark = cardSlot.querySelector('.void-mark span');
      if (mark && gsap && !reducedMotion()) {
        gsap.fromTo(mark, { scale: 3, opacity: 0, rotation: -40 }, { scale: 1, opacity: 1, rotation: -18, duration: 0.3, ease: 'power4.in' });
        gsap.fromTo(cardSlot.querySelector('.passport'), { x: -4 }, { x: 0, duration: 0.4, ease: 'elastic.out(1, 0.3)' });
      }
    } catch (e) {
      toast('Could not revoke: ' + e.message);
    }
  }

  async function resetDemo() {
    await ctx.run((b) => b.reset());
    toast('Fresh organisation issued: new keys, passports and mandates.');
  }

  const off = ctx.onDecision(pulse);
  root.mounted = () => { draw(true); animateCard(); };
  root.refresh = (snap) => { if (signature(snap) !== lastSig) draw(false); };
  root.themeChanged = () => draw(false);
  root.destroy = () => off();
  return root;
}

// ICAO 9303-style machine readable zone, with real check digits.
function mrz(pp, a) {
  const clean = (x) => String(x).toUpperCase().replace(/[^A-Z0-9]/g, '<');
  const pad = (x, n) => (x + '<'.repeat(n)).slice(0, n);
  const yymmdd = (sec) => { const d = new Date(sec * 1000); return String(d.getUTCFullYear()).slice(2) + String(d.getUTCMonth() + 1).padStart(2, '0') + String(d.getUTCDate()).padStart(2, '0'); };
  const line1 = pad('AP<NWL' + clean(a.name) + '<<' + clean(a.model), 44);
  const doc = pad(clean(pp.id.replace('pp_', '')), 9);
  const meas = clean(pp.runtime.measurement.slice(0, 14));
  const exp = yymmdd(pp.exp);
  const body = doc + check(doc) + 'NWL' + yymmdd(pp.iat) + check(yymmdd(pp.iat)) + 'X' + exp + check(exp) + meas;
  const line2 = pad(body, 43) + check(body);
  return line1 + '\n' + line2;
}

function check(str) {
  const w = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    const v = c === '<' ? 0 : /[0-9]/.test(c) ? Number(c) : c.charCodeAt(0) - 55;
    sum += v * w[i % 3];
  }
  return String(sum % 10);
}
