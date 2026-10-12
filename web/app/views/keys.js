// VII. Keys & trust: what happens when keys are lost, stolen or simply old.
// Key ring, guardian recovery, passkeys, short-lived agent keys, the kill switch,
// and the transparency checkpoint that independent witnesses co-sign.

import { h, s, gsap, reducedMotion, ago, clock, short, toast } from '../dom.js';
import { sigil } from '../sigil.js';
import * as passkey from '../passkey.js';

const ROLE = {
  root: ['Root', 'Kept offline. Changes keys; nothing else.'],
  operational: ['Operational', 'Issues passports, mandates and revocations day to day.'],
  approver: ['Approver', 'Can only co-sign held requests, up to a limit.'],
};

export function render(ctx) {
  const { app } = ctx;
  const switchEl = h('section.sheet.killswitch');
  const ringEl = h('section.sheet.keyring');
  const guardEl = h('section.sheet.guardians');
  const passEl = h('section.sheet.passkeys');
  const agentEl = h('section.sheet.agentkeys');
  const transEl = h('section.sheet.transparency');
  let sig = '';
  let busy = false;
  let lastWitness = null;

  const root = h('div.keys',
    h('div.section-head',
      h('div',
        h('span.label.kicker', {}, 'Keys & trust'),
        h('h1', {}, 'Keys get lost. ', h('em', {}, 'Trust survives.')),
      ),
      h('p', {}, 'A real deployment has to survive a stolen laptop, a leaked key and a rogue agent at 3 a.m. Each control below runs against the same authority with real signatures: rotate a key, recover a lost root with guardians, approve with a passkey, or freeze every agent with one signature.'),
    ),
    h('div.keys-grid', switchEl, passEl, ringEl, guardEl, agentEl, transEl),
  );

  const principal = () => app.snap.principals.find((p) => p.did === app.snap.world.principal.did) || app.snap.principals[0];

  async function act(btn, fn, done) {
    if (busy) return;
    busy = true;
    if (btn) btn.disabled = true;
    try {
      const r = await ctx.run(fn);
      await ctx.refresh();
      draw(false);
      done?.(r);
      return r;
    } catch (e) {
      toast(e.message);
    } finally {
      busy = false;
      if (btn) btn.disabled = false;
    }
  }

  // ------------------------------------------------------------ kill switch

  function drawSwitch(animate) {
    const p = principal();
    const frozen = !!p.frozen;
    const lid = h('button.ks-lid', { type: 'button', 'aria-label': 'Lift the safety cover' }, h('span', {}, 'Lift cover'));
    const lever = h('button.ks-lever', { type: 'button', 'aria-pressed': String(frozen), disabled: !frozen },
      h('span.ks-knob'),
      h('span.ks-text', {}, frozen ? 'Thaw agents' : 'Freeze all agents'),
    );
    const housing = h('div.ks-housing' + (frozen ? '.armed' : ''), lever, frozen ? null : lid);
    lid.addEventListener('click', () => {
      lever.disabled = false;
      if (gsap && !reducedMotion()) gsap.to(lid, { rotateX: 112, transformOrigin: '50% 0%', duration: 0.5, ease: 'back.out(1.6)', onComplete: () => lid.remove() });
      else lid.remove();
      lever.focus();
    });
    lever.addEventListener('click', () => act(lever, (b) => b.freeze(!frozen, frozen ? 'Incident closed' : 'Frozen from the console'), (r) => {
      toast(r.frozen ? `Every agent under Northwind Labs is frozen.${r.declined ? ` ${r.declined} waiting request(s) declined.` : ''}` : 'Agents thawed. Requests are evaluated normally again.');
      if (gsap && !reducedMotion()) gsap.fromTo('#app', { filter: r.frozen ? 'hue-rotate(-30deg) saturate(1.8)' : 'brightness(1.4)' }, { filter: 'none', duration: 0.8, clearProps: 'filter' });
    }));
    switchEl.classList.toggle('frozen', frozen);
    switchEl.replaceChildren(
      h('div.ks-copy',
        h('span.label', {}, 'Kill switch'),
        h('h2', {}, frozen ? 'All agents are frozen.' : 'One signature stops everything.'),
        h('p', {}, frozen
          ? `Since ${clock(p.frozen.at)}. Every request from every agent and sub-agent is refused at the passport check, and anything that was waiting for a co-sign was declined. Thawing needs the same key.`
          : 'A signed Freeze statement from Northwind’s operational key makes the authority refuse every request from every agent it vouches for, instantly, without touching a single agent or server.'),
        h('div.ks-state', h('span.dot'), frozen ? 'FROZEN' : 'Armed · agents running'),
      ),
      housing,
    );
    if (animate && frozen && gsap && !reducedMotion()) gsap.from(switchEl, { boxShadow: '0 0 0 12px color-mix(in srgb, var(--deny) 40%, transparent)', duration: 1 });
  }

  // ------------------------------------------------------------ passkeys

  function drawPasskeys() {
    const p = principal();
    const virtualIds = new Set(app.snap.world.virtualPasskeys || []);
    const enrollBtn = h('button.btn', { type: 'button' }, p.passkeys.length ? 'Enroll another passkey' : 'Enroll a passkey');
    enrollBtn.addEventListener('click', () => act(enrollBtn, (b) => passkey.enroll(b), (r) => {
      toast(r.virtual ? 'Enrolled the virtual authenticator: this frame can’t reach a real passkey.' : 'Passkey enrolled. Approvals can now require your fingerprint or face.');
      const last = passEl.querySelector('.pk-row:last-of-type');
      if (last && gsap && !reducedMotion()) gsap.from(last, { x: -20, opacity: 0, duration: 0.5, ease: 'power3.out' });
    }));
    passEl.replaceChildren(
      h('span.label', {}, 'Passkeys'),
      h('h2', {}, 'Approvals your phone has to sign.'),
      h('p.note', {}, 'An agent can read a one-time code. It cannot press your fingerprint. Each approval is a WebAuthn signature over the hash of that exact request, so a phished or replayed approval is useless.'),
      p.passkeys.length
        ? h('div.pk-list', p.passkeys.map((k) => h('div.pk-row',
          h('span.pk-glyph', { 'aria-hidden': 'true' }),
          h('div', h('b', {}, k.label), h('div.mono.dim', {}, `${k.credentialId.slice(0, 14)}… · ${k.jwk?.alg || 'ES256'} · ${virtualIds.has(k.credentialId) ? 'virtual authenticator' : 'device passkey'} · added ${ago(k.addedAt)}`)),
          h('span.tag', {}, k.uv === false ? 'presence' : 'user verified'),
        )))
        : h('p.empty-inline', {}, 'No passkeys yet.'),
      h('div.row-actions', enrollBtn),
    );
  }

  // ------------------------------------------------------------ key ring

  function drawRing() {
    const p = principal();
    const rotate = h('button.btn.ghost', { type: 'button' }, 'Rotate operational key');
    rotate.addEventListener('click', () => act(rotate, (b) => b.rotateKey(), () => {
      toast('New operational key in, old one retired. Records it signed before stay valid; anything it signs from now on is refused.');
      animateNewest();
    }));
    const keys = [...p.keys].sort((a, b) => (a.removedAt ? 1 : 0) - (b.removedAt ? 1 : 0) || a.addedAt - b.addedAt);
    ringEl.replaceChildren(
      h('span.label', {}, 'Key ring · Northwind Labs'),
      h('h2', {}, 'One identity, many keys.'),
      h('p.note', {}, `The organisation’s identifier never changes (${short(p.did)}); the keys behind it do. Each key has a role, so the key on a finance lead’s phone can approve a payment but can never issue a mandate.`),
      h('div.key-cards', keys.map((k) => {
        const [title, blurb] = ROLE[k.role] || [k.role, ''];
        const state = k.compromised ? 'compromised' : k.removedAt ? 'retired' : 'active';
        return h('article.key-card.' + state, { 'data-kid': k.kid },
          sigil(k.kid, 38),
          h('div',
            h('span.label', {}, title + (k.label ? ' · ' + k.label : '')),
            h('div.mono', {}, short(k.kid)),
            h('p', {}, blurb + (k.maxAmount ? ` Limit: $${k.maxAmount.toLocaleString('en-US')}.` : '')),
          ),
          state !== 'active' ? h('span.key-stamp', {}, state) : h('span.tag.ok', {}, 'active'),
        );
      })),
      h('div.row-actions', rotate),
    );
  }

  function animateNewest() {
    const cards = [...ringEl.querySelectorAll('.key-card.active')];
    const newest = cards.at(-1);
    if (newest && gsap && !reducedMotion()) gsap.from(newest, { y: 16, opacity: 0, scale: 0.97, duration: 0.55, ease: 'back.out(1.5)' });
    const stamps = ringEl.querySelectorAll('.key-stamp');
    if (stamps.length && gsap && !reducedMotion()) gsap.from(stamps[0], { scale: 2.2, opacity: 0, rotation: -20, duration: 0.3, ease: 'power4.in' });
  }

  // ------------------------------------------------------------ guardians

  function drawGuardians(animateQuorum = false) {
    const p = principal();
    const g = app.snap.world.guardians || [];
    const k = p.recovery?.k ?? 2;
    const recover = h('button.btn.ghost', { type: 'button' }, 'Lose the root key');
    const size = 220;
    const r = 78;
    const ring = s('svg.quorum', { viewBox: `0 0 ${size} ${size}`, width: size, height: size, 'aria-hidden': 'true' },
      s('circle.q-track', { cx: size / 2, cy: size / 2, r }),
      s('circle.q-fill', { cx: size / 2, cy: size / 2, r, 'stroke-dasharray': 2 * Math.PI * r, 'stroke-dashoffset': 2 * Math.PI * r }),
    );
    const nodes = g.map((x, i) => {
      const a = -Math.PI / 2 + (i * 2 * Math.PI) / g.length;
      return h('div.g-node', { style: { left: `${size / 2 + Math.cos(a) * r}px`, top: `${size / 2 + Math.sin(a) * r}px` }, 'data-i': i },
        sigil(x.did, 46), h('span', {}, x.name));
    });
    const center = h('div.g-center', h('b', {}, `${k} of ${g.length}`), h('span', {}, 'to replace a root key'));
    recover.addEventListener('click', () => act(recover, (b) => b.recoverRoot(), (res) => {
      toast(`${res.guardians.join(' and ')} signed. The lost root key is marked compromised and a new root key took its place.`);
      animateRecovery();
    }));
    guardEl.replaceChildren(
      h('span.label', {}, 'Recovery'),
      h('h2', {}, 'Lost root key? Ask the guardians.'),
      h('p.note', {}, `No helpdesk reset, no single point of failure. Any ${k} of these ${g.length} guardians can sign a key update that retires the lost root key and installs a new one. Everything the lost key signed is distrusted.`),
      h('div.g-stage', { style: { width: size + 'px', height: size + 'px' } }, ring, ...nodes, center),
      h('div.row-actions', recover),
    );
    if (animateQuorum) animateRecovery();
  }

  function animateRecovery() {
    if (!gsap || reducedMotion()) return;
    const fill = guardEl.querySelector('.q-fill');
    const nodes = guardEl.querySelectorAll('.g-node');
    const len = Number(fill.getAttribute('stroke-dasharray'));
    const tl = gsap.timeline();
    tl.to(nodes[0], { scale: 1.18, duration: 0.25, yoyo: true, repeat: 1 })
      .to(fill, { strokeDashoffset: len * (1 - 1 / 3), duration: 0.5, ease: 'power2.out' }, '<')
      .to(nodes[1], { scale: 1.18, duration: 0.25, yoyo: true, repeat: 1 })
      .to(fill, { strokeDashoffset: len * (1 - 2 / 3), duration: 0.5, ease: 'power2.out' }, '<')
      .from(guardEl.querySelector('.g-center b'), { scale: 1.6, color: 'var(--ok)', duration: 0.5 })
      .call(() => animateNewest());
  }

  // ------------------------------------------------------------ agent keys

  function drawAgents() {
    const agents = app.snap.world.agents;
    const leaked = app.snap.world.leaked;
    agentEl.replaceChildren(
      h('span.label', {}, 'Agent keys'),
      h('h2', {}, 'Short-lived by design.'),
      h('p.note', {}, 'An agent’s key lives as long as its job. Rotating issues a new key and a passport that supersedes the old one; the old passport is retired automatically, so a key copied from a log file last week opens nothing.'),
      h('div.ak-list', agents.map((a) => {
        const pp = app.snap.passports.find((x) => x.id === a.passport);
        const can = a.key === 'scout' || a.key === 'courier';
        const btn = can ? h('button.btn.ghost.small', { type: 'button' }, 'Rotate key') : null;
        btn?.addEventListener('click', () => act(btn, (b) => b.rotateAgent(a.key), (r) => {
          toast(`${a.name} now signs with ${short(r.to)}. The old key ${short(r.from)} is retired.`);
          const row = agentEl.querySelector(`[data-key="${a.key}"]`);
          if (row && gsap && !reducedMotion()) gsap.from(row.querySelector('canvas'), { rotation: -180, scale: 0.4, duration: 0.7, ease: 'back.out(1.4)' });
        }));
        return h('div.ak-row', { 'data-key': a.key },
          sigil(a.did, 34),
          h('div', h('b', {}, a.name), h('div.mono.dim', {}, `${short(a.did)} · issued ${pp ? ago(pp.iat * 1000) : '—'}`)),
          h('span.tag.' + (a.status === 'active' ? 'ok' : 'bad'), {}, a.status),
          btn,
        );
      })),
      leaked ? h('p.leak-note', {}, `Retired key ${short(leaked.did)} (${leaked.key}) is still in the attacker’s hands in this demo. Try “Leaked old key” on the Checkpoint.`) : null,
    );
  }

  // ------------------------------------------------------------ transparency

  function drawTransparency(proofData) {
    const wit = app.snap.ledger.witnessed || [];
    const btn = h('button.btn', { type: 'button' }, 'Publish a checkpoint & witness it');
    btn.addEventListener('click', async () => {
      if (busy) return;
      busy = true;
      btn.disabled = true;
      try {
        const w = await app.backend.witness();
        const { inclusion } = await app.backend.checkpoint();
        lastWitness = { ...w, inclusion };
        await ctx.refresh();
        drawTransparency(lastWitness);
        toast(w.previous ? `Witness checked that the log of ${w.previous.size} entries is a prefix of the log of ${w.checkpoint.size}, then co-signed.` : `Witness co-signed the first checkpoint: ${w.checkpoint.size} entries.`);
      } catch (e) {
        toast(e.message);
      } finally {
        busy = false;
        btn.disabled = false;
      }
    });
    const d = proofData || lastWitness;
    transEl.replaceChildren(
      h('span.label', {}, 'Transparency'),
      h('h2', {}, 'A log the authority can’t quietly rewrite.'),
      h('p.note', {}, 'The ledger is also a Merkle tree, like Certificate Transparency. The authority signs checkpoints; independent witnesses co-sign only checkpoints that extend what they saw before. A service can check that its receipt is in the log with a handful of hashes.'),
      d ? merkleView(d) : h('p.empty-inline', {}, 'No checkpoint published from this view yet.'),
      wit.length ? h('div.wit-list', wit.map((x) => h('div.wit-row', sigil(x.witness, 26), h('span', {}, h('b', {}, x.name), ` co-signed size ${x.size} · root ${x.root.slice(0, 12)}… · ${ago(x.at)}`)))) : null,
      h('div.row-actions', btn),
    );
  }

  function merkleView(d) {
    const cp = d.checkpoint;
    const inc = d.inclusion;
    const levels = inc ? inc.proof.length : 0;
    const W = 520;
    const rowH = 34;
    const H = (levels + 2) * rowH + 10;
    const svg = s('svg.merkle', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Inclusion proof with ${levels} hashes` });
    let x = W / 2;
    const pts = [];
    for (let i = 0; i <= levels; i++) {
      const y = H - 18 - i * rowH;
      pts.push([x, y]);
      if (i < levels) {
        const side = (i % 2 ? -1 : 1) * (60 + i * 6);
        svg.append(s('line.m-edge', { x1: x, y1: y, x2: x, y2: y - rowH }));
        svg.append(s('line.m-sib-edge', { x1: x + side, y1: y, x2: x, y2: y - rowH }));
        svg.append(s('rect.m-sib', { x: x + side - 46, y: y - 9, width: 92, height: 18, rx: 2 }));
        svg.append(s('text.m-sib-t', { x: x + side, y: y + 4, 'text-anchor': 'middle' }, inc.proof[i].slice(0, 10)));
      }
    }
    pts.forEach(([px, py], i) => {
      const isLeaf = i === 0;
      const isRoot = i === levels;
      svg.append(s('rect.m-node' + (isLeaf ? '.leaf' : isRoot ? '.root' : ''), { x: px - 54, y: py - 10, width: 108, height: 20, rx: 2 }));
      svg.append(s('text.m-t', { x: px, y: py + 4, 'text-anchor': 'middle' }, isLeaf ? `entry #${inc.seq}` : isRoot ? `root ${cp.root.slice(0, 8)}` : 'hash'));
    });
    if (gsap && !reducedMotion()) {
      gsap.from(svg.querySelectorAll('.m-edge, .m-sib-edge'), { drawSVG: 0, duration: 0.5, stagger: 0.08, ease: 'power2.out' });
      gsap.from(svg.querySelectorAll('.m-node, .m-sib, .m-t, .m-sib-t'), { opacity: 0, duration: 0.4, stagger: 0.03 });
    }
    return h('div.merkle-wrap',
      h('div.cp-facts',
        fact('Checkpoint', `size ${cp.size}`),
        fact('Merkle root', cp.root.slice(0, 20) + '…'),
        fact('Signed', clock(cp.ts)),
        fact('Proof size', `${levels} hashes for ${cp.size} entries`),
      ),
      svg,
    );
  }

  const fact = (k, v) => h('div', h('span.label', {}, k), h('div.mono', {}, v));

  function draw(animate) {
    sig = signature();
    drawSwitch(animate);
    drawPasskeys();
    drawRing();
    drawGuardians();
    drawAgents();
    drawTransparency();
    if (animate && gsap && !reducedMotion()) gsap.from(root.querySelectorAll('.keys-grid > .sheet'), { y: 22, opacity: 0, duration: 0.5, stagger: 0.06, ease: 'power3.out', clearProps: 'all' });
  }

  function signature() {
    const p = principal();
    return JSON.stringify([p.keys, p.frozen, p.passkeys.length, app.snap.world.agents.map((a) => a.did + a.status), app.snap.ledger.witnessed?.length]);
  }

  root.mounted = () => draw(true);
  root.refresh = () => {
    if (!busy && signature() !== sig) draw(false);
  };
  root.api = { animateRecovery, drawTransparency };
  return root;
}
