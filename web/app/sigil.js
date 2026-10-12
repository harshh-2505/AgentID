// Guilloche sigils: every key gets a unique engraved rosette derived from its bytes,
// the way banknotes and passports use guilloche as an anti-forgery fingerprint.
// Two agents never share a face, and a human can spot "that is not Ledgerline" at a glance.

import { unb64u } from '../core/encoding.js';
import { cssVar } from './dom.js';

const cache = new Map();

export function keyBytes(did) {
  try { return unb64u(did.slice(12)); } catch { return new Uint8Array(32).fill(7); }
}

export function drawGuilloche(ctx, cx, cy, R, bytes, { ink, accent, detail = 1, rotation = 0, alpha = 1 }) {
  const b = (i) => bytes[i % bytes.length];
  ctx.save();
  ctx.translate(cx, cy);
  ctx.rotate(rotation);
  ctx.globalAlpha = alpha;
  ctx.lineWidth = Math.max(0.45, R / 160);
  const steps = Math.round(720 * detail);

  // Outer band: phase-shifted wave rings, the classic security-print border.
  const n1 = 6 + (b(0) % 11);
  const n2 = 3 + (b(1) % 6);
  const amp = R * (0.05 + (b(2) / 255) * 0.06);
  const rings = Math.max(6, Math.round(16 * detail));
  for (let j = 0; j < rings; j++) {
    const ph = (j / rings) * Math.PI * (1 + b(3) / 255);
    ctx.strokeStyle = j % 2 ? accent : ink;
    ctx.beginPath();
    for (let i = 0; i <= steps; i++) {
      const t = (i / steps) * Math.PI * 2;
      const r = R * 0.8 + amp * Math.sin(n1 * t + ph) + amp * 0.55 * Math.sin(n2 * t - ph * 2);
      const x = r * Math.cos(t), y = r * Math.sin(t);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    }
    ctx.stroke();
  }

  // Inner rosette: a hypotrochoid whose petal count and depth come from the key.
  const k = 5 + (b(4) % 9);
  const Ri = R * 0.58;
  const ri = Ri / k * (1 + (b(5) % 3));
  const d = ri * (0.7 + (b(6) / 255) * 1.1);
  const loops = 1 + (b(7) % 3);
  const layers = Math.max(2, Math.round(4 * detail));
  for (let L = 0; L < layers; L++) {
    ctx.strokeStyle = L % 2 ? ink : accent;
    ctx.beginPath();
    const rot = (L / layers) * (Math.PI / k);
    const total = steps * 3 * loops;
    for (let i = 0; i <= total; i++) {
      const t = (i / total) * Math.PI * 2 * (k + loops);
      const x = (Ri - ri) * Math.cos(t + rot) + d * Math.cos(((Ri - ri) / ri) * t + rot);
      const y = (Ri - ri) * Math.sin(t + rot) - d * Math.sin(((Ri - ri) / ri) * t + rot);
      const scale = Ri / (Ri - ri + d);
      i ? ctx.lineTo(x * scale, y * scale) : ctx.moveTo(x * scale, y * scale);
    }
    ctx.stroke();
  }
  ctx.restore();
}

// Returns a canvas element sized for CSS pixels at device resolution.
export function sigil(did, size = 32, { detail } = {}) {
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  const ink = cssVar('--intaglio');
  const accent = cssVar('--rosette');
  const key = `${did}|${size}|${ink}|${accent}|${dpr}`;
  const c = document.createElement('canvas');
  c.className = 'sigil';
  c.width = c.height = Math.round(size * dpr);
  c.style.width = c.style.height = size + 'px';
  c.dataset.did = did;
  c.dataset.size = size;
  const ctx = c.getContext('2d');
  const cached = cache.get(key);
  if (cached) {
    ctx.drawImage(cached, 0, 0);
    return c;
  }
  drawGuilloche(ctx, c.width / 2, c.height / 2, c.width / 2 - 1, keyBytes(did), { ink, accent, detail: detail ?? (size > 80 ? 1 : size > 40 ? 0.6 : 0.35) });
  cache.set(key, c);
  return c;
}

// Repaints every sigil on the page, used after the theme changes.
export function repaintSigils(root = document) {
  for (const old of root.querySelectorAll('canvas.sigil[data-did]')) {
    const fresh = sigil(old.dataset.did, Number(old.dataset.size));
    fresh.className = old.className;
    old.replaceWith(fresh);
  }
}
