// Twelve Permissions — deterministic seal generator.
// Every visual decision derives from SHA-256 of the canonical event record,
// so anyone can re-run this file against events.json and get byte-identical art.
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const events = JSON.parse(fs.readFileSync(path.join(__dirname, 'events.json'), 'utf8'));

// Seal palettes: notary wax + engraved metal, deliberately NOT web-app navy/blue.
const PALETTES = [
  { name: 'obsidian-gold',   bg: '#161007', ring: '#8a7340', ink: '#e9dcb8', accent: '#e3b341', dim: '#4a3d22' },
  { name: 'parchment-oxblood', bg: '#ece1c8', ring: '#8c7c5c', ink: '#33241c', accent: '#8e1f1f', dim: '#c9bb9d' },
  { name: 'verdigris-brass', bg: '#0e1a16', ring: '#5c7a5e', ink: '#d7e4d0', accent: '#c9a84c', dim: '#2b3f34' },
  { name: 'iron-vermilion',  bg: '#1a1614', ring: '#6e625a', ink: '#e6ddd3', accent: '#d4552b', dim: '#3d3630' }
];

function byteAt(hash, i) { return parseInt(hash.slice((i * 2) % 62, (i * 2) % 62 + 2), 16); }
function bit(hash, i) { return (byteAt(hash, Math.floor(i / 8)) >> (i % 8)) & 1; }

function polar(cx, cy, r, deg) {
  const a = (deg - 90) * Math.PI / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function seal(ev) {
  const canonical = JSON.stringify({ n: ev.n, date: ev.date, title: ev.title, grant: ev.grant, detail: ev.detail, evidence: ev.evidence });
  const hash = crypto.createHash('sha256').update(canonical).digest('hex');
  const P = PALETTES[byteAt(hash, 0) % PALETTES.length];
  const rot = byteAt(hash, 1) % 360;
  const cx = 400, cy = 400;
  const parts = [];

  parts.push(`<rect width="800" height="800" fill="${P.bg}"/>`);

  // faint engraved field lines, spacing from hash
  const gap = 18 + (byteAt(hash, 2) % 14);
  for (let y = gap; y < 800; y += gap) {
    parts.push(`<line x1="0" y1="${y}" x2="800" y2="${y}" stroke="${P.dim}" stroke-width="0.6" opacity="0.35"/>`);
  }

  // outer seal rings
  parts.push(`<circle cx="${cx}" cy="${cy}" r="352" fill="none" stroke="${P.ring}" stroke-width="3"/>`);
  parts.push(`<circle cx="${cx}" cy="${cy}" r="344" fill="none" stroke="${P.ring}" stroke-width="1"/>`);
  parts.push(`<circle cx="${cx}" cy="${cy}" r="236" fill="none" stroke="${P.ring}" stroke-width="1.5"/>`);

  // 64 hash-bit ticks: long tick = 1, short = 0 — the hash is literally readable off the ring
  for (let i = 0; i < 64; i++) {
    const deg = rot + i * (360 / 64);
    const long = bit(hash, i) === 1;
    const [x1, y1] = polar(cx, cy, 336, deg);
    const [x2, y2] = polar(cx, cy, long ? 300 : 322, deg);
    parts.push(`<line x1="${x1.toFixed(2)}" y1="${y1.toFixed(2)}" x2="${x2.toFixed(2)}" y2="${y2.toFixed(2)}" stroke="${long ? P.accent : P.ink}" stroke-width="${long ? 4 : 1.5}" stroke-linecap="round" opacity="${long ? 0.95 : 0.55}"/>`);
  }

  // circular legend text
  const legend = `PERMISSION ${String(ev.n).padStart(2, '0')} OF 12 • GRANTED ${ev.date} • ${ev.title} • TWELVE PERMISSIONS • `;
  parts.push(`<defs><path id="tp${ev.n}" d="M ${cx} ${cy - 268} A 268 268 0 1 1 ${cx - 0.01} ${cy - 268}"/></defs>`);
  parts.push(`<text font-family="Georgia, 'Times New Roman', serif" font-size="21" letter-spacing="6" fill="${P.ink}"><textPath href="#tp${ev.n}">${esc(legend)}</textPath></text>`);

  // central sigil: 12 hash-driven vertices on a half-grid, mirrored for seal symmetry
  const cell = 36;
  const pts = [];
  for (let i = 0; i < 12; i++) {
    const c = parseInt(hash[i], 16) % 3;          // columns 0..2 (2 = axis)
    const r = parseInt(hash[i + 12], 16) % 7;     // rows 0..6
    pts.push([cx - (2 - c) * cell, cy + (r - 3) * cell]);
  }
  const mirror = pts.map(([x, y]) => [2 * cx - x, y]);
  const line = p => p.map(([x, y], i) => `${i ? 'L' : 'M'} ${x} ${y}`).join(' ');
  parts.push(`<path d="${line(pts)}" fill="none" stroke="${P.accent}" stroke-width="5" stroke-linejoin="round" stroke-linecap="round" opacity="0.9"/>`);
  parts.push(`<path d="${line(mirror)}" fill="none" stroke="${P.accent}" stroke-width="5" stroke-linejoin="round" stroke-linecap="round" opacity="0.9"/>`);
  for (const [x, y] of pts.concat(mirror)) {
    parts.push(`<circle cx="${x}" cy="${y}" r="7" fill="${P.bg}" stroke="${P.ink}" stroke-width="2.5"/>`);
  }
  parts.push(`<circle cx="${cx}" cy="${cy}" r="10" fill="${P.accent}"/>`);

  // stamp banner: opaque ribbon across the seal base so text never fights the ring
  const grant = ev.grant.toUpperCase();
  const ls = 4;
  const fsFit = Math.max(13, Math.min(26, (640 / grant.length - ls) / 0.6));
  parts.push(`<rect x="60" y="686" width="680" height="76" fill="${P.bg}" stroke="${P.brass || P.ring}" stroke-width="1.5"/>`);
  parts.push(`<text x="${cx}" y="718" text-anchor="middle" font-family="Georgia, serif" font-size="${fsFit.toFixed(1)}" letter-spacing="${ls}" fill="${P.ink}">${esc(grant)}</text>`);
  parts.push(`<text x="${cx}" y="748" text-anchor="middle" font-family="'Courier New', monospace" font-size="15" letter-spacing="3" fill="${P.accent}">sha256 ${hash.slice(0, 16)}…${hash.slice(-8)}</text>`);

  // progress squares in the clear top margin: filled = permissions granted at mint time
  for (let i = 0; i < 12; i++) {
    const x = cx - (12 * 26 - 10) / 2 + i * 26;
    const filled = i < ev.n;
    parts.push(`<rect x="${x}" y="20" width="16" height="16" rx="2" fill="${filled ? P.accent : 'none'}" stroke="${P.ink}" stroke-width="1.5" opacity="${filled ? 0.95 : 0.45}"/>`);
  }

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800" width="800" height="800">${parts.join('\n')}</svg>`;
  return { svg, hash, palette: P.name, canonical };
}

for (const ev of events) {
  const { svg, hash, palette, canonical } = seal(ev);
  const id = String(ev.n).padStart(2, '0');
  fs.writeFileSync(path.join(__dirname, 'pieces', `${id}.svg`), svg);
  fs.writeFileSync(path.join(__dirname, 'pieces', `${id}.json`), JSON.stringify({
    name: `Twelve Permissions #${id} — ${ev.title}`,
    description: `${ev.grant}. ${ev.detail} Evidence: ${ev.evidence}. Deterministic seal: every mark derives from sha256 of the canonical event record; re-run the public generator to verify.`,
    attributes: [
      { trait_type: 'Permission', value: ev.n },
      { trait_type: 'Granted', value: ev.date },
      { trait_type: 'Palette', value: palette },
      { trait_type: 'Event Hash', value: hash }
    ],
    canonical_record: canonical
  }, null, 2));
  console.log(`#${id} ${ev.title} — ${palette} — ${hash.slice(0, 12)}`);
}
console.log('done');
