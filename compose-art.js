// Composites the deterministic seal over generated field art, producing the
// display image for each piece.
//
// CRITICAL SEPARATION OF CONCERNS:
//   pieces/NN.svg  — the canonical seal. Derived purely from SHA-256 of the
//                    record by generate.js. NEVER touched here. It stays the
//                    verification artifact and is served as animation_url.
//   pieces/NN.png  — the display image. Seal composited over generated art.
//                    Beautiful, but NOT the thing you verify.
//
// Merging those two would collapse the collection's central claim: art that
// cannot be regenerated from the record proves nothing. The pretty version is
// explicitly downstream of, and separate from, the provable one.
//
// NOTE: resvg-js 2.6.2 does not render embedded raster images at all (verified:
// every data-URI variant produced an empty 2,127-byte PNG), so the field cannot
// be layered inside the SVG. resvg renders the seal to a transparent PNG and
// sharp does the compositing.
'use strict';
const { Resvg } = require('@resvg/resvg-js');
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const SIZE = 1280;   // display size: large enough to read the sha256 banner, small enough to serve
const SEAL_SCALE = 0.68;            // seal occupies this fraction of the frame
const fieldsDir = path.join(__dirname, 'fields');
const piecesDir = path.join(__dirname, 'pieces');

// Strip the seal's opaque background and the laid-paper lines drawn onto it, so
// only ink remains and the field shows through.
function sealInk(svg) {
  return svg
    .replace(/<rect width="800" height="800"[^>]*\/>\s*/, '')
    .replace(/<line x1="0" y1="\d+" x2="800"[^>]*\/>\s*/g, '');
}

(async () => {
  const ids = fs.readdirSync(piecesDir).filter(f => /^\d\d\.svg$/.test(f)).map(f => f.slice(0, 2));
  for (const id of ids) {
    const fieldPath = path.join(fieldsDir, `${id}.png`);
    if (!fs.existsSync(fieldPath)) { console.log(`#${id}: no field, skipped`); continue; }

    const sealPx = Math.round(SIZE * SEAL_SCALE);
    const sealPng = new Resvg(sealInk(fs.readFileSync(path.join(piecesDir, `${id}.svg`), 'utf8')), {
      fitTo: { mode: 'width', value: sealPx },
      background: 'rgba(0,0,0,0)',
      font: { loadSystemFonts: true, defaultFontFamily: 'Georgia' }
    }).render().asPng();

    const field = await sharp(fieldPath).resize(SIZE, SIZE, { fit: 'cover' }).toBuffer();
    const offset = Math.round((SIZE - sealPx) / 2);
    const out = await sharp(field)
      .composite([{ input: sealPng, top: offset, left: offset }])
      .png({ compressionLevel: 9, effort: 9, palette: true, colours: 160, quality: 80 })  // engravings quantise well; keeps files servable
      .toBuffer();

    fs.writeFileSync(path.join(piecesDir, `${id}.png`), out);
    console.log(`#${id} composited  ${Math.round(out.length / 1024)}KB`);
  }
})();
