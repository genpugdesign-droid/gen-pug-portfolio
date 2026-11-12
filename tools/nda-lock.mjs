// Builds the password-locked (NDA) pages.
//
// Edit the plain pages in _nda_src/ (git-ignored, never committed), then run:
//   NDA_PASSWORD='…' node tools/nda-lock.mjs
// Each <!--NDA:start …--> … <!--NDA:end--> region is encrypted (AES-GCM, key from PBKDF2) and replaced by a
// password gate. Images inside a region are encrypted into assets/nda/*.bin, and the readable originals are
// moved to _nda_src/assets/ so they are not published. The salt is public; the password is never written down.
import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const SRC = path.join(ROOT, '_nda_src');
const OUT_ASSETS = path.join(ROOT, 'assets/nda');
const CONFIG = path.join(OUT_ASSETS, 'config.json');
const ITER = 310000;

const pw = process.env.NDA_PASSWORD;
if (!pw) { console.error('Set NDA_PASSWORD'); process.exit(1); }

fs.mkdirSync(OUT_ASSETS, { recursive: true });
let cfg = fs.existsSync(CONFIG) ? JSON.parse(fs.readFileSync(CONFIG, 'utf8')) : null;
if (!cfg) {
  cfg = { salt: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64'), iter: ITER };
  fs.writeFileSync(CONFIG, JSON.stringify(cfg) + '\n');
}

const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt: Buffer.from(cfg.salt, 'base64'), iterations: cfg.iter, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

// guard against a typo: a later run must use the same password as the first one
if (cfg.check) {
  const b = Buffer.from(cfg.check, 'base64');
  try { await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.subarray(0, 12) }, key, b.subarray(12)); }
  catch { console.error('NDA_PASSWORD does not match the one the pages were locked with'); process.exit(1); }
}

async function seal(bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return Buffer.from(out);
}
if (!cfg.check) {
  cfg.check = (await seal(new TextEncoder().encode('nda-ok'))).toString('base64');
  fs.writeFileSync(CONFIG, JSON.stringify(cfg) + '\n');
}
const TYPES = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.mp4': 'video/mp4' };
const esc = s => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
const sha = async s => Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))).toString('hex').slice(0, 16);

// where to find a readable asset: in the site, or already moved into _nda_src/assets
const assetFile = rel => [path.join(ROOT, rel), path.join(SRC, rel)].find(p => fs.existsSync(p));

const lockedAssets = new Set();
const pages = fs.readdirSync(SRC).filter(f => f.endsWith('.html'));
for (const f of pages) {
  let html = fs.readFileSync(path.join(SRC, f), 'utf8');
  const re = /<!--NDA:start title="([^"]*)" org="([^"]*)" kind="(page|inline)"-->([\s\S]*?)<!--NDA:end-->/g;
  const parts = []; let last = 0, m, n = 0;
  while ((m = re.exec(html))) {
    let [all, title, org, kind, body] = m;
    const refs = [...body.matchAll(/(src|poster)="(assets\/[^"]+)"/g)];
    for (const [, , rel] of refs) {
      const file = assetFile(rel);
      if (!file) throw new Error(`${f}: missing ${rel}`);
      const id = await sha(rel);
      fs.writeFileSync(path.join(OUT_ASSETS, id + '.bin'), await seal(fs.readFileSync(file)));
      const type = TYPES[path.extname(rel).toLowerCase()] || 'application/octet-stream';
      body = body.split(`="${rel}"`).join(`="" data-nda-src="assets/nda/${id}.bin" data-nda-type="${type}"`);
      lockedAssets.add(rel);
    }
    const payload = (await seal(new TextEncoder().encode(body))).toString('base64');
    parts.push(html.slice(last, m.index),
      `<div class="nda-lock nda-${kind}" data-nda="${payload}" data-title="${esc(title)}" data-org="${esc(org)}"></div>`);
    last = m.index + all.length; n++;
  }
  parts.push(html.slice(last));
  html = parts.join('');
  if (!html.includes('assets/nda/nda.js')) {
    const tags = '<link rel="stylesheet" href="assets/nda/nda.css">\n<script src="assets/nda/nda.js" defer></script>\n';
    // some pages omit </head>; then the tags go just before <body>
    html = html.includes('</head>') ? html.replace('</head>', tags + '</head>') : html.replace('<body>', tags + '<body>');
  }
  fs.writeFileSync(path.join(ROOT, f), html);
  console.log(`${f}: ${n} region(s) locked`);
}

// move readable originals out of the published site, unless a public page still uses them
const publicHtml = fs.readdirSync(ROOT).filter(f => f.endsWith('.html')).map(f => fs.readFileSync(path.join(ROOT, f), 'utf8')).join('\n');
for (const rel of lockedAssets) {
  const live = path.join(ROOT, rel);
  if (!fs.existsSync(live)) continue;
  if (publicHtml.includes(`"${rel}"`)) { console.log(`kept public (still used elsewhere): ${rel}`); continue; }
  const dest = path.join(SRC, rel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.renameSync(live, dest);
  console.log(`moved out of the site: ${rel}`);
}
