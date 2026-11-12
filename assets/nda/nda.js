/* Password gate for work shared under NDA. The locked content is encrypted in the page (AES-GCM, key from
   PBKDF2), so it is not readable in the source; the password unlocks it in the browser. Once unlocked, the key
   is kept for this browser tab so the other NDA pages open without asking again. Built by tools/nda-lock.mjs. */
(() => {
  'use strict';
  const STORE = 'nda.key';
  const locks = [...document.querySelectorAll('.nda-lock[data-nda]')];
  if (!locks.length) return;
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const toB64 = u => btoa(String.fromCharCode(...new Uint8Array(u)));
  let cfgP = null;
  const cfg = () => (cfgP ||= fetch('assets/nda/config.json').then(r => r.json()));

  async function keyFrom(pw) {
    const c = await cfg();
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(c.salt), iterations: c.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  const open = (key, bytes) => crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, key, bytes.subarray(12));

  // "assets/nda/x.bin|image/png" → a blob URL of the decrypted file
  let openKey = null;
  const cache = new Map();
  function media(spec) {
    if (!cache.has(spec)) {
      const [url, type] = spec.split('|');
      cache.set(spec, fetch(url).then(r => r.arrayBuffer())
        .then(buf => open(openKey, new Uint8Array(buf)))
        .then(plain => URL.createObjectURL(new Blob([plain], { type }))));
    }
    return cache.get(spec);
  }
  // for media a page loads on demand (data-src): ndaMedia(el) decrypts and sets el.src
  window.ndaMedia = el => {
    if (!openKey || !el.dataset.ndaLazy || el.dataset.ndaBusy) return false;
    el.dataset.ndaBusy = '1';
    media(el.dataset.ndaLazy).then(u => { el.src = u; if (el.autoplay || el.dataset.ndaPlay) el.play && el.play().catch(() => {}); }).catch(() => {});
    return true;
  };

  async function unlockAll(key) {
    const done = [];
    for (const el of locks) {
      if (!el.isConnected) continue;
      const html = new TextDecoder().decode(await open(key, b64(el.dataset.nda))); // throws on a wrong key
      const t = document.createElement('template');
      t.innerHTML = html;
      const nodes = [...t.content.childNodes];
      el.replaceWith(t.content);
      done.push(...nodes);
    }
    openKey = key;
    for (const n of done) {
      if (n.nodeType !== 1) continue;
      const all = [n, ...n.querySelectorAll('[data-nda-src],[data-nda-poster]')];
      for (const el of all) {
        if (el.dataset.ndaSrc) media(el.dataset.ndaSrc).then(u => { el.src = u; }).catch(() => {});
        if (el.dataset.ndaPoster) media(el.dataset.ndaPoster).then(u => { el.poster = u; }).catch(() => {});
      }
    }
    document.documentElement.classList.add('nda-open');
    document.dispatchEvent(new Event('nda:unlocked'));
    // a link to a section (e.g. #booklet) can only land once the section exists
    const id = location.hash.slice(1).split('&')[0];
    const target = id && document.getElementById(id);
    if (target) requestAnimationFrame(() => target.scrollIntoView());
  }

  const LOCK_SVG = '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="4.5" y="10.5" width="15" height="10" rx="1.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/></svg>';
  function gate(el, i) {
    const page = el.classList.contains('nda-page');
    const box = document.createElement('div');
    box.className = 'nda-gate' + (page ? ' wrap' : '');
    const icon = document.createElement('div'); icon.className = 'nda-icon'; icon.innerHTML = LOCK_SVG;
    const tag = document.createElement('div'); tag.className = 'nda-tag mono'; tag.textContent = '// UNDER NDA · ' + el.dataset.org.toUpperCase();
    const h = document.createElement(page ? 'h1' : 'div'); h.className = 'nda-title head'; h.textContent = el.dataset.title;
    const p = document.createElement('p'); p.className = 'nda-copy';
    p.textContent = page
      ? 'This work was made under a non-disclosure agreement, so it stays private. If you have the password, enter it to view the case study.'
      : 'Private client work under NDA. Enter the password to view it.';
    box.append(icon, tag, h, p);
    if (page || i === locks.findIndex(l => !l.classList.contains('nda-page'))) {
      const f = document.createElement('form'); f.className = 'nda-form';
      const id = 'nda-pw-' + i;
      const lab = document.createElement('label'); lab.className = 'nda-sr'; lab.htmlFor = id; lab.textContent = 'Password';
      const inp = document.createElement('input'); inp.type = 'password'; inp.id = id; inp.placeholder = 'Password'; inp.autocomplete = 'current-password'; inp.required = true;
      const btn = document.createElement('button'); btn.type = 'submit'; btn.className = 'mono'; btn.textContent = 'UNLOCK';
      const msg = document.createElement('div'); msg.className = 'nda-msg mono'; msg.setAttribute('role', 'status');
      f.append(lab, inp, btn, msg);
      f.addEventListener('submit', async ev => {
        ev.preventDefault();
        btn.disabled = true; msg.textContent = 'Checking…';
        try {
          const key = await keyFrom(inp.value);
          await unlockAll(key);
          try { sessionStorage.setItem(STORE, toB64(await crypto.subtle.exportKey('raw', key))); } catch {}
        } catch {
          msg.textContent = "That password didn't work.";
          f.classList.remove('nda-shake'); void f.offsetWidth; f.classList.add('nda-shake');
          btn.disabled = false; inp.select();
        }
      });
      box.append(f);
      const ask = document.createElement('p'); ask.className = 'nda-ask mono';
      ask.innerHTML = 'NEED ACCESS? <a href="mailto:genpugdesign@gmail.com?subject=Portfolio%20password">ASK ME →</a>';
      if (page) box.append(ask);
    } else {
      const note = document.createElement('div'); note.className = 'nda-msg mono'; note.textContent = 'Unlocks with the password above.';
      box.append(note);
    }
    el.append(box);
  }

  (async () => {
    let saved = null;
    try { saved = sessionStorage.getItem(STORE); } catch {}
    if (saved) {
      try {
        const key = await crypto.subtle.importKey('raw', b64(saved), 'AES-GCM', false, ['decrypt']);
        await unlockAll(key);
        return;
      } catch { try { sessionStorage.removeItem(STORE); } catch {} }
    }
    locks.forEach(gate);
  })();
})();
