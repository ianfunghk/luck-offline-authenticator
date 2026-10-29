/* Offline TOTP authenticator - app logic. No network, no external assets. */
(function () {
  'use strict';
  var C = window.OTPCrypto, S = window.OTPSqlite;
  var $ = function (id) { return document.getElementById(id); };
  var enc = C.utf8Bytes, dec = C.utf8Str, b64 = C.toB64, unb64 = C.fromB64;

  /* ---------------- storage (best effort) ---------------- */
  var STORE_KEY = 'totp-offline-vault-v1';
  var memStore = {};
  var storageOK = (function () {
    try {
      var k = '__t__' + Date.now();
      window.localStorage.setItem(k, '1');
      window.localStorage.removeItem(k);
      return true;
    } catch (e) { return false; }
  })();
  function storeGet(k) {
    try { return storageOK ? window.localStorage.getItem(k) : (memStore[k] || null); }
    catch (e) { return memStore[k] || null; }
  }
  function storeSet(k, v) {
    try { if (storageOK) { window.localStorage.setItem(k, v); return true; } } catch (e) { }
    memStore[k] = v; return false;
  }
  function storeDel(k) {
    try { if (storageOK) window.localStorage.removeItem(k); } catch (e) { }
    delete memStore[k];
  }

  /* ---------------- vault state ---------------- */
  var state = {
    mode: 'loading',      // loading | setup | locked | unlocked
    key: null,            // Uint8Array master key (memory only)
    hmacKey: null,
    vault: null,          // {entries:[...]}
    raw: null,            // encrypted blob string currently in storage
    filter: '',
    revealed: {}
  };

  function newId() { return 'e' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

  function emptyVault() { return { v: 1, entries: [] }; }

  /* vault file format:  OTPV1.<saltB64>.<ivB64>.<ctB64>.<macB64> */
  function pad16(b) {
    var n = 16 - (b.length % 16);
    var out = new Uint8Array(b.length + n);
    out.set(b, 0);
    for (var i = b.length; i < out.length; i++) out[i] = n;
    return out;
  }
  function unpad16(b) {
    if (b.length === 0 || b.length % 16 !== 0) throw new Error('Vault contents are not readable.');
    var n = b[b.length - 1];
    if (n < 1 || n > 16 || n > b.length) throw new Error('Vault contents are not readable.');
    for (var i = b.length - n; i < b.length; i++) if (b[i] !== n) throw new Error('Vault contents are not readable.');
    return b.subarray(0, b.length - n);
  }

  function sealVault(vault, key, hmacKey) {
    var plain = pad16(enc(JSON.stringify(vault)));
    var iv = C.randomBytes(16);
    var ct = C.cbcEncrypt(key, iv, plain);
    var mac = C.hmacSha256(hmacKey, C.concatBytes(iv, ct));
    return 'OTPV1.' + b64(state.salt) + '.' + b64(iv) + '.' + b64(ct) + '.' + b64(mac);
  }
  function openVault(blob, key, hmacKey) {
    var parts = String(blob).split('.');
    if (parts.length !== 5 || parts[0] !== 'OTPV1') throw new Error('Not a valid vault file');
    var salt = unb64(parts[1]), iv = unb64(parts[2]), ct = unb64(parts[3]), mac = unb64(parts[4]);
    var calc = C.hmacSha256(hmacKey, C.concatBytes(iv, ct));
    if (!C.bytesEqual(mac, calc)) throw new Error('Wrong password, or the vault file is corrupted.');
    var plain = unpad16(C.cbcDecrypt(key, iv, ct));
    var v = JSON.parse(dec(plain));
    if (!v || !Array.isArray(v.entries)) throw new Error('Vault contents are not readable.');
    return v;
  }
  function deriveMaster(password) {
    var salt = state.salt || (state.salt = C.randomBytes(16));
    return C.pbkdf2Async('SHA256', enc(password), salt, 150000, 32).then(function (k) {
      var hs = new Uint8Array(salt.length);
      for (var i = 0; i < salt.length; i++) hs[i] = salt[i] ^ 0x5a;
      return C.pbkdf2Async('SHA256', k, hs, 2, 32).then(function (h) {
        return { key: k, hmacKey: h, salt: salt };
      });
    });
  }

  function persist() {
    if (!state.key || !state.vault) return;
    var blob = sealVault(state.vault, state.key, state.hmacKey);
    state.raw = blob;
    var saved = storeSet(STORE_KEY, blob);
    var wasLost = !!state.storageLost;
    state.storageLost = !saved;
    // surface a write failure the moment it happens, not on the next unlock
    if (state.storageLost && !wasLost && state.mode === 'unlocked' && els.storeWarn) {
      syncStorageWarning();
      msg(els.msgArea, 'This browser refused to save your vault. Your codes work until you close the page — export an encrypted backup now.', 'warn');
    }
  }

  /* ---------------- rendering ---------------- */
  var els = {};
  function initEls() {
    ['loading', 'setup', 'locked', 'unlocked', 'setupPw', 'setupPw2', 'setupGo', 'setupErr',
      'unlockPw', 'unlockGo', 'unlockErr', 'lockBtn', 'list', 'filter', 'count', 'empty',
      'addIssuer', 'addLabel', 'addSecret', 'addDigits', 'addPeriod', 'addAlgo', 'addGo', 'addErr',
      'dbFile', 'dbPw', 'dbGo', 'dbErr', 'uriText', 'uriGo', 'uriErr',
      'exportBtn', 'exportPlainBtn', 'importFile', 'restorePw', 'restoreGo', 'restoreErr',
      'changePw', 'changePwOld', 'changeGo', 'changeErr',
      'wipeBtn', 'storeWarn', 'msgArea', 'searchWrap'].forEach(function (id) { els[id] = $(id); });
  }

  function show(mode) {
    state.mode = mode;
    ['loading', 'setup', 'locked', 'unlocked'].forEach(function (m) {
      els[m].classList.toggle('hidden', m !== mode);
    });
    els.lockBtn.classList.toggle('hidden', mode !== 'unlocked');
  }

  function msg(el, text, kind) {
    if (!el) return;
    if (!text) { el.className = 'hidden'; el.textContent = ''; return; }
    el.className = 'msg ' + (kind || 'err');
    el.textContent = text;
  }

  function normalizeSecret(s) {
    return String(s || '').replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  }
  function validSecret(s) {
    try { C.base32Decode(s); return /^[A-Z2-7]+$/.test(s) && s.length >= 8; }
    catch (e) { return false; }
  }

  function renderList() {
    var needRefresh = false;
    var list = els.list;
    var entries = state.vault.entries;
    var q = state.filter.trim().toLowerCase();
    var shown = entries.filter(function (e) {
      if (!q) return true;
      return ((e.issuer || '') + ' ' + (e.label || '')).toLowerCase().indexOf(q) >= 0;
    });

    // full rebuild only when the visible set changed. HOTP counters live in the
    // badge text, so they must be part of the signature or the badge goes stale.
    var sig = shown.map(function (e) {
      return e.id + (e.type === 'hotp' ? ':' + (e.counter || 0) : '');
    }).join(',') + '|' + Object.keys(state.revealed).join(',');
    if (list.dataset.sig !== sig) {
      needRefresh = true;
      list.dataset.sig = sig;
      list.innerHTML = '';
      shown.forEach(function (e) {
        list.appendChild(entryNode(e));
      });
    }
    els.count.textContent = entries.length + (entries.length === 1 ? ' account' : ' accounts');
    els.empty.classList.toggle('hidden', entries.length > 0);
    els.searchWrap.classList.toggle('hidden', entries.length < 2);
    tick(needRefresh);
  }

  function entryNode(e) {
    var d = document.createElement('div');
    d.className = 'entry';
    d.dataset.id = e.id;

    var top = document.createElement('div');
    top.className = 'top';
    var who = document.createElement('div');
    who.className = 'who';
    var iss = document.createElement('div');
    iss.className = 'issuer';
    iss.textContent = e.issuer || '(no issuer)';
    var lab = document.createElement('div');
    lab.className = 'label';
    lab.textContent = e.label || '';
    who.appendChild(iss); who.appendChild(lab);
    var code = document.createElement('div');
    code.className = 'code';
    code.dataset.role = 'code';
    top.appendChild(who); top.appendChild(code);
    d.appendChild(top);

    var meta = document.createElement('div');
    meta.className = 'meta';
    var bar = document.createElement('div');
    bar.className = 'bar';
    var fill = document.createElement('i');
    bar.appendChild(fill);
    var secs = document.createElement('span');
    secs.className = 'secs';
    secs.dataset.role = 'secs';
    var badge = document.createElement('span');
    badge.className = 'badge' + (e.type === 'hotp' ? ' hotp' : '');
    badge.textContent = e.type === 'hotp'
      ? ('HOTP c' + (e.counter || 0))
      : (((e.algo || 'SHA1').replace('SHA', 'S')) + ' · ' + (e.digits || 6) + 'd · ' + (e.period || 30) + 's');
    meta.appendChild(bar); meta.appendChild(secs); meta.appendChild(badge);
    d.appendChild(meta);

    if (state.revealed[e.id]) {
      var box = document.createElement('div');
      box.className = 'secretbox';
      box.dataset.role = 'secret';
      box.textContent = e.secret;
      box.addEventListener('click', function () { copy(e.secret, 'Secret copied'); });
      d.appendChild(box);
    }

    var actions = document.createElement('div');
    actions.className = 'actions';
    actions.appendChild(mkBtn('Copy code', 'small', function () { copy(code.textContent, 'Code copied'); }));
    actions.appendChild(mkBtn('Show key', 'small', function () { toggleSecret(d, e); }));
    if (e.type === 'hotp') {
      actions.appendChild(mkBtn('Next code', 'small', function () {
        e.counter = (e.counter || 0) + 1; persist(); renderList();
      }));
    }
    actions.appendChild(mkBtn('Delete', 'small danger', function () {
      if (!confirm('Delete ' + (e.issuer || e.label || 'this account') + '? Make sure you have another way in.')) return;
      state.vault.entries = state.vault.entries.filter(function (x) { return x.id !== e.id; });
      persist(); renderList();
    }));
    d.appendChild(actions);
    return d;
  }

  function mkBtn(text, cls, fn) {
    var b = document.createElement('button');
    b.className = cls || '';
    b.textContent = text;
    b.addEventListener('click', fn);
    return b;
  }

  function toggleSecret(node, e) {
    if (state.revealed[e.id]) delete state.revealed[e.id];
    else state.revealed[e.id] = 1;
    renderList();
  }

  function tick(rebuilt) {
    if (state.mode !== 'unlocked' || !state.vault) return;
    var now = Math.floor(Date.now() / 1000);
    var nodes = els.list.children;
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      var id = node.dataset.id;
      var e = null;
      for (var j = 0; j < state.vault.entries.length; j++) if (state.vault.entries[j].id === id) e = state.vault.entries[j];
      if (!e) continue;
      var codeEl = node.querySelector('[data-role=code]');
      var secEl = node.querySelector('[data-role=secs]');
      var bar = node.querySelector('.bar');
      var fill = bar ? bar.firstChild : null;
      if (e.type === 'hotp') {
        codeEl.textContent = C.hotp(C.base32Decode(e.secret), e.counter || 0, e.digits || 6, e.algo || 'SHA1');
        if (secEl) secEl.textContent = '';
        if (fill) fill.style.width = '100%';
        bar.className = 'bar';
        continue;
      }
      var period = e.period || 30;
      var left = period - (now % period);
      var nextCode = C.totp(C.base32Decode(e.secret), e.digits || 6, period, e.algo || 'SHA1', now);
      if (codeEl.textContent !== nextCode) codeEl.textContent = nextCode;
      if (secEl) secEl.textContent = left;
      if (fill) fill.style.width = (left / period * 100).toFixed(2) + '%';
      bar.className = 'bar' + (left <= 5 ? ' crit' : (left <= 10 ? ' low' : ''));
    }
    if (rebuilt) { /* nothing extra */ }
  }

  function copy(text, label) {
    text = String(text || '').replace(/\s+/g, '');
    var done = function () { flash(label || 'Copied'); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else fallback();
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;';
      document.body.appendChild(ta);
      ta.select(); ta.setSelectionRange(0, text.length);
      try { document.execCommand('copy'); done(); } catch (e) { flash('Copy failed - select manually'); }
      document.body.removeChild(ta);
    }
  }
  var flashTimer = null;
  function flash(text) {
    var el = $('toast');
    el.textContent = text;
    el.classList.remove('hidden');
    clearTimeout(flashTimer);
    flashTimer = setTimeout(function () { el.classList.add('hidden'); }, 1400);
  }

  /* ---------------- setup / unlock ---------------- */
  function doSetup() {
    var pw = els.setupPw.value, pw2 = els.setupPw2.value;
    if (pw.length < 6) return msg(els.setupErr, 'Use at least 6 characters. This password encrypts your codes.');
    if (pw !== pw2) return msg(els.setupErr, 'The two passwords do not match.');
    busy(els.setupGo, true);
    try { state.salt = C.randomBytes(16); }
    catch (e) { busy(els.setupGo, false); return msg(els.setupErr, String(e.message || e)); }
    deriveMaster(pw).then(function (k) {
      state.key = k.key; state.hmacKey = k.hmacKey;
      state.vault = emptyVault();
      persist();
      els.setupPw.value = ''; els.setupPw2.value = '';
      msg(els.setupErr, '');
      afterUnlock(true);
    }).catch(function (e) { msg(els.setupErr, String(e.message || e)); }).then(function () { busy(els.setupGo, false); });
  }

  function doUnlock() {
    var pw = els.unlockPw.value;
    var blob = storeGet(STORE_KEY);
    if (!blob) return msg(els.unlockErr, 'No saved vault found on this device. Import a backup file instead.');
    busy(els.unlockGo, true);
    var salt;
    try {
      var parts = blob.split('.');
      if (parts.length !== 5 || parts[0] !== 'OTPV1') throw new Error('Stored vault is unreadable.');
      salt = unb64(parts[1]);
    } catch (e) { busy(els.unlockGo, false); return msg(els.unlockErr, String(e.message || e)); }
    state.salt = salt;
    deriveMaster(pw).then(function (k) {
      var v = openVault(blob, k.key, k.hmacKey);
      state.key = k.key; state.hmacKey = k.hmacKey; state.vault = v; state.raw = blob;
      els.unlockPw.value = '';
      msg(els.unlockErr, '');
      afterUnlock(false);
    }).catch(function (e) {
      msg(els.unlockErr, 'Wrong password.');
    }).then(function () { busy(els.unlockGo, false); });
  }

  function syncStorageWarning() {
    // storageOK is the boot-time probe; storageLost means a write actually failed
    // later (Safari private mode: the probe passes, then setItem throws).
    var bad = !storageOK || !!state.storageLost;
    if (els.storeWarn) els.storeWarn.classList.toggle('hidden', !bad);
    return bad;
  }

  function afterUnlock(fresh) {
    var bad = syncStorageWarning();
    show('unlocked');
    renderList();
    if (bad) {
      msg(els.msgArea, 'This browser blocked local storage, so your codes will vanish when the page closes. Export an encrypted backup before you leave.', 'warn');
    } else {
      msg(els.msgArea, '', '');
    }
  }

  function lock() {
    state.key = null; state.hmacKey = null; state.vault = null; state.revealed = {};
    els.list.innerHTML = ''; els.list.dataset.sig = '';
    els.filter.value = ''; state.filter = '';
    msg(els.msgArea, '');
    show('locked');
  }

  function busy(btn, on) {
    if (!btn) return;
    btn.disabled = on;
    btn.textContent = on ? 'Working…' : btn.dataset.label || btn.textContent;
    if (!on && btn.dataset.label) btn.textContent = btn.dataset.label;
  }

  /* ---------------- add / import ---------------- */
  function doAdd() {
    var secret = normalizeSecret(els.addSecret.value);
    if (!secret) return msg(els.addErr, 'Secret key is required.');
    if (!validSecret(secret)) return msg(els.addErr, 'That does not look like a base32 secret (letters A-Z and digits 2-7, e.g. JBSWY3DPEHPK3PXP).');
    var e = {
      id: newId(),
      issuer: els.addIssuer.value.trim(),
      label: els.addLabel.value.trim(),
      secret: secret,
      digits: parseInt(els.addDigits.value, 10) || 6,
      period: parseInt(els.addPeriod.value, 10) || 30,
      algo: els.addAlgo.value,
      type: 'totp', counter: 0
    };
    state.vault.entries.push(e);
    persist();
    els.addIssuer.value = ''; els.addLabel.value = ''; els.addSecret.value = '';
    msg(els.addErr, '');
    renderList();
    flash('Account added');
  }

  function safeDecode(s) {
    try { return decodeURIComponent(s); } catch (e) { return null; }
  }

  function parseOtpauth(line) {
    // Malformed input (e.g. a stray '%') must never throw: the caller imports
    // line by line and an exception would abort the whole batch mid-way.
    try {
      var m = /^otpauth:\/\/(totp|hotp)\/([^?]*)\?(.*)$/i.exec(line.trim());
      if (!m) return null;
      var type = m[1].toLowerCase();
      var label = safeDecode(m[2]);
      var params = {};
      var bad = false;
      m[3].split('&').forEach(function (kv) {
        var i = kv.indexOf('=');
        if (i < 0) return;
        var v = safeDecode(kv.slice(i + 1).replace(/\+/g, ' '));
        if (v === null) { bad = true; return; }
        params[kv.slice(0, i).toLowerCase()] = v;
      });
      if (bad || label === null) return null;
      var secret = normalizeSecret(params.secret || '');
      if (!secret || !validSecret(secret)) return null;
      var issuer = params.issuer || '';
      var name = label.replace(/^.*:/, '');
      return {
        id: newId(), issuer: issuer, label: name || label, secret: secret,
        digits: parseInt(params.digits, 10) || 6,
        period: parseInt(params.period, 10) || 30,
        algo: (params.algorithm || 'SHA1').toUpperCase().replace('SHA-', 'SHA'),
        type: type, counter: parseInt(params.counter, 10) || 0
      };
    } catch (e) {
      return null;
    }
  }

  function doUriImport() {
    var lines = els.uriText.value.split(/[\r\n]+/);
    var added = 0, skipped = 0;
    lines.forEach(function (line) {
      line = line.trim();
      if (!line) return;
      var e = parseOtpauth(line);
      if (!e) {
        // maybe it's just a bare secret
        var s = normalizeSecret(line);
        if (validSecret(s)) {
          e = { id: newId(), issuer: '', label: '', secret: s, digits: 6, period: 30, algo: 'SHA1', type: 'totp', counter: 0 };
        }
      }
      if (!e) { skipped++; return; }
      var dup = state.vault.entries.some(function (x) { return x.secret === e.secret; });
      if (dup) { skipped++; return; }
      state.vault.entries.push(e); added++;
    });
    if (!added) return msg(els.uriErr, 'No valid entries found. Paste otpauth:// URIs (one per line) or bare base32 secrets.');
    persist(); renderList();
    els.uriText.value = '';
    msg(els.uriErr, '');
    flash(added + ' imported' + (skipped ? ', ' + skipped + ' skipped' : ''));
  }

  function doDbImport() {
    var f = els.dbFile.files && els.dbFile.files[0];
    if (!f) return msg(els.dbErr, 'Choose the authplus.db file first.');
    var pw = els.dbPw.value;
    if (!pw) return msg(els.dbErr, 'Enter the Authenticator Plus master password.');
    msg(els.dbErr, '');
    busy(els.dbGo, true);
    var reader = new FileReader();
    reader.onerror = function () { busy(els.dbGo, false); msg(els.dbErr, 'Could not read that file.'); };
    reader.onload = function () {
      var file = new Uint8Array(reader.result);
      S.decryptSqlcipherAsync(file, enc(pw), function (p) {
        msg(els.dbErr, 'Trying ' + p + '…', 'warn');
      }).then(function (r) {
        var parsed = S.parseDb(r.db);
        var out = S.extractAccounts(parsed);
        if (!out.entries.length) {
          busy(els.dbGo, false);
          if (r.partial) {
            return msg(els.dbErr, 'The database is damaged: page ' + r.failedPage +
              ' failed its integrity check before any accounts could be read. Try restoring the backup from the old app again.', 'err');
          }
          return msg(els.dbErr, 'Database opened, but no accounts were found. Tables: ' +
            parsed.tables.map(function (t) { return t.name; }).join(', '));
        }
        var added = 0, skipped = 0;
        out.entries.forEach(function (e) {
          if (!validSecret(e.secret)) { skipped++; return; }
          if (state.vault.entries.some(function (x) { return x.secret === e.secret; })) { skipped++; return; }
          e.id = newId();
          state.vault.entries.push(e);
          added++;
        });
        persist(); renderList();
        els.dbPw.value = ''; els.dbFile.value = '';
        busy(els.dbGo, false);
        msg(els.dbErr, '');
        if (r.partial) {
          // Some page failed its HMAC check and the database was truncated there,
          // so accounts stored after that point are missing.
          msg(els.dbErr, 'Only part of the database could be decrypted: page ' + r.failedPage +
            ' failed its integrity check, so ' + added + ' account' + (added === 1 ? '' : 's') +
            ' were recovered and any stored after that point are missing. The file may be truncated or damaged — check the old app before deleting it.', 'warn');
        } else {
          flash(added + ' accounts imported' + (skipped ? ', ' + skipped + ' skipped' : ''));
        }
      }).catch(function (e) {
        busy(els.dbGo, false);
        msg(els.dbErr, String(e.message || e) + ' The password is the one you set inside Authenticator Plus.');
      });
    };
    reader.readAsArrayBuffer(f);
  }

  /* ---------------- export / import vault ---------------- */
  function download(filename, text) {
    try {
      var blob = new Blob([text], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click();
      setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
      return true;
    } catch (e) { return false; }
  }

  function doExport() {
    persist();
    var d = new Date();
    var stamp = d.getFullYear() + ('0' + (d.getMonth() + 1)).slice(-2) + ('0' + d.getDate()).slice(-2);
    var okd = download('authenticator-vault-' + stamp + '.otpv1.json', state.raw);
    if (!okd) prompt('Copy this encrypted backup to a safe place:', state.raw);
    else flash('Encrypted backup saved');
  }
  function doExportPlain() {
    var n = (state.vault && state.vault.entries.length) || 0;
    if (!confirm('This writes all ' + n + ' secret key' + (n === 1 ? '' : 's') +
      ' to a file in PLAINTEXT, with no password protection.\n\nAnyone who gets that file can generate your codes. Continue?')) return;
    var d = new Date();
    var stamp = d.getFullYear() + ('0' + (d.getMonth() + 1)).slice(-2) + ('0' + d.getDate()).slice(-2);
    var text = JSON.stringify(state.vault, null, 2);
    var okd = download('authenticator-PLAINTEXT-' + stamp + '.json', text);
    if (!okd) prompt('Plaintext export (keep it safe!):', text);
    else flash('Plaintext export saved - keep it safe');
  }

  function confirmReplace() {
    var n = (state.vault && state.vault.entries.length) || 0;
    if (!n) return true;
    return confirm('Restoring replaces all ' + n + ' account' + (n === 1 ? '' : 's') +
      ' currently in this vault. They will not be merged.\n\nExport an encrypted backup first if you want to keep them.');
  }

  function doImportVault() {
    var f = els.importFile.files && els.importFile.files[0];
    if (!f) return msg(els.restoreErr, 'Choose a backup file first.');
    var pw = els.restorePw ? els.restorePw.value : '';
    msg(els.restoreErr, '');
    busy(els.restoreGo, true);
    var reader = new FileReader();
    reader.onerror = function () { busy(els.restoreGo, false); msg(els.restoreErr, 'Could not read that file.'); };
    reader.onload = function () {
      var text = dec(new Uint8Array(reader.result));
      var blob = text.trim();
      var finish = function () { busy(els.restoreGo, false); els.importFile.value = ''; els.restorePw.value = ''; };
      if (blob.charAt(0) === '{') {
        // plaintext vault: re-sealed under the current master password
        try {
          var v = JSON.parse(blob);
          if (!v || !Array.isArray(v.entries)) throw new Error('bad');
          v.entries.forEach(function (e, i) { if (!e.id) e.id = newId() + i; });
          if (!confirmReplace()) { finish(); return; }
          state.vault = v; persist(); renderList();
          flash('Plain vault imported');
        } catch (e) { msg(els.restoreErr, 'That JSON file is not a vault export.'); }
        finish();
        return;
      }
      if (blob.indexOf('OTPV1.') !== 0) {
        msg(els.restoreErr, 'That file is not a vault backup (expected OTPV1… or a plain JSON export).');
        finish();
        return;
      }
      if (!pw) { msg(els.restoreErr, 'Enter the password that sealed this backup.'); finish(); return; }
      var salt;
      try { salt = unb64(blob.split('.')[1]); }
      catch (e) { msg(els.restoreErr, 'Backup file is malformed.'); finish(); return; }
      var prevSalt = state.salt;
      state.salt = salt;
      deriveMaster(pw).then(function (k) {
        var v = openVault(blob, k.key, k.hmacKey);
        if (!confirmReplace()) { state.salt = prevSalt; finish(); return; }
        state.key = k.key; state.hmacKey = k.hmacKey; state.vault = v;
        persist(); renderList();
        flash('Backup restored');
        finish();
      }).catch(function () {
        state.salt = prevSalt;
        msg(els.restoreErr, 'Could not open that backup — wrong password or damaged file.');
        finish();
      });
    };
    reader.readAsArrayBuffer(f);
  }

  function doChangePw() {
    var oldPw = els.changePwOld ? els.changePwOld.value : '';
    var pw = els.changePw.value;
    if (!state.vault) return msg(els.changeErr, 'Unlock the vault first.');
    if (!oldPw) return msg(els.changeErr, 'Enter your current password.');
    if (pw.length < 6) return msg(els.changeErr, 'New password must be at least 6 characters.');

    var prevSalt = state.salt;
    var stored;
    try { stored = storeGet(STORE_KEY); } catch (e) { stored = null; }
    if (!stored) return msg(els.changeErr, 'Could not read the stored vault.');

    busy(els.changeGo, true);
    var step = Promise.resolve();
    // 1. verify the old password against the blob that is actually on disk
    step = step.then(function () {
      state.salt = unb64(stored.split('.')[1]);
      return deriveMaster(oldPw).then(function (k) {
        openVault(stored, k.key, k.hmacKey); // throws on wrong password
      });
    });
    // 2. only then re-seal with a fresh salt under the new password
    step = step.then(function () {
      state.salt = C.randomBytes(16);
      return deriveMaster(pw);
    }).then(function (nk) {
      state.key = nk.key; state.hmacKey = nk.hmacKey;
      persist();
      if (state.storageLost) throw new Error('storage');
      els.changePw.value = '';
      if (els.changePwOld) els.changePwOld.value = '';
      busy(els.changeGo, false);
      msg(els.changeErr, 'Password changed. Old backups still use the old password.', 'ok');
    }).catch(function (e) {
      state.salt = prevSalt;
      busy(els.changeGo, false);
      if (e && e.message === 'storage') {
        msg(els.changeErr, 'Password changed in this session, but this browser refused to save the vault. Export a backup now.', 'warn');
      } else {
        msg(els.changeErr, 'Current password is wrong.');
      }
    });
  }

  /* ---------------- boot ---------------- */
  function boot() {
    initEls();
    ['setupGo', 'unlockGo', 'addGo', 'dbGo', 'uriGo', 'exportBtn', 'exportPlainBtn',
      'restoreGo', 'changeGo', 'lockBtn'].forEach(function (id) {
        if (els[id]) els[id].dataset.label = els[id].textContent;
      });

    els.setupGo.addEventListener('click', doSetup);
    els.setupPw2.addEventListener('keydown', function (e) { if (e.key === 'Enter') doSetup(); });
    els.unlockGo.addEventListener('click', doUnlock);
    els.unlockPw.addEventListener('keydown', function (e) { if (e.key === 'Enter') doUnlock(); });
    els.lockBtn.addEventListener('click', lock);
    els.addGo.addEventListener('click', doAdd);
    els.dbGo.addEventListener('click', doDbImport);
    els.uriGo.addEventListener('click', doUriImport);
    els.exportBtn.addEventListener('click', doExport);
    els.exportPlainBtn.addEventListener('click', doExportPlain);
    els.restoreGo.addEventListener('click', doImportVault);
    els.changeGo.addEventListener('click', doChangePw);
    els.filter.addEventListener('input', function () { state.filter = els.filter.value; renderList(); });
    els.wipeBtn.addEventListener('click', function () {
      if (!confirm('Delete the vault stored on this device? Export a backup first if you need it.')) return;
      storeDel(STORE_KEY); lock(); show('setup');
    });

    var blob = storeGet(STORE_KEY);
    show(blob ? 'locked' : 'setup');
    setInterval(function () { tick(false); }, 1000);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) tick(true); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
