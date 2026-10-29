/* Offline SQLCipher(3/4) decryptor + minimal SQLite b-tree reader.
   Used to pull secrets straight out of an Authenticator Plus `authplus.db`. */
(function (global) {
  'use strict';
  var C = global.OTPCrypto;
  var MAGIC = [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00];

  /* ---------- varint ---------- */
  function readVarint(b, p) {
    var v = 0n, i;
    for (i = 0; i < 8; i++) {
      v = (v << 7n) | BigInt(b[p + i] & 0x7f);
      if ((b[p + i] & 0x80) === 0) return { value: v, next: p + i + 1 };
    }
    v = (v << 8n) | BigInt(b[p + 8]);
    return { value: v, next: p + 9 };
  }
  function readU32BE(b, p) { return ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0; }
  function readU16BE(b, p) { return (b[p] << 8) | b[p + 1]; }
  function u32le(n) { return new Uint8Array([n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >> 24) & 255]); }
  function readSigned(b, p, n) {
    var v = 0, i;
    if (n === 8) {
      var hi = readU32BE(b, p), lo = readU32BE(b, p + 4);
      // 64-bit signed -> Number (approximate but fine here)
      return hi >= 0x80000000 ? -(0x10000000000000000 - (hi * 4294967296 + lo)) : hi * 4294967296 + lo;
    }
    for (i = 0; i < n; i++) v = v * 256 + b[p + i];
    var sign = 1 << (n * 8 - 1);
    return v >= sign ? v - sign * 2 : v;
  }

  /* ---------- SQLCipher ---------- */
  var HASHES = {
    'SHA1': { fn: function () { return C.sha1; }, bs: 64, sz: 20 },
    'SHA256': { fn: function () { return C.sha256; }, bs: 64, sz: 32 },
    'SHA512': { fn: function () { return C.sha512; }, bs: 128, sz: 64 }
  };

  function deriveKeysSync(passwordBytes, salt, cfg) {
    var h = HASHES[cfg.kdf];
    var encKey = C.pbkdf2(h.fn(), h.bs, passwordBytes, salt, cfg.iter, 32);
    var hs = new Uint8Array(salt.length);
    for (var i = 0; i < salt.length; i++) hs[i] = salt[i] ^ 0x3a;
    var hmacKey = C.pbkdf2(h.fn(), h.bs, encKey, hs, cfg.fastIter || 2, 32);
    return { encKey: encKey, hmacKey: hmacKey };
  }
  function deriveKeysAsync(passwordBytes, salt, cfg) {
    var h = HASHES[cfg.kdf];
    return C.pbkdf2Async(cfg.kdf, passwordBytes, salt, cfg.iter, 32).then(function (encKey) {
      var hs = new Uint8Array(salt.length);
      for (var i = 0; i < salt.length; i++) hs[i] = salt[i] ^ 0x3a;
      return C.pbkdf2Async(cfg.kdf, encKey, hs, cfg.fastIter || 2, 32).then(function (hmacKey) {
        return { encKey: encKey, hmacKey: hmacKey };
      });
    });
  }
  function pageMac(hmacKey, algo, data, pgno) {
    var h = HASHES[algo];
    var input = C.concatBytes(data, u32le(pgno));
    if (algo === 'SHA1') return C.hmacSha1(hmacKey, input);
    if (algo === 'SHA256') return C.hmacSha256(hmacKey, input);
    return C.hmacSha512(hmacKey, input);
  }

  /* Try one parameter combination. Returns plaintext db or null. */
  function tryParams(file, keys, cfg) {
    var pageSz = cfg.pageSz, reserve = cfg.reserve, hmacSz = HASHES[cfg.hmac].sz;
    var ph = cfg.plaintextHeader || 0;
    var off = ph ? ph : 16;
    var size1 = pageSz - off - reserve;
    var size = pageSz - reserve;
    if (size1 <= 0 || size <= 0) return null;
    if (file.length < off + size1 + 16 + hmacSz) return null;
    if (file.length % pageSz !== 0) return null;

    /* --- page 1 --- */
    var in1 = file.subarray(off, off + size1);
    var iv1 = file.subarray(off + size1, off + size1 + 16);
    var mac1 = file.subarray(off + size1 + 16, off + size1 + 16 + hmacSz);
    var calc1 = pageMac(keys.hmacKey, cfg.hmac, file.subarray(off, off + size1 + 16), 1);
    if (!C.bytesEqual(mac1, calc1.subarray(0, hmacSz))) return null;

    var body1 = C.cbcDecrypt(keys.encKey, iv1, in1);
    var head = ph ? file.subarray(0, ph) : new Uint8Array(MAGIC);
    var page1 = new Uint8Array(pageSz);
    page1.set(head.subarray(0, Math.min(head.length, off)), 0);
    page1.set(body1, off);
    for (var m = 0; m < 16; m++) if (page1[m] !== MAGIC[m]) return null;

    var declPage = readU16BE(page1, 16);
    if (declPage === 1) declPage = 65536;
    if (declPage !== pageSz) return null;
    if (page1[20] !== reserve) return null;

    /* --- remaining pages --- */
    var nPages = Math.floor(file.length / pageSz);
    var out = new Uint8Array(file.length);
    out.set(page1, 0);
    for (var n = 2; n <= nPages; n++) {
      var base = (n - 1) * pageSz;
      var data = file.subarray(base, base + size + 16);
      var macN = file.subarray(base + size + 16, base + size + 16 + hmacSz);
      var calcN = pageMac(keys.hmacKey, cfg.hmac, data, n);
      if (!C.bytesEqual(macN, calcN.subarray(0, hmacSz))) {
        return { partial: true, db: out.subarray(0, base), pageSz: pageSz, reserve: reserve, failedPage: n };
      }
      var plain = C.cbcDecrypt(keys.encKey, file.subarray(base + size, base + size + 16), file.subarray(base, base + size));
      out.set(plain, base);
    }
    return { db: out, pageSz: pageSz, reserve: reserve, cfg: cfg };
  }

  var PAGE_SIZES = [1024, 4096, 2048, 8192, 512, 16384, 32768, 65536];
  var RESERVES = [48, 16, 32, 64, 80, 96, 112, 128];

  function attempt(file, keys, base) {
    var tried = [];
    for (var pi = 0; pi < PAGE_SIZES.length; pi++) {
      for (var ri = 0; ri < RESERVES.length; ri++) {
        var cfg = {
          pageSz: PAGE_SIZES[pi], reserve: RESERVES[ri], hmac: base.hmac,
          kdf: base.kdf, iter: base.iter, fastIter: base.fastIter || 2,
          plaintextHeader: base.plaintextHeader || 0
        };
        var r = tryParams(file, keys, cfg);
        if (r) { r.tried = tried; return r; }
        tried.push(PAGE_SIZES[pi] + '/' + RESERVES[ri]);
      }
    }
    return null;
  }

  /* Ordered list of SQLCipher profiles to try.
     Note: SQLCipher 1 (no HMAC at all) is deliberately NOT listed. tryParams always
     verifies a page MAC, so a profile that cannot verify one could never succeed
     and would only burn PBKDF2 iterations. Supporting it would need a separate
     decrypt path with no integrity check, which this tool does not offer. */
  var PROFILES = [
    { name: 'SQLCipher 3 defaults', kdf: 'SHA1', hmac: 'SHA1', iter: 64000, plaintextHeader: 0 },
    { name: 'SQLCipher 3 (4k iter)', kdf: 'SHA1', hmac: 'SHA1', iter: 4000, plaintextHeader: 0 },
    { name: 'SQLCipher 4 defaults', kdf: 'SHA512', hmac: 'SHA512', iter: 256000, plaintextHeader: 32 },
    { name: 'SQLCipher 4 (plaintext hdr 32, sha1)', kdf: 'SHA1', hmac: 'SHA1', iter: 64000, plaintextHeader: 32 },
    { name: 'SQLCipher 4 defaults (no plaintext hdr)', kdf: 'SHA512', hmac: 'SHA512', iter: 256000, plaintextHeader: 0 },
    { name: 'SHA256 kdf/hmac, 64000', kdf: 'SHA256', hmac: 'SHA256', iter: 64000, plaintextHeader: 0 }
  ];

  // Sync path has no WebCrypto (or it failed): skip the very slow SHA-512 profiles.
  var PROFILES_SYNC = PROFILES.filter(function (p) { return p.kdf !== 'SHA512'; });

  function decryptSqlcipherSync(file, passwordBytes) {
    if (file.length < 512) throw new Error('File too small to be a SQLite database');
    var salt = file.subarray(0, 16);
    var errors = [];
    for (var i = 0; i < PROFILES_SYNC.length; i++) {
      var p = PROFILES_SYNC[i];
      var keys;
      try { keys = deriveKeysSync(passwordBytes, salt, p); }
      catch (e) { errors.push(p.name + ': ' + e.message); continue; }
      var r = attempt(file, keys, p);
      if (r) { r.profile = p.name; return r; }
      errors.push(p.name);
    }
    var err = new Error('Could not open the database — wrong password, or unsupported encryption settings.');
    err.tried = errors;
    throw err;
  }

  function decryptSqlcipherAsync(file, passwordBytes, onProgress) {
    if (file.length < 512) return Promise.reject(new Error('File too small to be a SQLite database'));
    var salt = file.subarray(0, 16);
    var i = 0;
    function next() {
      if (i >= PROFILES.length) {
        return Promise.reject(new Error('Could not open the database — wrong password, or unsupported encryption settings.'));
      }
      var p = PROFILES[i++];
      if (onProgress) onProgress(p.name);
      return deriveKeysAsync(passwordBytes, salt, p).then(function (keys) {
        // yield to the UI between heavy derivations
        return new Promise(function (res) { setTimeout(res, 0); }).then(function () {
          return { keys: keys, r: attempt(file, keys, p), p: p };
        });
      }).then(function (out) {
        if (out.r) { out.r.profile = out.p.name; return out.r; }
        return next();
      });
    }
    return next();
  }

  /* ---------- minimal SQLite reader ---------- */
  function parseDb(db) {
    var pageSz = readU16BE(db, 16); if (pageSz === 1) pageSz = 65536;
    var reserved = db[20];
    var usable = pageSz - reserved;
    var nPages = readU32BE(db, 28);
    if (nPages * pageSz > db.length) nPages = Math.floor(db.length / pageSz);

    function page(n) { return db.subarray((n - 1) * pageSz, n * pageSz); }
    function cellPayload(pageBytes, off, isLeaf) {
      var vi = readVarint(pageBytes, off);
      var payloadSize = Number(vi.value);
      var p = vi.next;
      var rowid = null;
      if (isLeaf) { var rv = readVarint(pageBytes, p); rowid = rv.value; p = rv.next; }
      var maxLocal = usable - 35;
      var minLocal = Math.floor((usable - 12) * 32 / 255) - 23;
      var local = payloadSize;
      var overflow = null;
      if (payloadSize > maxLocal) {
        local = minLocal + ((payloadSize - minLocal) % (usable - 4));
        if (local > maxLocal) local = minLocal;
        overflow = readU32BE(pageBytes, off + (p - off) + local);
      }
      var bytes = pageBytes.subarray(p, p + local);
      if (overflow) {
        var chunks = [bytes], pg = overflow, guard = 0;
        while (pg && guard++ < 100000) {
          var op = page(pg);
          var nxt = readU32BE(op, 0);
          chunks.push(op.subarray(4, usable));
          pg = nxt;
        }
        var total = 0; for (var i = 0; i < chunks.length; i++) total += chunks[i].length;
        var all = new Uint8Array(total), at = 0;
        for (i = 0; i < chunks.length; i++) { all.set(chunks[i], at); at += chunks[i].length; }
        bytes = all.subarray(0, payloadSize);
      }
      return { payload: bytes, rowid: rowid };
    }
    function decodeRecord(payload) {
      var hv = readVarint(payload, 0);
      var hdrSize = Number(hv.value);
      var p = hv.next, end = hdrSize;
      var types = [];
      while (p < end && p < payload.length) { var t = readVarint(payload, p); types.push(Number(t.value)); p = t.next; }
      var bp = hdrSize, vals = [];
      for (var i = 0; i < types.length; i++) {
        var t2 = types[i], len;
        if (t2 === 0) { vals.push(null); }
        else if (t2 >= 1 && t2 <= 6) { len = [0, 1, 2, 3, 4, 6, 8][t2]; vals.push(readSigned(payload, bp, len)); bp += len; }
        else if (t2 === 7) {
          var dv = new DataView(payload.buffer, payload.byteOffset + bp, 8);
          vals.push(dv.getFloat64(0, false)); bp += 8;
        }
        else if (t2 === 8) { vals.push(0); }
        else if (t2 === 9) { vals.push(1); }
        else if (t2 === 10 || t2 === 11) { vals.push(null); }
        else if (t2 % 2 === 0) { len = (t2 - 12) / 2; vals.push(payload.subarray(bp, bp + len)); bp += len; }
        else { len = (t2 - 13) / 2; vals.push(C.utf8Str(payload.subarray(bp, bp + len))); bp += len; }
      }
      return vals;
    }
    function walk(root, cb) {
      var stack = [root], seen = {};
      while (stack.length) {
        var pgno = stack.pop();
        if (seen[pgno]) continue;
        seen[pgno] = 1;
        var pb = page(pgno);
        if (pb.length < 100) continue;
        var h = (pgno === 1) ? 100 : 0;
        var type = pb[h];
        var ncells = readU16BE(pb, h + 3);
        var i;
        if (type === 0x0d) {
          for (i = 0; i < ncells; i++) {
            var cp = h + 8 + i * 2;
            if (cp + 1 >= pb.length) break;
            var off = readU16BE(pb, cp);
            if (off < h || off >= usable) continue;
            try {
              var rec = cellPayload(pb, off, true);
              cb(decodeRecord(rec.payload), rec.rowid);
            } catch (e) { /* skip corrupt cell */ }
          }
        } else if (type === 0x05) {
          for (i = 0; i < ncells; i++) {
            var cp2 = h + 12 + i * 2;
            if (cp2 + 1 >= pb.length) break;
            var coff = readU16BE(pb, cp2);
            if (coff < h || coff >= usable) continue;
            stack.push(readU32BE(pb, coff));
          }
          stack.push(readU32BE(pb, h + 8));
        } else {
          // not a table b-tree page (index page or overflow) - ignore
        }
      }
    }

    var tables = [];
    var master = [];
    walk(1, function (vals) {
      // sqlite_master: type, name, tbl_name, rootpage, sql
      master.push({ type: vals[0], name: vals[1], tblName: vals[2], rootpage: vals[3], sql: vals[4] });
    });
    master.forEach(function (m) {
      if (m.type !== 'table') return;
      var t = { name: m.name, sql: m.sql, rootpage: m.rootpage, columns: parseColumns(m.sql || ''), rows: [] };
      if (t.rootpage && t.rootpage > 0) {
        try {
          walk(t.rootpage, function (vals) { t.rows.push(vals); });
        } catch (e) { t.error = e.message; }
      }
      tables.push(t);
    });
    return { pageSz: pageSz, reserved: reserved, usable: usable, nPages: nPages, tables: tables, master: master };
  }

  function parseColumns(sql) {
    var open = sql.indexOf('(');
    var close = sql.lastIndexOf(')');
    if (open < 0) return [];
    var body = sql.slice(open + 1, close < 0 ? sql.length : close);
    var parts = [], cur = '', depth = 0, q = null;
    for (var i = 0; i < body.length; i++) {
      var ch = body[i];
      if (q) { cur += ch; if (ch === q) q = null; continue; }
      if (ch === '"' || ch === "'" || ch === '`') { q = ch; cur += ch; continue; }
      if (ch === '[') { q = ']'; cur += ch; continue; }
      if (ch === '(') { depth++; cur += ch; continue; }
      if (ch === ')') { depth--; cur += ch; continue; }
      if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
      cur += ch;
    }
    if (cur.trim()) parts.push(cur);
    var cols = [];
    parts.forEach(function (p) {
      p = p.trim();
      if (!p) return;
      if (/^(constraint|primary|unique|check|foreign|exclude)\b/i.test(p)) return;
      var m = p.match(/^["'`\[]?([^"'`\[\]\s]+)/);
      if (m) cols.push(m[1]);
    });
    return cols;
  }

  /* ---------- Authenticator Plus specific extraction ---------- */
  function extractAccounts(parsed) {
    var warnings = [];
    var tables = parsed.tables.filter(function (t) { return t.rows.length > 0 || /accounts/i.test(t.name); });
    var t = null;
    tables.forEach(function (x) { if (/^accounts$/i.test(x.name)) t = x; });
    if (!t) {
      tables.forEach(function (x) {
        if (!t && x.columns.some(function (c) { return /^(secret|key|seed)$/i.test(c); })) t = x;
      });
    }
    if (!t) {
      return { entries: [], warnings: ['No "accounts" table found. Tables present: ' + parsed.tables.map(function (x) { return x.name; }).join(', ')] };
    }
    var cols = t.columns;
    function pick(obj, names, dflt) {
      for (var i = 0; i < names.length; i++) {
        var k = names[i];
        if (obj[k] !== undefined && obj[k] !== null && obj[k] !== '') return obj[k];
        var found = Object.keys(obj).filter(function (c) { return c.toLowerCase() === k.toLowerCase(); })[0];
        if (found !== undefined && obj[found] !== null && obj[found] !== '') return obj[found];
      }
      return dflt;
    }
    var entries = [];
    t.rows.forEach(function (row) {
      var o = {};
      cols.forEach(function (c, i) { o[c] = row[i]; });
      var secret = String(pick(o, ['secret', 'key', 'seed'], '') || '')
        .replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
      if (!secret) return;
      var label = String(pick(o, ['email', 'label', 'name', 'account', 'original_name', 'username'], '') || '');
      var issuer = String(pick(o, ['issuer', 'original_name', 'name'], '') || '');
      var digits = parseInt(pick(o, ['digits'], 6), 10);
      if (!digits || isNaN(digits)) digits = 6;
      var period = parseInt(pick(o, ['period', 'time_step'], 30), 10);
      if (!period || isNaN(period)) period = 30;
      var type = String(pick(o, ['type', 'otp_type'], 'totp') || 'totp').toLowerCase();
      var algo = String(pick(o, ['algorithm', 'algo'], 'SHA1') || 'SHA1').toUpperCase();
      if (algo === 'SHA-1') algo = 'SHA1';
      if (algo !== 'SHA1' && algo !== 'SHA256' && algo !== 'SHA512') algo = 'SHA1';
      entries.push({
        issuer: issuer, label: label, secret: secret,
        digits: digits, period: period, type: type === 'hotp' ? 'hotp' : 'totp',
        algo: algo,
        counter: parseInt(pick(o, ['counter'], 0), 10) || 0
      });
    });
    return { entries: entries, warnings: warnings, table: t.name, columns: cols };
  }

  var api = {
    decryptSqlcipherSync: decryptSqlcipherSync,
    decryptSqlcipherAsync: decryptSqlcipherAsync,
    deriveKeysSync: deriveKeysSync,
    deriveKeysAsync: deriveKeysAsync,
    tryParams: tryParams,
    parseDb: parseDb,
    parseColumns: parseColumns,
    extractAccounts: extractAccounts,
    readVarint: readVarint,
    PROFILES: PROFILES
  };
  global.OTPSqlite = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
