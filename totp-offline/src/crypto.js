/* Pure-JS crypto core: SHA-1/256/512, HMAC, PBKDF2, AES-256-CBC, Base32, HOTP/TOTP.
   No external dependencies, no WebCrypto requirement (works from file:// too). */
(function (global) {
  'use strict';

  /* ---------------- bytes / text helpers ---------------- */
  function utf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xC0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else {
        c -= 0x10000;
        out.push(0xF0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      }
    }
    return new Uint8Array(out);
  }
  function utf8Str(b) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(b);
    var s = '', i = 0;
    while (i < b.length) {
      var c = b[i++];
      if (c < 0x80) s += String.fromCharCode(c);
      else if (c < 0xE0) s += String.fromCharCode(((c & 31) << 6) | (b[i++] & 63));
      else if (c < 0xF0) s += String.fromCharCode(((c & 15) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63));
      else {
        var u = ((c & 7) << 18) | ((b[i++] & 63) << 12) | ((b[i++] & 63) << 6) | (b[i++] & 63);
        s += String.fromCharCode(0xD800 + ((u - 0x10000) >> 10), 0xDC00 + ((u - 0x10000) & 1023));
      }
    }
    return s;
  }
  function bytesToHex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) { var h = b[i].toString(16); s += h.length < 2 ? '0' + h : h; }
    return s;
  }
  function hexToBytes(h) {
    h = String(h).replace(/[^0-9a-fA-F]/g, '');
    var out = new Uint8Array(h.length >> 1);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  function concatBytes(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }
  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    var d = 0;
    for (var i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }
  function toB64(b) {
    var s = '', CH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    for (var i = 0; i < b.length; i += 3) {
      var n = (b[i] << 16) | ((i + 1 < b.length ? b[i + 1] : 0) << 8) | (i + 2 < b.length ? b[i + 2] : 0);
      var r = b.length - i;
      s += CH[(n >> 18) & 63] + CH[(n >> 12) & 63] + (r > 1 ? CH[(n >> 6) & 63] : '=') + (r > 2 ? CH[n & 63] : '=');
    }
    return s;
  }
  function fromB64(str) {
    var CH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    str = String(str).replace(/[^A-Za-z0-9+/]/g, '');
    var out = [], buf = 0, bits = 0;
    for (var i = 0; i < str.length; i++) {
      buf = (buf << 6) | CH.indexOf(str[i]); bits += 6;
      if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
    }
    return new Uint8Array(out);
  }
  function randomBytes(n) {
    var out = new Uint8Array(n);
    if (global.crypto && global.crypto.getRandomValues) { global.crypto.getRandomValues(out); return out; }
    if (global.msCrypto && global.msCrypto.getRandomValues) { global.msCrypto.getRandomValues(out); return out; }
    if (typeof require === 'function') { try { return new Uint8Array(require('crypto').randomBytes(n)); } catch (e) { } }
    // Never fall back to Math.random: these bytes are the vault salt and IV.
    // Failing loudly is far better than encrypting secrets with guessable values.
    throw new Error('This browser does not provide a secure random number generator (crypto.getRandomValues), so codes cannot be encrypted safely here.');
  }

  /* ---------------- bigint helpers (for constant generation) ---------------- */
  function isqrt(n) {
    if (n < 2n) return n;
    var x = 1n << BigInt(Math.ceil(n.toString(2).length / 2));
    while (true) { var y = (x + n / x) >> 1n; if (y >= x) break; x = y; }
    return x;
  }
  function icbrt(n) {
    if (n < 2n) return n;
    var x = 1n << BigInt(Math.ceil(n.toString(2).length / 3));
    while (true) { var y = (2n * x + n / (x * x)) / 3n; if (y >= x) break; x = y; }
    return x;
  }
  function firstPrimes(n) {
    var out = [], v = 2;
    while (out.length < n) {
      var ok = true;
      for (var i = 0; i < out.length && out[i] * out[i] <= v; i++) if (v % out[i] === 0) { ok = false; break; }
      if (ok) out.push(v);
      v++;
    }
    return out;
  }

  /* ---------------- SHA-1 ---------------- */
  function sha1(msg) {
    msg = msg instanceof Uint8Array ? msg : utf8Bytes(String(msg));
    var len = msg.length;
    var total = (((len + 8) >> 6) + 1) << 6;
    var buf = new Uint8Array(total);
    buf.set(msg);
    buf[len] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(len * 8 / 4294967296), false);
    dv.setUint32(total - 4, (len * 8) >>> 0, false);
    var h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    var w = new Uint32Array(80);
    for (var off = 0; off < total; off += 64) {
      for (var t = 0; t < 16; t++) w[t] = dv.getUint32(off + t * 4, false);
      for (t = 16; t < 80; t++) w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
      var a = h0, b = h1, c = h2, d = h3, e = h4;
      for (t = 0; t < 80; t++) {
        var f, k;
        if (t < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        var tmp = (rotl32(a, 5) + f + e + k + w[t]) >>> 0;
        e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
    }
    var out = new Uint8Array(20), odv = new DataView(out.buffer);
    odv.setUint32(0, h0, false); odv.setUint32(4, h1, false); odv.setUint32(8, h2, false);
    odv.setUint32(12, h3, false); odv.setUint32(16, h4, false);
    return out;
  }
  function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

  /* ---------------- SHA-256 ---------------- */
  var K256 = null, H256 = null;
  function initSha256() {
    if (K256) return;
    var p = firstPrimes(64);
    H256 = new Uint32Array(8);
    for (var i = 0; i < 8; i++) H256[i] = Number(isqrt(BigInt(p[i]) << 64n) & 0xffffffffn);
    K256 = new Uint32Array(64);
    for (i = 0; i < 64; i++) K256[i] = Number(icbrt(BigInt(p[i]) << 96n) & 0xffffffffn);
  }
  function sha256(msg) {
    initSha256();
    msg = msg instanceof Uint8Array ? msg : utf8Bytes(String(msg));
    var len = msg.length;
    var total = (((len + 8) >> 6) + 1) << 6;
    var buf = new Uint8Array(total);
    buf.set(msg); buf[len] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(len * 8 / 4294967296), false);
    dv.setUint32(total - 4, (len * 8) >>> 0, false);
    var h = new Uint32Array(H256), w = new Uint32Array(64);
    for (var off = 0; off < total; off += 64) {
      for (var t = 0; t < 16; t++) w[t] = dv.getUint32(off + t * 4, false);
      for (t = 16; t < 64; t++) {
        var s0 = (rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18) ^ (w[t - 15] >>> 3)) >>> 0;
        var s1 = (rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19) ^ (w[t - 2] >>> 10)) >>> 0;
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (t = 0; t < 64; t++) {
        var S1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0;
        var ch = ((e & f) ^ (~e & g)) >>> 0;
        var t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
        var S0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0;
        var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        var t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = new Uint8Array(32), odv = new DataView(out.buffer);
    for (var i = 0; i < 8; i++) odv.setUint32(i * 4, h[i], false);
    return out;
  }
  function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  /* ---------------- SHA-512 (BigInt based, used rarely) ---------------- */
  var K512 = null, H512 = null;
  function initSha512() {
    if (K512) return;
    var p = firstPrimes(80), M = (1n << 64n) - 1n;
    H512 = []; K512 = [];
    for (var i = 0; i < 8; i++) H512.push(isqrt(BigInt(p[i]) << 128n) & M);
    for (i = 0; i < 80; i++) K512.push(icbrt(BigInt(p[i]) << 192n) & M);
  }
  function sha512(msg) {
    initSha512();
    msg = msg instanceof Uint8Array ? msg : utf8Bytes(String(msg));
    var len = msg.length;
    var total = (((len + 16) >> 7) + 1) << 7;
    var buf = new Uint8Array(total);
    buf.set(msg); buf[len] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(total - 4, (len * 8) >>> 0, false);
    var M = (1n << 64n) - 1n;
    var rotr = function (x, n) { return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & M; };
    var h = H512.slice();
    var w = new Array(80);
    for (var off = 0; off < total; off += 128) {
      for (var t = 0; t < 16; t++) {
        w[t] = (BigInt(dv.getUint32(off + t * 8, false)) << 32n) | BigInt(dv.getUint32(off + t * 8 + 4, false));
      }
      for (t = 16; t < 80; t++) {
        var s0 = rotr(w[t - 15], 1) ^ rotr(w[t - 15], 8) ^ (w[t - 15] >> 7n);
        var s1 = rotr(w[t - 2], 19) ^ rotr(w[t - 2], 61) ^ (w[t - 2] >> 6n);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & M;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (t = 0; t < 80; t++) {
        var S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        var ch = (e & f) ^ (~e & g & M);
        var t1 = (hh + S1 + ch + K512[t] + w[t]) & M;
        var S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) & M;
        hh = g; g = f; f = e; e = (d + t1) & M; d = c; c = b; b = a; a = (t1 + t2) & M;
      }
      h[0] = (h[0] + a) & M; h[1] = (h[1] + b) & M; h[2] = (h[2] + c) & M; h[3] = (h[3] + d) & M;
      h[4] = (h[4] + e) & M; h[5] = (h[5] + f) & M; h[6] = (h[6] + g) & M; h[7] = (h[7] + hh) & M;
    }
    var out = new Uint8Array(64), odv = new DataView(out.buffer);
    for (var i = 0; i < 8; i++) {
      odv.setUint32(i * 8, Number((h[i] >> 32n) & 0xffffffffn), false);
      odv.setUint32(i * 8 + 4, Number(h[i] & 0xffffffffn), false);
    }
    return out;
  }

  /* ---------------- HMAC ---------------- */
  function hmac(hashFn, blockSize, key, msg) {
    key = key instanceof Uint8Array ? key : utf8Bytes(String(key));
    msg = msg instanceof Uint8Array ? msg : utf8Bytes(String(msg));
    if (key.length > blockSize) key = hashFn(key);
    var ipad = new Uint8Array(blockSize), opad = new Uint8Array(blockSize);
    ipad.fill(0x36); opad.fill(0x5c);
    for (var i = 0; i < blockSize; i++) {
      var k = i < key.length ? key[i] : 0;
      ipad[i] ^= k; opad[i] ^= k;
    }
    var inner = hashFn(concatBytes(ipad, msg));
    return hashFn(concatBytes(opad, inner));
  }
  function hmacSha1(k, m) { return hmac(sha1, 64, k, m); }
  function hmacSha256(k, m) { return hmac(sha256, 64, k, m); }
  function hmacSha512(k, m) { return hmac(sha512, 128, k, m); }

  /* ---------------- PBKDF2 ---------------- */
  function pbkdf2(hashFn, blockSize, pass, salt, iter, dkLen) {
    pass = pass instanceof Uint8Array ? pass : utf8Bytes(String(pass));
    salt = salt instanceof Uint8Array ? salt : utf8Bytes(String(salt));
    var hLen = hashFn(new Uint8Array(0)).length;
    var blocks = Math.ceil(dkLen / hLen);
    var out = new Uint8Array(blocks * hLen);
    var u = new Uint8Array(blockSize), t = new Uint8Array(blockSize);
    for (var b = 1; b <= blocks; b++) {
      var saltBlock = concatBytes(salt, new Uint8Array([(b >> 24) & 255, (b >> 16) & 255, (b >> 8) & 255, b & 255]));
      u = hmac(hashFn, blockSize, pass, saltBlock);
      t.set(u);
      for (var i = 1; i < iter; i++) {
        u = hmac(hashFn, blockSize, pass, u);
        for (var j = 0; j < hLen; j++) t[j] ^= u[j];
      }
      out.set(t.subarray(0, hLen), (b - 1) * hLen);
    }
    return out.subarray(0, dkLen);
  }
  /* Async version: uses WebCrypto when available (much faster), else pure JS. */
  function pbkdf2Async(alg, pass, salt, iter, dkLen) {
    // accept 'SHA1' / 'SHA-1' / 'sha256' ... WebCrypto needs the dashed form
    var a = String(alg).toUpperCase().replace(/-/g, '');
    var webName = a === 'SHA1' ? 'SHA-1' : (a === 'SHA512' ? 'SHA-512' : 'SHA-256');
    var fn = a === 'SHA1' ? sha1 : (a === 'SHA512' ? sha512 : sha256);
    var bs = a === 'SHA512' ? 128 : 64;
    var sub = global.crypto && global.crypto.subtle;
    var passBytes = pass instanceof Uint8Array ? pass : utf8Bytes(String(pass));
    var saltBytes = salt instanceof Uint8Array ? salt : utf8Bytes(String(salt));
    if (!sub || typeof Promise === 'undefined') {
      return Promise.resolve(pbkdf2(fn, bs, passBytes, saltBytes, iter, dkLen));
    }
    try {
      return sub.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits']).then(function (k) {
        return sub.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: webName }, k, dkLen * 8);
      }).then(function (bits) {
        return new Uint8Array(bits);
      }).catch(function () {
        return pbkdf2(fn, bs, passBytes, saltBytes, iter, dkLen);
      });
    } catch (e) {
      return Promise.resolve(pbkdf2(fn, bs, pass, salt, iter, dkLen));
    }
  }

  /* ---------------- AES-256 ---------------- */
  var SBOX = null, INV_SBOX = null;
  function gmul(a, b) {
    var r = 0;
    for (var i = 0; i < 8; i++) {
      if (b & 1) r ^= a;
      var hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return r & 0xff;
  }
  function aesInit() {
    if (SBOX) return;
    var i, j;
    // multiplicative inverses in GF(2^8) (AES polynomial 0x11b is irreducible but NOT
    // primitive, so x has order 51 - log/antilog tables over 2^i would be wrong.
    // brute force is 65k multiplies, a few ms, and impossible to get subtly wrong.
    var inv = new Uint8Array(256);
    inv[0] = 0;
    for (i = 1; i < 256; i++) {
      for (j = 1; j < 256; j++) { if (gmul(i, j) === 1) { inv[i] = j; break; } }
    }
    SBOX = new Uint8Array(256); INV_SBOX = new Uint8Array(256);
    var rotl8 = function (v, n) { return ((v << n) | (v >> (8 - n))) & 0xff; };
    for (i = 0; i < 256; i++) {
      var b = inv[i];
      SBOX[i] = (b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63) & 0xff;
    }
    for (i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
  }
  function keyExpansion(key) {
    aesInit();
    if (key.length !== 32) throw new Error('AES-256 needs a 32-byte key, got ' + key.length);
    var rk = new Uint8Array(240), i, j;
    rk.set(key, 0);
    var rcon = 1, t = [0, 0, 0, 0];
    for (i = 32; i < 240; i += 4) {
      t[0] = rk[i - 4]; t[1] = rk[i - 3]; t[2] = rk[i - 2]; t[3] = rk[i - 1];
      if (i % 32 === 0) {
        var tmp = t[0];
        t[0] = SBOX[t[1]] ^ rcon; t[1] = SBOX[t[2]]; t[2] = SBOX[t[3]]; t[3] = SBOX[tmp];
        rcon = ((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0)) & 0xff;
      } else if (i % 32 === 16) {
        for (j = 0; j < 4; j++) t[j] = SBOX[t[j]];
      }
      rk[i] = rk[i - 32] ^ t[0]; rk[i + 1] = rk[i - 31] ^ t[1];
      rk[i + 2] = rk[i - 30] ^ t[2]; rk[i + 3] = rk[i - 29] ^ t[3];
    }
    return rk;
  }
  function addRoundKey(s, rk, off) { for (var i = 0; i < 16; i++) s[i] ^= rk[off + i]; }
  function subBytes(s) { for (var i = 0; i < 16; i++) s[i] = SBOX[s[i]]; }
  function invSubBytes(s) { for (var i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]]; }
  function shiftRows(s) {
    var t = new Uint8Array(16), r, c;
    for (r = 0; r < 4; r++) for (c = 0; c < 4; c++) t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
    s.set(t);
  }
  function invShiftRows(s) {
    var t = new Uint8Array(16), r, c;
    for (r = 0; r < 4; r++) for (c = 0; c < 4; c++) t[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
    s.set(t);
  }
  function mixColumns(s) {
    var t = new Uint8Array(16), c;
    for (c = 0; c < 4; c++) {
      var o = 4 * c, a0 = s[o], a1 = s[o + 1], a2 = s[o + 2], a3 = s[o + 3];
      t[o] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
      t[o + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
      t[o + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
      t[o + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
    s.set(t);
  }
  function invMixColumns(s) {
    var t = new Uint8Array(16), c;
    for (c = 0; c < 4; c++) {
      var o = 4 * c, a0 = s[o], a1 = s[o + 1], a2 = s[o + 2], a3 = s[o + 3];
      t[o] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
      t[o + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
      t[o + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
      t[o + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
    s.set(t);
  }
  function aesEncryptBlock(rk, block) {
    var s = new Uint8Array(block);
    addRoundKey(s, rk, 0);
    for (var r = 1; r < 14; r++) { subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s, rk, r * 16); }
    subBytes(s); shiftRows(s); addRoundKey(s, rk, 224);
    return s;
  }
  function aesDecryptBlock(rk, block) {
    var s = new Uint8Array(block);
    addRoundKey(s, rk, 224);
    for (var r = 13; r >= 1; r--) { invShiftRows(s); invSubBytes(s); addRoundKey(s, rk, r * 16); invMixColumns(s); }
    invShiftRows(s); invSubBytes(s); addRoundKey(s, rk, 0);
    return s;
  }
  function cbcEncrypt(key, iv, data) {
    var rk = keyExpansion(key);
    var out = new Uint8Array(data.length), prev = new Uint8Array(iv), blk = new Uint8Array(16);
    for (var i = 0; i < data.length; i += 16) {
      for (var j = 0; j < 16; j++) blk[j] = data[i + j] ^ prev[j];
      prev = aesEncryptBlock(rk, blk);
      out.set(prev, i);
    }
    return out;
  }
  function cbcDecrypt(key, iv, data) {
    var rk = keyExpansion(key);
    var out = new Uint8Array(data.length), prev = new Uint8Array(iv), blk = new Uint8Array(16);
    for (var i = 0; i < data.length; i += 16) {
      blk.set(data.subarray(i, i + 16));
      var d = aesDecryptBlock(rk, blk);
      for (var j = 0; j < 16; j++) out[i + j] = d[j] ^ prev[j];
      prev.set(data.subarray(i, i + 16));
    }
    return out;
  }

  /* ---------------- Base32 (RFC 4648) ---------------- */
  function base32Decode(str) {
    var A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    str = String(str).toUpperCase().replace(/[=\s\r\n-]/g, '');
    var bits = 0, value = 0, out = [];
    for (var i = 0; i < str.length; i++) {
      // strict RFC 4648 alphabet: no 0/1/8 look-alike leniency, a wrong key
      // must fail instead of silently producing a different secret.
      var idx = A.indexOf(str[i]);
      if (idx < 0) throw new Error('Invalid base32 character: ' + str[i]);
      value = (value << 5) | idx; bits += 5;
      if (bits >= 8) { bits -= 8; out.push((value >> bits) & 0xff); }
    }
    return new Uint8Array(out);
  }
  function base32Encode(bytes) {
    var A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var out = '', bits = 0, value = 0;
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i]; bits += 8;
      while (bits >= 5) { bits -= 5; out += A[(value >> bits) & 31]; }
    }
    if (bits > 0) out += A[(value << (5 - bits)) & 31];
    return out;
  }

  /* ---------------- HOTP / TOTP ---------------- */
  function hotp(secretBytes, counter, digits, algo) {
    var msg = new Uint8Array(8);
    var hi = Math.floor(counter / 4294967296);
    msg[0] = (hi >>> 24) & 0xff; msg[1] = (hi >>> 16) & 0xff; msg[2] = (hi >>> 8) & 0xff; msg[3] = hi & 0xff;
    msg[4] = (counter >>> 24) & 0xff; msg[5] = (counter >>> 16) & 0xff; msg[6] = (counter >>> 8) & 0xff; msg[7] = counter & 0xff;
    var mac;
    if (algo === 'SHA256') mac = hmacSha256(secretBytes, msg);
    else if (algo === 'SHA512') mac = hmacSha512(secretBytes, msg);
    else mac = hmacSha1(secretBytes, msg);
    var off = mac[mac.length - 1] & 0x0f;
    var bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
    var code = bin % Math.pow(10, digits || 6);
    return String(code).padStart(digits || 6, '0').slice(-(digits || 6));
  }
  function totp(secretBytes, digits, period, algo, unixSeconds) {
    var t = (unixSeconds === undefined ? Math.floor(Date.now() / 1000) : unixSeconds);
    period = period || 30;
    return hotp(secretBytes, Math.floor(t / period), digits || 6, algo || 'SHA1');
  }
  function totpRemaining(period, unixSeconds) {
    var t = (unixSeconds === undefined ? Math.floor(Date.now() / 1000) : unixSeconds);
    return (period || 30) - (t % (period || 30));
  }

  var api = {
    utf8Bytes: utf8Bytes, utf8Str: utf8Str, bytesToHex: bytesToHex, hexToBytes: hexToBytes,
    concatBytes: concatBytes, bytesEqual: bytesEqual, toB64: toB64, fromB64: fromB64, randomBytes: randomBytes,
    sha1: sha1, sha256: sha256, sha512: sha512,
    hmac: hmac, hmacSha1: hmacSha1, hmacSha256: hmacSha256, hmacSha512: hmacSha512,
    pbkdf2: pbkdf2, pbkdf2Async: pbkdf2Async,
    cbcEncrypt: cbcEncrypt, cbcDecrypt: cbcDecrypt,
    aesEncryptBlock: aesEncryptBlock, aesDecryptBlock: aesDecryptBlock, keyExpansion: keyExpansion,
    base32Decode: base32Decode, base32Encode: base32Encode,
    hotp: hotp, totp: totp, totpRemaining: totpRemaining
  };
  global.OTPCrypto = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
