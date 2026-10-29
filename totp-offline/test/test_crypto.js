const C = require('../src/crypto.js');
const nodeCrypto = require('crypto');
let pass = 0, fail = 0;
function eq(name, a, b) {
  const ok = a === b;
  if (ok) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + '\n        got: ' + a + '\n        exp: ' + b); }
}
function hex(b) { return Buffer.from(b).toString('hex'); }

console.log('--- hashes ---');
for (const m of ['', 'abc', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'hello world 世界 🌍', 'x'.repeat(1000)]) {
  const buf = Buffer.from(m, 'utf8');
  eq('sha1   ' + m.slice(0, 12), hex(C.sha1(buf)), nodeCrypto.createHash('sha1').update(buf).digest('hex'));
  eq('sha256 ' + m.slice(0, 12), hex(C.sha256(buf)), nodeCrypto.createHash('sha256').update(buf).digest('hex'));
  eq('sha512 ' + m.slice(0, 12), hex(C.sha512(buf)), nodeCrypto.createHash('sha512').update(buf).digest('hex'));
}

console.log('--- hmac ---');
{
  // RFC 2202 test case 1 (HMAC-SHA1, key 20x0b, "Hi There")
  const key = Buffer.alloc(20, 0x0b);
  eq('hmac-sha1 rfc2202', hex(C.hmacSha1(key, Buffer.from('Hi There'))), 'b617318655057264e28bc0b6fb378c8ef146be00');
  // RFC 4231 test case 2 (HMAC-SHA256, key "Jefe", "what do ya want for nothing?")
  eq('hmac-sha256 rfc4231', hex(C.hmacSha256(Buffer.from('Jefe'), Buffer.from('what do ya want for nothing?'))),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  // RFC 4231 test case 2 (HMAC-SHA512)
  eq('hmac-sha512 rfc4231', hex(C.hmacSha512(Buffer.from('Jefe'), Buffer.from('what do ya want for nothing?'))),
    '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737');
  const longKey = Buffer.from('k'.repeat(200));
  eq('hmac long key', hex(C.hmacSha256(longKey, Buffer.from('data'))),
    nodeCrypto.createHmac('sha256', longKey).update(Buffer.from('data')).digest('hex'));
}

console.log('--- pbkdf2 ---');
{
  // RFC 6070
  eq('pbkdf2-sha1 rfc6070', hex(C.pbkdf2(C.sha1, 64, 'password', 'salt', 1, 20)), '0c60c80f961f0e71f3a9b524af6012062fe037a6');
  eq('pbkdf2-sha1 rfc6070 i2', hex(C.pbkdf2(C.sha1, 64, 'password', 'salt', 2, 20)), 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');
  eq('pbkdf2-sha1 rfc6070 i4096', hex(C.pbkdf2(C.sha1, 64, 'password', 'salt', 4096, 20)), '4b007901b765489abead49d926f721d065a429c1');
  eq('pbkdf2-sha1 dkLen>20', hex(C.pbkdf2(C.sha1, 64, 'password', 'salt', 8, 32)),
    nodeCrypto.pbkdf2Sync('password', 'salt', 8, 32, 'sha1').toString('hex'));
  eq('pbkdf2-sha256 vs node', hex(C.pbkdf2(C.sha256, 64, 'pw', 'some salt', 100, 32)),
    nodeCrypto.pbkdf2Sync('pw', 'some salt', 100, 32, 'sha256').toString('hex'));
  eq('pbkdf2-sha512 vs node', hex(C.pbkdf2(C.sha512, 128, 'pw', 'some salt', 50, 64)),
    nodeCrypto.pbkdf2Sync('pw', 'some salt', 50, 64, 'sha512').toString('hex'));
}

console.log('--- aes-256-cbc ---');
{
  const key = nodeCrypto.randomBytes(32), iv = nodeCrypto.randomBytes(16);
  for (const n of [16, 32, 48, 160, 1024]) {
    const pt = nodeCrypto.randomBytes(n);
    const enc = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
    enc.setAutoPadding(false);
    const ref = enc.update(pt, null, 'hex') + enc.final('hex');
    eq('aes enc ' + n, hex(C.cbcEncrypt(key, iv, pt)), ref);
    eq('aes dec ' + n, hex(C.cbcDecrypt(key, iv, Buffer.from(ref, 'hex'))), pt.toString('hex'));
  }
  const nistKey = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
  const nistPt = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  eq('aes-256 block (NIST)', hex(C.aesEncryptBlock(C.keyExpansion(nistKey), nistPt)), '8ea2b7ca516745bfeafc49904b496089');
  eq('aes-256 block inv', hex(C.aesDecryptBlock(C.keyExpansion(nistKey), Buffer.from('8ea2b7ca516745bfeafc49904b496089', 'hex'))), nistPt.toString('hex'));
  // NIST SP800-38A F.2.5 CBC-AES256 first block
  const k2 = Buffer.from('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'hex');
  const iv2 = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const p2 = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');
  eq('aes-256-cbc NIST F.2.5', hex(C.cbcEncrypt(k2, iv2, p2)), 'f58c4c04d6e5f1ba779eabfb5f7bfbd6');
}

console.log('--- base32 ---');
{
  eq('b32 enc/dec roundtrip', C.base32Encode(C.base32Decode('MZXW6YTBOI======')), 'MZXW6YTBOI');
  eq('b32 decode foo', Buffer.from(C.base32Decode('MZXW6===')).toString(), 'foo');
  eq('b32 decode foobar', Buffer.from(C.base32Decode('MZXW6YTBOI======')).toString(), 'foobar');
  const rnd = nodeCrypto.randomBytes(20);
  eq('b32 roundtrip rnd', C.base32Decode(C.base32Encode(rnd)).length > 0 ? Buffer.from(C.base32Decode(C.base32Encode(rnd))).toString('hex').slice(0, 40) : '', rnd.toString('hex').slice(0, 40));
}

console.log('--- TOTP (RFC 6238) ---');
{
  // RFC 6238 uses per-algorithm key lengths: 20 / 32 / 64 bytes
  const s1 = Buffer.from('12345678901234567890');
  const s256 = Buffer.from('12345678901234567890123456789012');
  const s512 = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234');
  eq('secret == RFC bytes', Buffer.from(C.base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')).toString(), s1.toString());
  eq('totp sha1   T=59', C.totp(s1, 8, 30, 'SHA1', 59), '94287082');
  eq('totp sha256 T=59', C.totp(s256, 8, 30, 'SHA256', 59), '46119246');
  eq('totp sha512 T=59', C.totp(s512, 8, 30, 'SHA512', 59), '90693936');
  eq('totp sha1   T=1111111109', C.totp(s1, 8, 30, 'SHA1', 1111111109), '07081804');
  eq('totp sha256 T=1111111109', C.totp(s256, 8, 30, 'SHA256', 1111111109), '68084774');
  eq('totp sha512 T=1111111109', C.totp(s512, 8, 30, 'SHA512', 1111111109), '25091201');
  eq('totp sha1   T=2000000000', C.totp(s1, 8, 30, 'SHA1', 2000000000), '69279037');
  eq('totp sha1   6-digit T=59', C.totp(s1, 6, 30, 'SHA1', 59), '287082');
  eq('totp period 60 T=59', C.totp(s1, 8, 60, 'SHA1', 59), C.hotp(s1, 0, 8, 'SHA1'));
  // Steam-style 5-digit / 7-digit sanity (just check length + determinism)
  eq('totp 7-digit len', String(C.totp(s1, 7, 30, 'SHA1', 59)).length, 7);
  eq('hotp counter 0', C.hotp(s1, 0, 6, 'SHA1'), '755224');
  eq('hotp counter 1', C.hotp(s1, 1, 6, 'SHA1'), '287082');
}

console.log('--- helpers ---');
{
  const b = nodeCrypto.randomBytes(64);
  eq('b64 roundtrip', Buffer.from(C.fromB64(C.toB64(b))).toString('hex'), b.toString('hex'));
  eq('utf8 roundtrip', C.utf8Str(C.utf8Bytes('中文abc 🌍 test')), '中文abc 🌍 test');
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
