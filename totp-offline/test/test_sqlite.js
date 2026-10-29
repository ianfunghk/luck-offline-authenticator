const fs = require('fs');
const path = require('path');
require('../src/crypto.js');
const S = require('../src/sqlite.js');
const C = require('../src/crypto.js');

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (extra ? '\n        ' + extra : '')); }
}
function eq(name, a, b) {
  ok(name, a === b, 'got: ' + JSON.stringify(a).slice(0, 200) + '\n        exp: ' + JSON.stringify(b).slice(0, 200));
}
const FIX = path.join(__dirname, 'fixtures');

const main = async () => {
console.log('--- SQLite parser on a real sqlite3 db (300 rows, multi-page b-tree) ---');
{
  const db = new Uint8Array(fs.readFileSync(path.join(FIX, 'plain_real.db')));
  const exp = JSON.parse(fs.readFileSync(path.join(FIX, 'plain_real.expected.json'), 'utf8'));
  const p = S.parseDb(db);
  eq('page size', p.pageSz, 1024);
  eq('reserved', p.reserved, 0);
  const accounts = p.tables.find(t => t.name === 'accounts');
  ok('accounts table found', !!accounts);
  eq('columns parsed', JSON.stringify(accounts.columns), JSON.stringify(['email', 'issuer', 'secret', 'type']));
  eq('row count', accounts.rows.length, 300);
  const got = accounts.rows.map(r => r.join('|')).sort();
  const want = exp.rows.map(r => r.join('|')).sort();
  eq('all 300 rows match', JSON.stringify(got) === JSON.stringify(want), true);
  const cat = p.tables.find(t => t.name === 'category');
  eq('second table rows', cat.rows.length, 20);
  eq('second table first row', cat.rows[0].join('|'), 'cat0|0');
}

console.log('--- SQLCipher 3 decrypt (fixture built with openssl + hashlib) ---');
{
  const file = new Uint8Array(fs.readFileSync(path.join(FIX, 'authplus_sample.db')));
  const exp = JSON.parse(fs.readFileSync(path.join(FIX, 'authplus_sample.expected.json'), 'utf8'));

  // key derivation first, compare against python hashlib ground truth
  const salt = file.subarray(0, 16);
  const keys = S.deriveKeysSync(C.utf8Bytes(exp.password), salt, { kdf: 'SHA1', hmac: 'SHA1', iter: 64000, fastIter: 2 });
  eq('derived enc key', C.bytesToHex(keys.encKey), exp.encKey);
  eq('derived hmac key', C.bytesToHex(keys.hmacKey), exp.hmacKey);

  const t0 = Date.now();
  const r = await S.decryptSqlcipherAsync(file, C.utf8Bytes(exp.password));
  console.log('        (decrypted in ' + (Date.now() - t0) + ' ms, profile: ' + r.profile + ')');
  eq('profile', r.profile, 'SQLCipher 3 defaults');
  eq('page size', r.pageSz, 1024);
  eq('reserve', r.reserve, 48);
  eq('db length', r.db.length, file.length);

  // compare against the known plaintext, page by page (last 48 bytes of each page are reserve)
  const want = Buffer.from(exp.plaintext, 'hex');
  let diff = 0;
  for (let pg = 0; pg < 4; pg++) {
    for (let i = 0; i < 1024 - 48; i++) {
      if (r.db[pg * 1024 + i] !== want[pg * 1024 + i]) diff++;
    }
  }
  eq('plaintext matches exactly (usable bytes)', diff, 0);
  let magic = Buffer.from(r.db.subarray(0, 16)).toString('latin1');
  eq('page1 magic', magic, 'SQLite format 3\u0000');

  // parse + extract
  const parsed = S.parseDb(r.db);
  const acc = parsed.tables.find(t => t.name === 'accounts');
  ok('accounts table present', !!acc);
  eq('accounts column list', JSON.stringify(acc.columns), JSON.stringify(['_id', 'email', 'issuer', 'secret', 'type']));
  eq('accounts row count', acc.rows.length, 3);
  const out = S.extractAccounts(parsed);
  eq('extracted count', out.entries.length, 3);
  out.entries.sort((a, b) => a.label.localeCompare(b.label));
  eq('entry 1 email/issuer/secret', [out.entries[0].label, out.entries[0].issuer, out.entries[0].secret].join('|'),
    'alice@gmail.com|Google|JBSWY3DPEHPK3PXP');
  eq('entry 2', [out.entries[1].label, out.entries[1].issuer, out.entries[1].secret].join('|'),
    'bob@outlook.com|Microsoft|MZXW6YTBOI');
  eq('entry 3 (overflow page, 2500 bytes)', out.entries[2].secret.length, 2500);
  eq('entry 3 issuer', out.entries[2].issuer, 'BigCorp');
  eq('entry 3 secret content', out.entries[2].secret, 'A'.repeat(2500));
  eq('default digits', out.entries[0].digits, 6);
  eq('default period', out.entries[0].period, 30);
}

console.log('--- wrong password / garbage handling ---');
{
  const file = new Uint8Array(fs.readFileSync(path.join(FIX, 'authplus_sample.db')));
  let threw = false;
  try { await S.decryptSqlcipherAsync(file, C.utf8Bytes('wrong-password')); } catch (e) { threw = true; }
  ok('wrong password throws', threw);
  threw = false;
  try { await S.decryptSqlcipherAsync(new Uint8Array(64), C.utf8Bytes('x')); } catch (e) { threw = true; }
  ok('tiny file throws', threw);
  // a plain (unencrypted) sqlite db should not be mistaken for sqlcipher
  const plain = new Uint8Array(fs.readFileSync(path.join(FIX, 'plain_real.db')));
  threw = false;
  try { await S.decryptSqlcipherAsync(plain, C.utf8Bytes('x')); } catch (e) { threw = true; }
  ok('plain db rejected', threw);
  // sync path must work too (used when WebCrypto is unavailable)
  let syncOk = false;
  try { const rr = S.decryptSqlcipherSync(file, C.utf8Bytes('testpw123')); syncOk = rr && rr.pageSz === 1024; } catch (e) { syncOk = false; }
  ok('sync decrypt path works', syncOk);
}

console.log('--- TOTP codes from extracted secrets ---');
{
  const file = new Uint8Array(fs.readFileSync(path.join(FIX, 'authplus_sample.db')));
  const exp = JSON.parse(fs.readFileSync(path.join(FIX, 'authplus_sample.expected.json'), 'utf8'));
  const r = await S.decryptSqlcipherAsync(file, C.utf8Bytes(exp.password));
  const out = S.extractAccounts(S.parseDb(r.db));
  const e = out.entries.find(x => x.issuer === 'Google');
  const sec = C.base32Decode(e.secret); // "Hello!\xde\xad\xbe\xef"
  const code = C.totp(sec, 6, 30, 'SHA1', 1234567890);
  ok('code is 6 digits', /^\d{6}$/.test(code), 'got ' + code);
  const code2 = C.totp(sec, 6, 30, 'SHA1', 1234567890 + 30);
  ok('code changes with time', code !== code2, code + ' vs ' + code2);
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
};

main().catch(e => { console.error(e); process.exit(1); });
