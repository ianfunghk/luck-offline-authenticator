/* End-to-end test: loads the built single-file HTML in Chromium over file://
   and drives the real UI. No network. */
const path = require('path');
const fs = require('fs');
const { chromium } = require('playwright');

const FILE = 'file://' + path.join(__dirname, '..', 'dist', 'offline-authenticator.html');
const DB = path.join(__dirname, 'fixtures', 'authplus_sample.db');
const REALDB = path.join(__dirname, 'fixtures', 'plain_real.db');

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (extra ? '\n        ' + extra : '')); }
}
function eq(name, a, b) { ok(name, a === b, 'got: ' + JSON.stringify(a) + '  exp: ' + JSON.stringify(b)); }
async function openDetails(page, text) {
  const d = page.locator('details', { hasText: text }).first();
  const isOpen = await d.evaluate(el => el.open);
  if (!isOpen) await d.locator('summary').click();
}

(async () => {
  // CHROME_PATH lets CI or a Linux box point at a system Chrome; otherwise use
  // the Chromium that Playwright downloaded, which works on every platform.
  const launchOpts = { args: ['--no-sandbox', '--allow-file-access-from-files'] };
  if (process.env.CHROME_PATH) launchOpts.executablePath = process.env.CHROME_PATH;
  const browser = await chromium.launch(launchOpts);
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });

  let netHits = 0;
  await page.route('**/*', route => {
    const u = route.request().url();
    if (!u.startsWith('file://') && !u.startsWith('data:') && !u.startsWith('blob:')) { netHits++; console.log('    NETWORK:', u); }
    route.continue();
  });

  await page.goto(FILE);

  console.log('--- boots into setup ---');
  ok('setup screen visible', await page.isVisible('#setup'));
  ok('locked screen hidden', !(await page.isVisible('#locked')));

  console.log('--- create vault ---');
  await page.fill('#setupPw', 'correct horse battery');
  await page.fill('#setupPw2', 'correct horse battery');
  await page.click('#setupGo');
  await page.waitForSelector('#unlocked:not(.hidden)', { timeout: 20000 });
  ok('unlocked after setup', await page.isVisible('#unlocked'));
  ok('empty state shown', await page.isVisible('#empty'));

  console.log('--- add account manually, verify live code ---');
  await openDetails(page, 'Add an account manually');
  await page.fill('#addIssuer', 'GitHub');
  await page.fill('#addLabel', 'me@example.com');
  await page.fill('#addSecret', 'GEZDGNBVGY3TQOJQ');   // distinct from the .db fixture secrets
  await page.click('#addGo');
  await page.waitForSelector('.entry', { timeout: 5000 });
  eq('one entry rendered', await page.locator('.entry').count(), 1);
  eq('issuer text', (await page.locator('.entry .issuer').first().textContent()), 'GitHub');
  const code1 = (await page.locator('.entry .code').first().textContent()).trim();
  ok('code is 6 digits', /^\d{6}$/.test(code1), 'got ' + code1);

  // cross-check the displayed code against an independent RFC-6238 implementation
  const nodeCrypto = require('crypto');
  function refTotp(secretB32, digits, period, t) {
    const key = Buffer.from(secretB32.replace(/=+$/, ''), 'utf8');
    // base32 decode
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, val = 0, out = [];
    for (const ch of key.toString().toUpperCase()) {
      const idx = A.indexOf(ch); if (idx < 0) continue;
      val = (val << 5) | idx; bits += 5;
      if (bits >= 8) { bits -= 8; out.push((val >> bits) & 0xff); }
    }
    const counter = Math.floor(t / period);
    const msg = Buffer.alloc(8);
    msg.writeUInt32BE(Math.floor(counter / 4294967296), 0);
    msg.writeUInt32BE(counter >>> 0, 4);
    const mac = nodeCrypto.createHmac('sha1', Buffer.from(out)).update(msg).digest();
    const off = mac[mac.length - 1] & 0x0f;
    const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
    return String(bin % Math.pow(10, digits)).padStart(digits, '0').slice(-digits);
  }
  const nowSec = Math.floor(Date.now() / 1000);
  eq('displayed code matches independent RFC 6238 impl', code1, refTotp('GEZDGNBVGY3TQOJQ', 6, 30, nowSec));

  console.log('--- countdown + hotp/totp badge ---');
  const secs = (await page.locator('.entry .secs').first().textContent()).trim();
  ok('seconds remaining shown 1..30', /^\d+$/.test(secs) && +secs >= 1 && +secs <= 30, 'got ' + secs);
  ok('badge shows params', /S1.*6d.*30s/.test(await page.locator('.entry .badge').first().textContent()));

  console.log('--- show key / copy ---');
  await page.click('.entry button:has-text("Show key")');
  eq('secret revealed', (await page.locator('.entry .secretbox').first().textContent()).trim(), 'GEZDGNBVGY3TQOJQ');
  await page.click('.entry button:has-text("Show key")');
  eq('secret hidden again', await page.locator('.entry .secretbox').count(), 0);

  console.log('--- import Authenticator Plus .db ---');
  await openDetails(page, 'Import from Authenticator Plus');
  await page.setInputFiles('#dbFile', DB);
  await page.fill('#dbPw', 'testpw123');
  await page.click('#dbGo');
  await page.waitForFunction(() => document.querySelectorAll('.entry').length === 4, null, { timeout: 30000 });
  eq('4 entries after db import', await page.locator('.entry').count(), 4);
  const issuers = await page.locator('.entry .issuer').allTextContents();
  ok('Google from db', issuers.includes('Google'), JSON.stringify(issuers));
  ok('Microsoft from db', issuers.includes('Microsoft'), JSON.stringify(issuers));
  ok('BigCorp from db (overflow page)', issuers.includes('BigCorp'), JSON.stringify(issuers));

  console.log('--- wrong db password is rejected ---');
  await page.setInputFiles('#dbFile', DB);
  await page.fill('#dbPw', 'nope');
  await page.click('#dbGo');
  await page.waitForFunction(() => {
    const e = document.getElementById('dbErr');
    return e && !e.classList.contains('hidden') && /Could not open/.test(e.textContent);
  }, null, { timeout: 40000 });
  ok('error message shown', /Could not open/.test(await page.textContent('#dbErr')));
  eq('still 4 entries', await page.locator('.entry').count(), 4);

  console.log('--- search filter ---');
  await page.fill('#filter', 'micro');
  await page.waitForTimeout(150);
  eq('filtered to 1', await page.locator('.entry').count(), 1);
  await page.fill('#filter', '');
  await page.waitForTimeout(150);
  eq('filter cleared', await page.locator('.entry').count(), 4);

  console.log('--- persistence across reload ---');
  await page.reload();
  await page.waitForSelector('#locked:not(.hidden)', { timeout: 10000 });
  ok('locked after reload', await page.isVisible('#locked'));
  await page.fill('#unlockPw', 'wrong');
  await page.click('#unlockGo');
  await page.waitForTimeout(800);
  ok('wrong password rejected', /Wrong password/.test(await page.textContent('#unlockErr')));
  await page.fill('#unlockPw', 'correct horse battery');
  await page.click('#unlockGo');
  await page.waitForSelector('#unlocked:not(.hidden)', { timeout: 20000 });
  eq('4 entries restored after reload', await page.locator('.entry').count(), 4);

  console.log('--- otpauth:// import ---');
  await openDetails(page, 'Paste otpauth');
  await page.fill('#uriText',
    'otpauth://totp/Acme:alice?secret=NBSWY3DPEHPK3PXP&issuer=Acme&digits=8&period=60\n' +
    'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n' +
    '### definitely not a key ###');
  await page.click('#uriGo');
  await page.waitForTimeout(400);
  eq('2 more entries', await page.locator('.entry').count(), 6);
  const badges = await page.locator('.entry .badge').allTextContents();
  ok('8-digit/60s entry parsed', badges.some(b => /8d/.test(b) && /60s/.test(b)), JSON.stringify(badges));

  console.log('--- malformed otpauth URI is skipped, not fatal ---');
  // a stray '%' makes decodeURIComponent throw; before the fix this aborted the
  // whole batch and left the earlier lines pushed but not persisted.
  await page.fill('#uriText',
    'otpauth://totp/Bad:one?secret=JBSWY3DPEHPK3PXP&issuer=%zz\n' +
    'otpauth://totp/Good:two?secret=MFRGGZDFMZTWQ2LK&issuer=Good');
  await page.click('#uriGo');
  await page.waitForTimeout(400);
  eq('only the valid line imported', await page.locator('.entry').count(), 7);
  ok('valid line did import', (await page.locator('.entry .issuer').allTextContents()).includes('Good'));
  ok('no page error from bad URI', errors.length === 0, JSON.stringify(errors));

  console.log('--- HOTP counter badge updates on "Next code" ---');
  await page.fill('#uriText', 'otpauth://hotp/Steam:me?secret=KRUGS4ZANFZSAYJA&issuer=Steam&counter=0');
  await page.click('#uriGo');
  await page.waitForTimeout(400);
  const hotpEntry = page.locator('.entry', { hasText: 'Steam' }).first();
  ok('hotp badge starts at c0', /c0/.test(await hotpEntry.locator('.badge').textContent()));
  const beforeCode = (await hotpEntry.locator('.code').textContent()).trim();
  await hotpEntry.locator('button:has-text("Next code")').click();
  await page.waitForTimeout(300);
  const hotpBadge = await page.locator('.entry', { hasText: 'Steam' }).first().locator('.badge').textContent();
  ok('hotp badge now c1', /c1/.test(hotpBadge), hotpBadge);
  ok('hotp code advanced',
    (await page.locator('.entry', { hasText: 'Steam' }).first().locator('.code').textContent()).trim() !== beforeCode);

  console.log('--- encrypted export / restore round trip ---');
  await openDetails(page, 'Backup, restore');
  const dl = await Promise.all([
    page.waitForEvent('download', { timeout: 15000 }),
    page.click('#exportBtn')
  ]);
  const p = path.join('/tmp', 'vault-' + Date.now() + '.json');
  await dl[0].saveAs(p);
  const blob = fs.readFileSync(p, 'utf8');
  ok('export starts with OTPV1.', blob.indexOf('OTPV1.') === 0, blob.slice(0, 40));
  ok('export does not contain plaintext secrets',
    blob.indexOf('JBSWY3DPEHPK3PXP') < 0 && blob.indexOf('Acme') < 0 &&
    blob.indexOf('GEZDGNBVGY3TQOJQ') < 0 && blob.indexOf('GitHub') < 0 &&
    blob.indexOf('NBSWY3DPEHPK3PXP') < 0);

  console.log('--- plaintext export asks for confirmation ---');
  let plainDialog = '';
  page.once('dialog', async d => { plainDialog = d.message(); await d.dismiss(); });
  const plainDownload = page.waitForEvent('download', { timeout: 5000 }).catch(() => null);
  await page.click('#exportPlainBtn');
  ok('plaintext export warns before writing', /PLAINTEXT/.test(plainDialog), plainDialog);
  ok('declining the confirm downloads nothing', (await plainDownload) === null);

  console.log('--- wipe, then restore from the encrypted backup ---');
  await page.click('#lockBtn');
  await page.waitForSelector('#locked:not(.hidden)');
  page.once('dialog', d => d.accept());
  await page.click('#wipeBtn');
  await page.waitForSelector('#setup:not(.hidden)', { timeout: 10000 });
  ok('back to setup after wipe', await page.isVisible('#setup'));

  await page.fill('#setupPw', 'a brand new password');
  await page.fill('#setupPw2', 'a brand new password');
  await page.click('#setupGo');
  await page.waitForSelector('#unlocked:not(.hidden)', { timeout: 20000 });
  eq('fresh vault is empty', await page.locator('.entry').count(), 0);

  await openDetails(page, 'Backup, restore');
  await page.setInputFiles('#importFile', p);
  await page.fill('#restorePw', 'correct horse battery');
  await page.click('#restoreGo');
  await page.waitForFunction(() => document.querySelectorAll('.entry').length === 8, null, { timeout: 25000 });
  eq('8 accounts restored from backup', await page.locator('.entry').count(), 8);
  ok('restored issuer present', (await page.locator('.entry .issuer').allTextContents()).includes('BigCorp'));
  eq('restore button label is restored', (await page.textContent('#restoreGo')).trim(), 'Restore');

  console.log('--- restoring over a non-empty vault asks first ---');
  // declining must leave the current vault untouched
  let replaceMsg = '';
  page.once('dialog', async d => { replaceMsg = d.message(); await d.dismiss(); });
  await page.setInputFiles('#importFile', p);
  await page.fill('#restorePw', 'correct horse battery');
  await page.click('#restoreGo');
  await page.waitForFunction(() => document.getElementById('restoreGo').textContent.trim() === 'Restore', null, { timeout: 20000 });
  await page.waitForTimeout(300);
  ok('replace confirmation mentions the account count', /replaces all 8 accounts/.test(replaceMsg), replaceMsg);
  eq('declining keeps the vault intact', await page.locator('.entry').count(), 8);
  ok('vault still unlockable after declining', await page.isVisible('#unlocked'));

  console.log('--- restored codes still match the reference implementation ---');
  await page.fill('#filter', 'GitHub');
  await page.waitForTimeout(200);
  const restored = (await page.locator('.entry .code').first().textContent()).trim();
  eq('restored code matches RFC 6238', restored, refTotp('GEZDGNBVGY3TQOJQ', 6, 30, Math.floor(Date.now() / 1000)));
  await page.fill('#filter', '');
  await page.waitForTimeout(200);

  console.log('--- tampered backup is rejected ---');
  const tampered = blob.split('.');
  tampered[3] = tampered[3].slice(0, -8) + 'AAAAAAAA';
  const tp = path.join('/tmp', 'tampered-' + Date.now() + '.json');
  fs.writeFileSync(tp, tampered.join('.'));
  await page.setInputFiles('#importFile', tp);
  await page.fill('#restorePw', 'correct horse battery');
  await page.click('#restoreGo');
  await page.waitForFunction(() => {
    const e = document.getElementById('restoreErr');
    return e && !e.classList.contains('hidden') && e.textContent.length > 0;
  }, null, { timeout: 20000 });
  ok('tampered backup rejected', /Could not open|not readable/.test(await page.textContent('#restoreErr')),
    await page.textContent('#restoreErr'));

  console.log('--- wrong backup password is rejected ---');
  await page.setInputFiles('#importFile', p);
  await page.fill('#restorePw', 'not the password');
  await page.click('#restoreGo');
  await page.waitForFunction(() => {
    const e = document.getElementById('restoreErr');
    return e && /Could not open/.test(e.textContent);
  }, null, { timeout: 20000 });
  ok('wrong backup password rejected', /Could not open/.test(await page.textContent('#restoreErr')));

  console.log('--- no network requests at all ---');
  eq('zero external requests', netHits, 0);
  eq('zero page errors', errors.length, 0, JSON.stringify(errors));

  console.log('--- password change survives a storage write failure ---');
  const storagePage = await browser.newPage();
  await storagePage.goto(FILE);
  await storagePage.fill('#setupPw', 'old-password');
  await storagePage.fill('#setupPw2', 'old-password');
  await storagePage.click('#setupGo');
  await storagePage.waitForSelector('#unlocked:not(.hidden)', { timeout: 20000 });
  await storagePage.evaluate(() => {
    Storage.prototype.setItem = function () { throw new DOMException('full', 'QuotaExceededError'); };
  });
  await openDetails(storagePage, 'Backup, restore');
  await storagePage.fill('#changePwOld', 'old-password');
  await storagePage.fill('#changePw', 'new-password');
  await storagePage.click('#changeGo');
  await storagePage.waitForFunction(() => {
    return /Password changed in this session/.test(document.getElementById('changeErr').textContent);
  }, null, { timeout: 20000 });
  // A later persist must keep the new salt paired with the new key.
  await openDetails(storagePage, 'Add an account manually');
  await storagePage.fill('#addSecret', 'JBSWY3DPEHPK3PXP');
  await storagePage.click('#addGo');
  const storageDownload = await Promise.all([
    storagePage.waitForEvent('download', { timeout: 15000 }),
    storagePage.click('#exportBtn')
  ]);
  const storagePath = path.join('/tmp', 'vault-storage-failure-' + Date.now() + '.json');
  await storageDownload[0].saveAs(storagePath);
  const storageParts = fs.readFileSync(storagePath, 'utf8').split('.');
  function storageVaultAccepts(password) {
    const salt = Buffer.from(storageParts[1], 'base64');
    const key = nodeCrypto.pbkdf2Sync(password, salt, 150000, 32, 'sha256');
    const hmacSalt = Buffer.from(salt.map(b => b ^ 0x5a));
    const hmacKey = nodeCrypto.pbkdf2Sync(key, hmacSalt, 2, 32, 'sha256');
    const mac = nodeCrypto.createHmac('sha256', hmacKey)
      .update(Buffer.concat([Buffer.from(storageParts[2], 'base64'), Buffer.from(storageParts[3], 'base64')]))
      .digest();
    return mac.equals(Buffer.from(storageParts[4], 'base64'));
  }
  ok('export after later persist accepts the new password', storageVaultAccepts('new-password'));
  ok('export after later persist rejects the old password', !storageVaultAccepts('old-password'));
  await storagePage.close();

  console.log('--- invalid OTP parameters are rejected before persistence ---');
  const validationPage = await browser.newPage();
  const validationErrors = [];
  validationPage.on('pageerror', e => validationErrors.push(e.message));
  await validationPage.goto(FILE);
  await validationPage.fill('#setupPw', 'password');
  await validationPage.fill('#setupPw2', 'password');
  await validationPage.click('#setupGo');
  await validationPage.waitForSelector('#unlocked:not(.hidden)', { timeout: 20000 });
  await openDetails(validationPage, 'Paste otpauth');
  await validationPage.fill('#uriText',
    'otpauth://totp/BadDigits?secret=JBSWY3DPEHPK3PXP&digits=1000000000\n' +
    'otpauth://totp/BadPeriod?secret=JBSWY3DPEHPK3PXP&period=-30\n' +
    'otpauth://hotp/BadCounter?secret=JBSWY3DPEHPK3PXP&counter=-1\n' +
    'otpauth://totp/Good?secret=JBSWY3DPEHPK3PXP&digits=8&period=60');
  await validationPage.click('#uriGo');
  await validationPage.waitForSelector('.entry', { timeout: 5000 });
  eq('only valid OTP parameters are imported', await validationPage.locator('.entry').count(), 1);
  ok('valid entry retains its parameters', /8d.*60s/.test(await validationPage.locator('.badge').textContent()));
  await validationPage.reload();
  await validationPage.fill('#unlockPw', 'password');
  await validationPage.click('#unlockGo');
  await validationPage.waitForSelector('.entry', { timeout: 20000 });
  eq('vault still opens after rejecting malformed entries', await validationPage.locator('.entry').count(), 1);
  eq('malformed entries cause no page errors', validationErrors.length, 0, JSON.stringify(validationErrors));
  await validationPage.close();

  await browser.close();
  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
