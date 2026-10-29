#!/usr/bin/env node
/* Inline src/*.js + styles.css into one self-contained HTML file. */
const fs = require('fs');
const path = require('path');
const root = __dirname;
const src = p => fs.readFileSync(path.join(root, 'src', p), 'utf8');

let html = src('index.template.html');
html = html.replace('/*__CSS__*/', () => src('styles.css'));
html = html.replace('/*__CRYPTO__*/', () => src('crypto.js'));
html = html.replace('/*__SQLITE__*/', () => src('sqlite.js'));
html = html.replace('/*__APP__*/', () => src('app.js'));

const out = path.join(root, 'dist', 'offline-authenticator.html');
fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
fs.writeFileSync(out, html);
const kb = (Buffer.byteLength(html) / 1024).toFixed(1);
console.log('built ' + out + ' (' + kb + ' KB)');
if (/__CSS__|__CRYPTO__|__SQLITE__|__APP__/.test(html)) {
  console.error('ERROR: placeholder left un-replaced');
  process.exit(1);
}
if (/src\s*=\s*["']http|href\s*=\s*["']http/.test(html)) {
  console.error('ERROR: external reference found');
  process.exit(1);
}
