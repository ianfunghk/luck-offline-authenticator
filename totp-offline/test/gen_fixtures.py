#!/usr/bin/env python3
"""Build test fixtures with INDEPENDENT ground truth:
   - PBKDF2 / HMAC : python hashlib+hmac (OpenSSL backed)
   - AES-256-CBC   : openssl CLI
   - SQLite file   : hand-built (so we can set reserved-bytes=48, which the
                     stdlib sqlite3 module cannot do) + one real stdlib db.
"""
import hashlib, hmac, json, os, sqlite3, struct, subprocess, sys

OUT = '/tmp/totp_fixtures'
os.makedirs(OUT, exist_ok=True)
PASSWORD = 'testpw123'
PAGE = 1024
RESERVE = 48
USABLE = PAGE - RESERVE  # 976

# ---------------------------------------------------------------- varint / records
def varint(v):
    if v < 0x80:
        return bytes([v])
    if v < (1 << 56):
        parts = []
        t = v
        while True:
            parts.insert(0, t & 0x7f)
            t >>= 7
            if t == 0:
                break
        out = bytearray()
        for i, p in enumerate(parts):
            out.append(p | (0x80 if i < len(parts) - 1 else 0))
        return bytes(out)
    b8 = v & 0xff
    t = v >> 8
    parts = []
    while True:
        parts.insert(0, t & 0x7f)
        t >>= 7
        if t == 0:
            break
    out = bytearray([0x80] * 8)
    for i, p in enumerate(parts):
        out[i] = p | 0x80
    out.append(b8)
    return bytes(out)

def serial_text(s):
    b = s.encode('utf-8')
    return (13 + 2 * len(b), b)

def serial_int(v):
    for n, st in ((1, 1), (2, 2), (3, 3), (4, 4), (6, 5), (8, 6)):
        if -2 ** (8 * n - 1) <= v < 2 ** (8 * n - 1):
            return (st, v.to_bytes(n, 'big', signed=True))
    return (6, v.to_bytes(8, 'big', signed=True))

def record(fields):
    """fields: list of (serial_type, payload_bytes)"""
    h = b''.join(varint(t) for t, _ in fields)
    size = len(varint(len(h) + 1)) + len(h)
    while len(varint(size)) + len(h) != size:
        size = len(varint(size)) + len(h)
    return varint(size) + h + b''.join(p for _, p in fields)

def blob(b):
    return (12 + 2 * len(b), b)

# ---------------------------------------------------------------- page building
def build_leaf(records, hdr_off, page_no, usable=USABLE, page_len=PAGE):
    """Lay out a table-leaf page. records: [(rowid, payload_bytes)]
       Returns (page_bytes, overflow_pages_bytes_list)."""
    max_local = usable - 35
    min_local = ((usable - 12) * 32 // 255) - 23
    cells = []
    overflow_pages = []
    next_ov = page_no + 1
    for rowid, payload in records:
        cell = varint(len(payload)) + varint(rowid)
        if len(payload) > max_local:
            local = min_local + ((len(payload) - min_local) % (usable - 4))
            if local > max_local:
                local = min_local
            rest = payload[local:]
            chunks = [rest[i:i + usable - 4] for i in range(0, len(rest), usable - 4)]
            first = next_ov
            next_ov += len(chunks)
            for i, ch in enumerate(chunks):
                op = bytearray(page_len)
                nxt = (first + i + 1) if i + 1 < len(chunks) else 0
                op[0:4] = nxt.to_bytes(4, 'big')
                op[4:4 + len(ch)] = ch
                overflow_pages.append(bytes(op))
            cell += payload[:local] + first.to_bytes(4, 'big')
        else:
            cell += payload
        cells.append(cell)

    page = bytearray(page_len)
    content_end = usable
    ptrs = []
    for cell in cells:
        content_end -= len(cell)
        page[content_end:content_end + len(cell)] = cell
        ptrs.append(content_end)

    page[hdr_off] = 0x0d
    page[hdr_off + 1:hdr_off + 3] = (0).to_bytes(2, 'big')
    page[hdr_off + 3:hdr_off + 5] = len(ptrs).to_bytes(2, 'big')
    page[hdr_off + 5:hdr_off + 7] = content_end.to_bytes(2, 'big')
    page[hdr_off + 7] = 0
    base = hdr_off + 8
    for i, p in enumerate(ptrs):
        page[base + 2 * i:base + 2 * i + 2] = p.to_bytes(2, 'big')
    return bytes(page), overflow_pages


def u32le(n):
    return struct.pack('<I', n)

def aes_cbc_encrypt(key, iv, data):
    r = subprocess.run(['openssl', 'enc', '-aes-256-cbc', '-K', key.hex(), '-iv', iv.hex(), '-nopad'],
                       input=data, capture_output=True)
    if r.returncode != 0:
        sys.exit('openssl enc failed: ' + r.stderr.decode())
    return r.stdout

# ---------------------------------------------------------------- fixture 1: real stdlib db
def make_real_db():
    path = os.path.join(OUT, 'plain_real.db')
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.execute('PRAGMA page_size=1024')
    con.execute('PRAGMA journal_mode=DELETE')
    con.execute('CREATE TABLE accounts (email TEXT, issuer TEXT, secret TEXT, type TEXT)')
    rows = []
    for i in range(300):
        email = 'user%d@example.com' % i
        issuer = 'Service %d' % (i % 17)
        secret = ('SECRET%04d' % i) * 3   # ~33 chars, forces multiple pages
        rows.append((email, issuer, secret, 'totp'))
    con.executemany('INSERT INTO accounts VALUES (?,?,?,?)', rows)
    con.execute('CREATE TABLE category (name TEXT, position INTEGER)')
    con.executemany('INSERT INTO category VALUES (?,?)', [('cat%d' % i, i) for i in range(20)])
    con.commit()
    con.execute('VACUUM')
    con.close()
    json.dump({'rows': rows}, open(os.path.join(OUT, 'plain_real.expected.json'), 'w'))
    print('wrote', path)

# ---------------------------------------------------------------- fixture 2: hand-built sqlcipher db
def make_sqlcipher_db():
    accounts = [
        (1, 'alice@gmail.com', 'Google', 'JBSWY3DPEHPK3PXP', 'totp'),
        (2, 'bob@outlook.com', 'Microsoft', 'MZXW6YTBOI======', 'totp'),
        (3, 'carol@corp.io', 'BigCorp', 'A' * 2500, 'totp'),
    ]
    cols = ['_id', 'email', 'issuer', 'secret', 'type']
    sql = 'CREATE TABLE accounts (_id INTEGER PRIMARY KEY, email TEXT, issuer TEXT, secret TEXT, type TEXT)'

    # sqlite_master page (page 1)
    master_rec = record([serial_text('table'), serial_text('accounts'), serial_text('accounts'),
                         serial_int(2), serial_text(sql)])
    page1, _ = build_leaf([(1, master_rec)], 100, 1)

    # fill db header
    p = bytearray(page1)
    p[0:16] = b'SQLite format 3\x00'
    p[16:18] = (1024).to_bytes(2, 'big')
    p[18] = 1; p[19] = 1
    p[20] = RESERVE
    p[21] = 64; p[22] = 32; p[23] = 32
    p[24:28] = (1).to_bytes(4, 'big')
    p[28:32] = (4).to_bytes(4, 'big')     # db size in pages
    p[32:36] = (0).to_bytes(4, 'big')     # freelist trunk
    p[36:40] = (0).to_bytes(4, 'big')     # freelist count
    p[40:44] = (1).to_bytes(4, 'big')     # schema cookie
    p[44:48] = (4).to_bytes(4, 'big')     # schema format
    p[48:52] = (2000).to_bytes(4, 'big')
    p[52:56] = (0).to_bytes(4, 'big')
    p[56:60] = (1).to_bytes(4, 'big')     # utf-8
    p[60:64] = (0).to_bytes(4, 'big')
    p[64:68] = (0).to_bytes(4, 'big')
    p[68:72] = (0).to_bytes(4, 'big')
    p[92:96] = (1).to_bytes(4, 'big')
    p[96:100] = (3045000).to_bytes(4, 'big')
    page1 = bytes(p)

    # accounts leaf (page 2)
    recs = []
    for row in accounts:
        _id, email, issuer, secret, typ = row
        rec = record([serial_int(_id), serial_text(email), serial_text(issuer),
                      serial_text(secret), serial_text(typ)])
        recs.append((_id, rec))
    page2, ov_pages = build_leaf(recs, 0, 2)

    plaintext_pages = [page1, page2] + ov_pages
    plaintext = b''.join(plaintext_pages)
    assert len(plaintext_pages) == 4, len(plaintext_pages)

    # --- encrypt, SQLCipher 3 defaults ---
    salt = bytes(range(16))  # deterministic for the fixture
    enc_key = hashlib.pbkdf2_hmac('sha1', PASSWORD.encode(), salt, 64000, 32)
    hmac_salt = bytes(b ^ 0x3a for b in salt)
    hmac_key = hashlib.pbkdf2_hmac('sha1', enc_key, hmac_salt, 2, 32)

    out = bytearray()
    out += salt
    for idx, pg in enumerate(plaintext_pages):
        pgno = idx + 1
        if pgno == 1:
            body = pg[16:USABLE]           # 960 bytes: header's first 16 bytes are the salt
        else:
            body = pg[0:USABLE]            # 976 bytes
        iv = hashlib.sha1(b'iv%d' % pgno).digest()[:16]
        ct = aes_cbc_encrypt(enc_key, iv, body)
        mac = hmac.new(hmac_key, ct + iv + u32le(pgno), hashlib.sha1).digest()
        out += ct + iv + mac
        # remaining reserve bytes (48 = 16 IV + 20 MAC + 12 random)
        out += bytes(12)
    assert len(out) == 4 * PAGE, len(out)

    path = os.path.join(OUT, 'authplus_sample.db')
    open(path, 'wb').write(bytes(out))
    json.dump({
        'password': PASSWORD,
        'accounts': [{'_id': a[0], 'email': a[1], 'issuer': a[2], 'secret': a[3], 'type': a[4]} for a in accounts],
        'plaintext': plaintext.hex(),
        'encKey': enc_key.hex(),
        'hmacKey': hmac_key.hex(),
        'pageSz': PAGE, 'reserve': RESERVE
    }, open(os.path.join(OUT, 'authplus_sample.expected.json'), 'w'))
    print('wrote', path)

if __name__ == '__main__':
    print('openssl:', subprocess.run(['openssl', 'version'], capture_output=True).stdout.decode().strip())
    make_real_db()
    make_sqlcipher_db()
    import shutil, glob
    dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
    os.makedirs(dest, exist_ok=True)
    for f in glob.glob(os.path.join(OUT, '*')):
        shutil.copy(f, dest)
    print('copied to', dest)
