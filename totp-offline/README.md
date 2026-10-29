# Offline Authenticator — 單一 HTML 檔案的 2FA 驗證器

> 專案背景、快速開始與貢獻方式請見根目錄的 [README](../README.md)。本文件是技術細節。

一個完全離線、單檔案的 TOTP/HOTP 驗證器，專門用來接手已經下架的 **Authenticator Plus**。
打開 HTML 就能用，不需要伺服器、不需要網路、不需要安裝任何東西。

產物：**`dist/offline-authenticator.html`**（約 84 KB，所有 CSS / JS 都內嵌在裡面）

---

## 它能做什麼

| 功能 | 說明 |
|---|---|
| **直接讀取 `authplus.db`** | 內建 SQLCipher 解密 + SQLite 解析器，把舊 app 的密鑰整批救出來 |
| **產生 6/7/8 位驗證碼** | TOTP（含 30s/60s 週期）與 HOTP，支援 SHA1 / SHA256 / SHA512 |
| **密碼加密保管** | AES-256-CBC + HMAC-SHA256，密鑰由密碼經 PBKDF2-SHA256（15 萬次）派生 |
| **匯出加密備份** | 存成 `OTPV1…` 檔案，需要用密碼才能還原 |
| **手動新增 / 貼上 `otpauth://`** | 之後換服務時也很好用 |
| **搜尋、複製、顯示密鑰、倒數計時** | 基本操作都有 |

---

## 在 iPhone 上怎麼用

iOS 不會像桌機那樣「點兩下 HTML 就用瀏覽器打開」。可靠的方式有三種，任選一種：

1. **文件 App → 分享 → Safari**
   把 HTML 存進「檔案」App（AirDrop / 郵件附件 / iCloud Drive 都可以），長按檔案 → 分享 → 選 **Safari**。Safari 會執行頁面裡的 JavaScript。
   *（某些 iOS 版本會擋住這條路，那就用下面兩種。）*

2. **Documents by Readdle（免費）**
   把 HTML 放進去 → 內建瀏覽器直接開，或用它的 "Start Server" 功能，再到 Safari 開 `http://127.0.0.1:8080`。

3. **離線 HTML 閱讀器**
   App Store 上有專門開單檔 HTML 的閱讀器（例如 *AI Artifact Reader*），支援 JavaScript 且預設封鎖網路。

> ⚠️ **不管用哪種方式，都請先確認網址列是 `file://` 或 `127.0.0.1`**，不要把它上傳到任何線上「HTML 預覽」網站——那會把你的密鑰送到別人伺服器。

### 從 Authenticator Plus 搬家的步驟

1. 在舊手機打開 Authenticator Plus，還**不要刪掉它**。
2. **Settings → Backup & Restore → Backup to SD Card**，得到 `authplus.db`。
   - Android：通常在 `/storage/emulated/0/AuthenticatorPlus/authplus.db`
   - iPhone：接上 Mac → Finder → 選你的 iPhone → **Files** → Authenticator Plus → 把 Backup 資料夾拖到 Mac
3. 在本頁「Import from Authenticator Plus」選擇該檔案，輸入 **Authenticator Plus 的主密碼**（不是手機密碼，也不是 Google 密碼）。
4. 匯入後**先隨便挑兩個帳號實際登入驗證一次**，確認驗證碼被接受，再去關掉舊 app 的 2FA。

---

## 安全設計

- **真正的離線**：沒有任何 `<script src>`、`<link>`、字型或圖片外連；還加了 CSP `default-src 'none'`，就算你連著網路，頁面也無法對外發出任何請求。端到端測試會攔截並斷言「零外部請求」。
- **密碼不落地**：只保存由密碼派生出的金鑰，密碼本身不寫入任何地方。
- **先加密後認證**（encrypt-then-MAC）：密文被竄改會被 HMAC 擋下，測試中有專門的竄改偵測案例。
- **忘記密碼就沒救**：沒有後門，沒有「忘記密碼」。請另外保存好各服務的備用碼（recovery codes）。

### 儲存空間

頁面會嘗試用 `localStorage` 自動記住你的保管庫。某些 iOS 情境下 `localStorage` 會被擋，這時頁面會**明確警告你**：資料關掉就沒了，請先匯出加密備份。

---

## 驗證方式（不是「我覺得可以用」）

這個專案有三層測試，全部通過才算數：

```
node test/test_crypto.js    # 63 項：對照 OpenSSL / Node crypto
node test/test_sqlite.js    # 33 項：對照 openssl CLI + Python hashlib 建立的 fixture
node test/test_e2e.js       # 36 項：Playwright 開真實 Chromium，用 file:// 載入成品並操作 UI
```

- **加密原語**逐條比對 Node 的 `crypto` 模組：SHA-1/256/512、HMAC（RFC 2202 / 4231 向量）、PBKDF2（RFC 6070）、AES-256-CBC（NIST SP 800-38A 向量）、TOTP（RFC 6238 全部官方測試向量，含 SHA1/SHA256/SHA512）。
- **SQLCipher / SQLite** 用 Python 的 `hashlib` + `openssl enc` 產生獨立的加密資料庫 fixture，再讓 JS 解密，逐位元組比對還原結果；另外用一個 300 列、真的由 `sqlite3` 產生的資料庫驗證 b-tree 走訪與 overflow page。
- **端到端**在真實瀏覽器裡跑完整流程：建立保管庫 → 手動新增 → 匯入 `.db` → 密碼錯誤被拒 → 重新載入後解鎖 → 匯出 → 抹除 → 從備份還原 → 竄改偵測；並斷言**外部網路請求數為 0**。

---

## 已知限制

- **不支援掃描 QR code**：`file://` 不是安全上下文，拿不到相機權限。所以搬家請走「匯入 `authplus.db`」這條路（也正是你需要的），或手動貼上 `otpauth://` / 密鑰。
- **不產生 QR code**：要換到別的驗證器 app 時，用「Show key」把 base32 密鑰複製出來，貼到新 app 的手動新增欄位。
- **沒有生物辨識解鎖**：只能用密碼。
- **跨裝置同步**：靠匯出／匯入加密備份檔案，沒有雲端同步（這是刻意的）。

---

## 專案結構

```
src/crypto.js            純 JS 加密核心（SHA/HMAC/PBKDF2/AES-256-CBC/Base32/HOTP/TOTP）
src/sqlite.js            SQLCipher 解密 + 極簡 SQLite b-tree 讀取 + Authenticator Plus 擷取
src/app.js               介面邏輯、保管庫加解密、匯入匯出
src/styles.css           樣式
src/index.template.html  HTML 樣板
build.js                 把上面全部內嵌成單一 HTML
test/                    三層測試 + fixture 產生器
dist/offline-authenticator.html   成品
```

## 重新打包

改完 `src/` 之後執行：

```bash
node build.js
```

它會重新產生 `dist/offline-authenticator.html`，並檢查沒有留下未替換的佔位符、沒有任何外部資源引用。

`dist/` 已被 `.gitignore` 忽略。要拿到可以放上手機的成品，把建置結果複製到儲存庫根目錄：

```bash
node build.js && cp dist/offline-authenticator.html ../
```

根目錄那份 `offline-authenticator.html` 是**已提交的權威副本**，也是你實際傳到手機上的檔案。改動 `src/` 之後請務必重新建置並更新它，否則它會和原始碼不一致。

### 測試

```bash
npm install          # 只有端到端測試需要（Playwright）
npm run test:unit    # 加密 + SQLite，無需瀏覽器
npm run test:e2e     # 真實 Chromium；預設用 Playwright 內建版本
```

端到端測試預設使用 Playwright 自帶的 Chromium。若要改用系統安裝的 Chrome，設定 `CHROME_PATH`：

```bash
CHROME_PATH=/usr/bin/google-chrome npm run test:e2e
```

