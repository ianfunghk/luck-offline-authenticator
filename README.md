# Offline Authenticator

單一 HTML 檔、完全離線的 TOTP / HOTP 驗證器，可以直接讀取 **Authenticator Plus** 的 `authplus.db` 備份。
不裝 app、不連網路、不需要伺服器 —— 用瀏覽器打開就能把帳號救回來。

成品：[`offline-authenticator.html`](offline-authenticator.html)（約 84 KB，所有 CSS / JS 都內嵌）

---

## 為什麼會有這個專案

[Authenticator Plus](https://www.authenticatorplus.com/) 曾是一款評價很好的兩步驟驗證器，支援雲端自動備份（Google Drive / Dropbox），很多人（包括我）把幾十個帳號的 2FA 密鑰都放在裡面。

後來它從 App Store / Google Play 下架了，也不再更新。

問題是：**我的備份還在，卻沒有任何 app 打得開。**

Authenticator Plus 的備份是一顆 SQLCipher 加密的 SQLite 資料庫 —— `authplus.db`。它只認得自己的 app，格式沒有公開文件，市面上也沒有其他驗證器願意（或能夠）匯入它。於是就變成很荒謬的處境：

- 檔案是我自己的、完整無損、就躺在雲端和硬碟裡；
- 但唯一的讀取工具已經不存在；
- 換了新手機、無法再安裝舊 app（或系統版本已不支援）之後，這些帳號的 2FA 就只能靠當初印下來、或根本沒存的 recovery code。

我做的第一件事是把「解密 + 讀取 + 產生驗證碼」整條路自己走一遍：搞清楚 SQLCipher 的 KDF 參數、用純 JS 重寫解密、手寫一個只讀取必要部分的 SQLite b-tree 解析器、再實作 TOTP。做完之後，`authplus.db` 裡的密鑰可以一條一條挖出來，驗證碼也能正常產生。

既然都寫完了，那就把它包成**一個 HTML 檔**放出來。這樣同樣被卡住的人不必重寫一次，也不必把 `.db` 和密碼交給任何來路不明的線上「轉換神器」——那等於直接把所有人的 2FA 送出去。

這個專案最初是為了解決自己的問題，但目的不只是自救：

- 如果你手上也有一顆打不開的 `authplus.db`，希望你今天就能把帳號搬出來；
- 如果你發現某個版本的備份格式不相容、或在某支手機上開不起來，歡迎開 issue；
- 如果你願意貢獻程式、測試向量或文件翻譯，也非常歡迎（見下方 [貢獻](#貢獻)）。

---

## English summary

**Authenticator Plus** was a popular cloud-synced two-factor authenticator. It has been removed from the App Store and Google Play and is no longer maintained, but its backups — SQLCipher-encrypted `authplus.db` files — can no longer be opened by any app. This project is a single, self-contained HTML file that decrypts such a backup in the browser, extracts the secrets, and generates TOTP/HOTP codes, so people who still hold a backup are not locked out of their own accounts. It runs fully offline: no install, no server, no network requests (enforced by CSP and asserted in the end-to-end tests). Imported codes can be kept in a password-encrypted local vault or exported as an encrypted backup.

---

## 快速開始

1. 下載 [`offline-authenticator.html`](offline-authenticator.html)。
2. 用瀏覽器打開它（桌機直接雙擊；iPhone / Android 的開啟方式見[詳細文件](totp-offline/README.md#在-iphone-上怎麼用)）。
3. 建立保管庫密碼 → 展開 **Import from Authenticator Plus (authplus.db)** → 選擇 `authplus.db` → 輸入**舊 app 的主密碼**（不是手機密碼，也不是 Google 密碼）。
4. 從舊手機匯出備份：
   - Android：舊 app → **Settings → Backup & Restore → Backup to SD Card**，檔案通常在 `/storage/emulated/0/AuthenticatorPlus/authplus.db`
   - iPhone：接上 Mac → Finder → 你的 iPhone → **Files** → Authenticator Plus → 把 Backup 資料夾拖出來
5. **先挑兩個帳號實際登入一次**，確認驗證碼被服務接受，再去動舊的 2FA 設定。
6. 匯出一次加密備份，並另外保存好各服務的 recovery code。

> 安全提醒：請確認網址列是 `file://` 或 `127.0.0.1`。**不要**把這個 HTML 或你的 `.db` 上傳到任何線上「HTML 預覽」或「轉檔」網站——那會把密鑰送到別人的伺服器。

---

## 功能

- **直接匯入 `authplus.db`**：內建 SQLCipher 解密與極簡 SQLite 解析器，不需要先轉檔。
- **TOTP / HOTP**：6 / 7 / 8 位數，週期 30s / 60s，支援 SHA1 / SHA256 / SHA512。
- **密碼加密保管庫**：AES-256-CBC + HMAC-SHA256，密鑰由 PBKDF2-SHA256（15 萬次）派生，存於 `localStorage`。
- **匯出 / 還原加密備份**：`OTPV1…` 格式，需要用密碼才能解開；也可匯出明文 JSON 自行保管。
- **手動新增**：貼上 `otpauth://` 連結或純 base32 密鑰。
- **搜尋、複製、倒數計時、顯示密鑰**：日常操作都有。

---

## 更多說明

完整的技術細節都在 **[totp-offline/README.md](totp-offline/README.md)**：

- 在 iPhone / Android 上開啟單檔 HTML 的三種可行方式
- 從 Authenticator Plus 搬家的完整步驟
- 安全設計（CSP `default-src 'none'`、encrypt-then-MAC、零外部請求）
- 三層測試（加密原語 / SQLCipher + SQLite / Playwright 端到端，共 130+ 項斷言）
- 已知限制（不支援掃 QR code、不產生 QR code、無生物辨識、無雲端同步）
- 專案結構與重新打包方式

```bash
cd totp-offline
npm install          # 只有端到端測試需要（Playwright）
npm run test:unit    # 加密 + SQLite，不需瀏覽器
npm run test:e2e     # 真實 Chromium，以 file:// 載入成品
```

---

## 貢獻

這個專案還很小，任何形式的幫助都有用：

- **回報相容性**：其他版本 / 平台的 `authplus.db` 能不能匯入？失敗的話請附上**不含密鑰**的結構描述或錯誤訊息。
- **改善開啟體驗**：iOS 上開單檔 HTML 一直很彆扭，如果你有更穩定的做法（例如 PWA 打包、可信任的離線閱讀器），歡迎提出。
- **補測試**：更多加密測試向量、其他 SQLite 邊界情況（overflow page、多層 b-tree、WAL）。
- **文件與翻譯**：英文或其他語言的說明。

流程很簡單：fork → 改 `totp-offline/src/` → `node build.js` → 把 `dist/offline-authenticator.html` 複製回根目錄 → 發 PR。
根目錄那份成品是**已提交的權威副本**，也是大家實際下載的檔案，改動原始碼後請務必同步更新它。

**請不要**在 issue 或 PR 中貼上真實的密鑰、可用的 `.db` 檔案，或任何含個人資料的截圖。要提供樣本時，請自行產生測試用的假帳號。

---

## 免責

- 本專案為非官方工具，與 Authenticator Plus / mufri.com 沒有任何關聯。
- 2FA 攸關帳號安全。請務必自行保留各服務的 recovery code，並在移除舊驗證器之前確認新工具產生的驗證碼可以正常登入。
- 保管庫密碼沒有後門、沒有「忘記密碼」：忘記就真的救不回，只能靠各服務的備用碼。

---

## 授權

[MIT](LICENSE)
