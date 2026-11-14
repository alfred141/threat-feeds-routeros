# threat-feeds-routeros

把 FireHOL、HaGeZi、ipsum、abuse.ch、Q-Feeds 等公開威脅情資來源，在 **PC 端**抓取、解析、跨來源去重、合併網段，切塊成 MikroTik RouterOS 可直接 `/import` 的 `.rsc` 檔。

> 為什麼不直接在 RouterOS 上抓？
> RouterOS 的 `/tool fetch` 變數上限 64KB、`/file read` 需要自己處理分塊邊界，逐筆 `add` 35 萬筆要跑 20～40 分鐘。PC 端一次抓好再用 `/import`（原生 parser）匯入，是快 10 倍以上的做法。

---

## 特色

| | |
|---|---|
| **多來源容錯** | 每個來源都有主網址 + jsDelivr 鏡像，單一下載失敗自動切換 |
| **跨來源全域去重** | 12 個來源合併成一份，沒有重複政策 |
| **CIDR 等價合併** | 用 `ipaddress.collapse_addresses()` 把「完全被涵蓋」的相鄰 IP 併成網段，**不會多擋任何一個 IP** |
| **自動切塊** | 避開 RouterOS `/import` 的 `Use verbose mode for large files` 限制 |
| **DNS 故障繞過** | Ubuntu 上 DNS 壞掉時自動改走 `resolvectl` / `dig` 直查公共 DNS |
| **分層輸出** | `threat_all`（forward 鏈，全開）／ `threat_strict`（input 鏈，高信心） |
| **可稽核** | 產出 `manifest.txt`：各來源筆數、總筆數、SHA256 |

---

## 資料來源

| # | 來源 | 內容 | 參考筆數 | 更新頻率 | strict | 備註 |
|---|---|---|---|---|---|---|
| 1 | `fh_l1` | dshield / feodo / fullbogons / spamhaus_drop | 3,946 網段 / 611,218,753 IPs | 每日 | ✅ | 幾乎全是大網段，記憶體友善 |
| 2 | `fh_l2` | blocklist_de / dshield_1d / greensnow | 15,860 網段 / 34,240 IPs | 每日 | ✅ | 近 48 小時攻擊來源 |
| 3 | `fh_l3` | bruteforceblocker / ciarmy / myip / vxvault | 12,636 網段 / 35,110 IPs | 每日 | — | 近 30 天回報 |
| 4 | `fh_l4` | blocklist_net_ua / botscout / cybercrime / iblocklist_* | 178,778 網段 / 9,318,326 IPs | 每日 | — | ⚠️ **官方標註大量誤報**，含 IDC／雲端主機段 |
| 5 | `fh_webclient` | 網頁不該連的來源 | 517 網段 / 520 IPs | 每日 | — | |
| 6 | `fh_webserver` | 架設惡意內容的主機 | 894 網段 / 60,597 IPs | 每日 | — | |
| 7 | `c2_tracker` | Cobalt Strike / Sliver / Metasploit | 2,470 IPs | 每 7 天 | ✅ | ⚠️ 上游 repo 已封存，**已凍結不再更新** |
| 8 | `ipsum_1` | 30+ 來源 union | 136,343 IPs | 每日 | — | level N = 出現在 N 個以上名單 |
| 9 | `et_compromised` | 已入侵主機 | ~584 IPs | 每日 | ✅ | |
| 10 | `tor_exits` | Tor 出口節點 | ~1,252 IPs | 每日 | — | |
| 11 | `hg_tif` | HaGeZi Threat Intelligence Feed | 36,031 IPs | 每日 | ✅ | 惡意軟體 / C2 / 釣魚 / 挖礦 |
| 12 | `hg_doh` | 公開 DoH / DoT 解析器 | 1,779 IPs | 每日 | — | 用於封鎖 DNS 洩漏 |
| 13 | `tf_recent` | ThreatFox（abuse.ch） | 動態 | 每日 | ✅ | ⚠️ **需 Auth-Key** |
| 14 | `urlhaus` | URLhaus（abuse.ch） | 動態 | 每日 | — | ⚠️ **需 Auth-Key** |
| 15 | `qf_malware` | Q-Feeds malware IP | 動態 | 每日 | — | 需免費 token；每頁 4,000 筆自動分頁 |

`strict` = 建議納入 **input 鏈**（擋 router 自身）的子集。

### ⚠️ 來源注意事項

**FireHOL `level4` 誤報風險最高**
`firehol_level4` 官方說明直接寫「may include a large number of false positives」[^firehol-level4]，內容包含 `blocklist_net_ua`（IDC / 雲端主機段）與 `iblocklist_*`。容易誤傷 Cloudflare、GitHub Actions、各類 SaaS。
→ **建議：匯入後觀察一週，若有誤擋就把 `fh_l4` 從 `feeds.txt` 移除再重跑。**

**abuse.ch 需要 Auth-Key**
自 2025 年 10 月起，ThreatFox / URLhaus / MalwareBazaar 的檔案匯出都需要在 URL 中帶入 Auth-Key[^abusech-auth]，舊的公開匯出路徑已回傳 `410 Gone`。
→ 免費申請：https://auth.abuse.ch/

**C2-Tracker 已封存**
原始 repo 的 `data/` 文字檔已被移除且不再更新，本專案改用 FireHOL 保留的 `c2_tracker.ipset`（每 7 天更新，但因上游已死實際上等於凍結。要即時的 C2 資料請依賴 ThreatFox。

**Q-Feeds 免費版**
Community 版為每日更新、內容為 OSINT 彙整。更快的更新頻率與商業情資需付費方案。

---

## 系統需求

- Linux（Ubuntu / Debian 已實測），macOS 亦可
- `bash` 4+
- `python3`（用於 CIDR 合併與 CSV 解析）
- `curl`
- `unzip`（選用，ThreatFox 改用 python zipfile 則不需要）

---

## 快速開始

```bash
git clone <your-repo> threat-feeds-routeros
cd threat-feeds-routeros
chmod +x build_feeds.sh

# 互動式輸入 token（不會寫入 shell history）
read -rs -p "Q-Feeds token : " QF_TOKEN; echo
read -rs -p "abuse.ch AuthKey: " ABUSECH_KEY; echo
export QF_TOKEN ABUSECH_KEY

bash build_feeds.sh

unset QF_TOKEN ABUSECH_KEY
```

### 輸出

```
=== 抓取靜態來源 ===
fh_l1          4648
fh_l2          16073
fh_l3          13156
fh_l4          186543
fh_webclient   520
fh_webserver   976
c2_tracker     2470
ipsum_1        136343
et_compromised 584
tor_exits      1252
hg_tif         36031
hg_doh         1779

=== ThreatFox (abuse.ch) ===
tf_recent      12345

=== Q-Feeds ===
      qfeeds page 1    4000 lines
      ...
qf_malware     45678

=== 合併去重 ===
merged unique : 358432
strict unique : 62110

=== CIDR 合併 ===
CIDR merge   : 358432 -> 281093 entries (78.4% retained, 0 invalid)

=== 產生 .rsc ===
-rw-r--r-- 1 user user  20M threat_all.rsc
-rw-r--r-- 1 user user 3.5M threat_strict.rsc
chunks: 12 + strict 3
```

---

## 環境變數

| 變數 | 預設 | 說明 |
|---|---|---|
| `QF_TOKEN` | 空 | Q-Feeds API token（https://tip.qfeeds.com/） |
| `ABUSECH_KEY` | 空 | abuse.ch Auth-Key（https://auth.abuse.ch/） |
| `INCLUDE_QFEEDS` | `1` | 是否匯入 Q-Feeds |
| `INCLUDE_THREATFOX` | `1` | 是否匯入 ThreatFox |
| `INCLUDE_URLHAUS` | `1` | 是否匯入 URLhaus |
| `QF_INCLUDE_IPV6` | `0` | `1` = 保留 Q-Feeds 的 IPv6 項目 |
| `QF_LIMIT` | `4000` | Q-Feeds 每頁筆數（官方腳本值） |
| `COLLAPSE_CIDR` | `1` | `0` = 不做網段合併 |
| `CHUNK_SIZE` | `25000` | 每個 chunk 行數；匯入報錯就減半 |
| `OUT_DIR` | `feeds` | 產物輸出目錄 |

> 🔐 **Token 安全**：`QF_TOKEN` / `ABUSECH_KEY` 請務必用 `read -rs` 輸入，不要直接寫在指令列（會進 shell history），也**不要 commit 進 git**。

---

## 匯入 MikroTik RouterOS

### 0. 前置：先建白名單 ⚠️

**先做這步，否則會把自己鎖在門外。**

```
/ip firewall address-list add list=trusted address=<你的管理IP> comment="admin"
/ip firewall address-list add list=trusted address=<你的出口IP> comment="office"
```

### 1. 上傳檔案

用 WinSCP / SFTP / Files 把 `chunk_*.rsc` 與 `schunk_*.rsc` 全部傳到 router。

### 2. 匯入（舊版Router OS，逐塊）

```
/ip firewall address-list remove [find where list=threat_all]
/ip firewall address-list remove [find where list=threat_strict]

/import file-name=chunk_00.rsc
/import file-name=chunk_01.rsc
...
/import file-name=schunk_00.rsc
```

> 為什麼要切塊？
> RouterOS 的 `/import` 遇到大型檔案且未加 `verbose=yes` 時，會直接拒絕執行並提示 `Use verbose mode for large files`。切塊後每檔 2.5 萬行即可正常匯入，也讓排程可以自動執行。
> 若某塊仍報錯，把 `CHUNK_SIZE` 改成 `12500` 重切。

### 2. 匯入（一個檔案完整匯入）

#### 2.1 指令

| 目的 | 指令 |
|---|---|
| 先測試檔案，不動到現有設定 | `import file-name=threat_all.rsc verbose=yes dry-run` |
| 只看匯入進度，不逐行輸出 | `import file-name=threat_all.rsc verbose=progress` |
| 重跑並找出卡住或出錯的行 | `import file-name=threat_all.rsc verbose=yes` |

在 verbose 模式下會逐行執行並回報，遇到問題時會停下來並指出出錯的位置；`dry-run` 則可在完全不更動設定的情況下找出錯誤。

匯入後可再確認：
- 相關區段是否有內容，例如 `/ip firewall filter print` 或 `/ip firewall address-list print`（依 `threat_all.rsc` 的內容而定）。
- 若該裝置原本就有類似的規則或位址清單，可能出現名稱重複（naming conflict）錯誤，用 verbose 模式即可看到是哪一行。

把完整的 verbose／dry-run 輸出貼上來，我可以幫你指出是哪幾行失敗。查證如下（版本資訊來自 MikroTik 官方 CHANGELOG）。

##### `/import` 各參數的起始版本

| 功能 | 起始版本 | 說明 |
| --- | --- | --- |
| `/import` 指令本身 | v6.0 | 整份匯入，預設不逐行輸出 |
| `verbose=yes` | **v6.2**（2013-08-02） | 逐行執行並顯示內容，遇到錯誤即停止 |
| `verbose=progress` | **v7.16**（2024） | 顯示匯入進度狀態更新，且只在失敗時輸出詳細內容 |
| `dry-run` | **v7.16**（2024） | 模擬匯入以找出語法錯誤、不變更設定；原文明確標示僅在 verbose 模式下可用 |

v6.2 的 changelog 原文：

> `*) console - added 'verbose' argument to '/import' command that enables line-by-line script import. By default import whole script at once and don't print it, as it was in version 6.0;`

##### 實務上的幾點差異

- **v6 只接受 `verbose=yes`／`no`**；`verbose=progress` 這個第三個選值是 v7.16 才加的。
- **v6 沒有 `dry-run`**。你在文件裡寫的 `import file-name=threat_all.rsc verbose=yes dry-run` 只在 v7.16 以上能用，v6 裝置執行會報參數錯誤。
- **v6 的 `verbose=yes` 會把整個檔案逐行印出**，像 `threat_all.rsc` 這種大檔會洗版；v7.16 以後建議改用 `verbose=progress`，只在失敗時才輸出細節。
- 你看到的 `Use verbose mode for large files` 只是提示預設（非 verbose）模式不適合大檔，不是錯誤。

確認目前裝置版本可用：

```
/system resource print
```

如果這份文件要同時支援 v6 與 v7 裝置，建議把驗證步驟改成分版本寫法，例如：

```
# v7.16 以上：模擬匯入，不變更設定
/import file-name=threat_all.rsc verbose=yes dry-run

# v6：只能逐行執行並在錯誤處停下
/import file-name=threat_all.rsc verbose=yes
```

並在文件中標註 `dry-run` 需 v7.16 以上、否則讀者會在 v6 裝置上踩到參數錯誤。

**References**

: [download.mikrotik.com](https://download.mikrotik.com/routeros/7.16rc2/CHANGELOG) (64%)
: [download.mikrotik.com](https://download.mikrotik.com/routeros/6.2/CHANGELOG) (36%)

#### 2.2 兩份檔案的關係

| 檔案 | 內容 | 來源 |
| --- | --- | --- |
| `threat_all.rsc` | 完整清單 | `feeds.txt` 全部 + abuse.ch + Q-Feeds 的聯集 |
| `threat_strict.rsc` | 精簡清單 | 僅標記 `strict=yes` 的項目 ⊂ `threat_all.rsc` |

簡言之：**`threat_strict.rsc` 的每一筆都已經包含在 `threat_all.rsc` 裡面**，
兩者不是互斥清單，而是「完整 ⊃ 精簡」的關係。

#### 2.3 匯入前必做：清除舊清單

重複執行匯入會造成重複項目報錯：

    failure: already have such entry

而且 RouterOS 會在該行**中止匯入**，後面的項目都不會寫入。
所以每次更新前先清掉同名清單：

    /ip firewall address-list remove [find list=threat-all]
    /ip firewall address-list remove [find list=threat-strict]
    /import file-name=threat_all.rsc
    /import file-name=threat_strict.rsc

> 若 `threat_all.rsc` 與 `threat_strict.rsc` 寫進**同一個** list 名稱，
> 第二份會整份撞名而匯不進去。請讓兩份檔案使用**不同的 list 名稱**
> （例如 `threat-all` / `threat-strict`），或在腳本產生端就分流好。

#### 2.4 驗證

    /ip firewall address-list print count-only where list=threat-all
    /ip firewall address-list print count-only where list=threat-strict

匯入前想先試跑、不動到現有設定：

    /import file-name=threat_all.rsc verbose=yes dry-run

`dry-run` 只模擬不變更設定；`verbose` 可設 `no` / `yes` / `progress`。
大檔案時畫面出現 `Use verbose mode for large files` 只是提示，不是錯誤。



### 3. 驗證

```
/ip firewall address-list print count-only where list=threat_all
/ip firewall address-list print count-only where list=threat_strict
/system resource print
```

### 4. 防火牆規則

```
/ip firewall filter add chain=input action=accept src-address-list=trusted \
    comment="Accept trusted" place-before=0
/ip firewall filter add chain=input action=drop src-address-list=threat_strict \
    comment="Drop threat (input)" place-before=0

/ip firewall filter add chain=forward action=accept src-address-list=trusted \
    comment="Accept trusted" place-before=0
/ip firewall filter add chain=forward action=drop src-address-list=threat_all \
    comment="Drop threat (forward)" place-before=0

# 封鎖公開 DoH / DoT（只放 forward，不影響 router 自己的 DNS）
/ip firewall filter add chain=forward action=drop src-address-list=hg_doh \
    comment="Block public DoH/DoT" place-before=0
```

### 5. 排程（重開機自動重建）

`timeout=1d` 的項目只存在 **RAM**，重開機會消失，所以 `start-time=startup` 一定要有。

建立 `/system script`（名稱 `import-threat`）：

```routeros
{
  /ip firewall address-list remove [find where list=threat_all]
  /ip firewall address-list remove [find where list=threat_strict]
  :local ok 0
  :local bad 0
  :foreach f in=[/file find where name~"^chunk_"] do={
    :local n [/file get $f name]
    :do { /import file-name=$n :set ok ($ok + 1) } on-error={ :set bad ($bad + 1) }
  }
  :foreach f in=[/file find where name~"^schunk_"] do={
    :local n [/file get $f name]
    :do { /import file-name=$n :set ok ($ok + 1) } on-error={ :set bad ($bad + 1) }
  }
  :log info ("threat import: ok=" . $ok . " failed=" . $bad)
}
```

```
/system scheduler add name=threatfeeds-startup on-event="/system script run import-threat" \
    start-time=startup policy=read,write,policy,test
```

> 排程每天重跑也可以，但一次要 10～25 分鐘，建議排離峰時間。

---

## 記憶體估算

RouterOS 的 address-list **每一筆都是一個獨立物件**，不論是 `/32` 還是 `/24`。實測約 **320 bytes/筆**。

| 項目 | 筆數 | 估 RAM |
|---|---|---|
| `threat_all` | ~280,000 | ~90 MiB |
| `threat_strict` | ~62,000 | ~20 MiB |
| **合計** | | **~110 MiB** |

hEX S（512MiB）實測餘裕足夠。匯入前後都跑一次 `/system resource print` 確認。

---

## 關於網段合併（CIDR collapse）

很多清單看起來「都是單一 IP 沒網段」，這是**上游本來就是 host 清單**，不是處理錯誤：

- FireHOL 的 `.netset` 檔頭標示 `Aggregation : none` —— 它**刻意不**把相鄰 IP 併成大網段（因為那會多擋無辜 IP）
- `ipsum_1`、`hg_tif`、`c2_tracker`、`tor_exits` 全部都是單一 IP 格式
- 但 `fh_l1` 幾乎全是網段（`0.0.0.0/8`、`224.0.0.0/3`…），`fh_l4` 則是混合

`collapse_addresses()` 只在**集合完全被涵蓋**時才合併，所以：

```
1.2.3.4 + 1.2.3.5 + 1.2.3.6 + 1.2.3.7  →  1.2.3.4/30
```

兩者封鎖的位址集合**完全相同**，不會多擋任何一個 IP，但物件數從 4 降到 1。

---

## 疑難排解

<details>
<summary><b>DNS: Could not resolve host</b></summary>

Ubuntu 上 DNS 查不到名稱。腳本會自動嘗試 `getent` → `resolvectl` → `dig @1.1.1.1` 三層備援。

手動修：

```bash
IFACE=$(ip -o -4 route show to default | awk '{print $5; exit}')
sudo resolvectl revert "$IFACE"
sudo resolvectl dns "$IFACE" 1.1.1.1 8.8.8.8
sudo resolvectl domain "$IFACE" ~.
```

若 `/etc/resolv.conf` 是實體檔而非 symlink，`resolvectl` 設定不會生效：

```bash
ls -l /etc/resolv.conf
sudo rm -f /etc/resolv.conf
sudo ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```
</details>

<details>
<summary><b>ThreatFox / URLhaus 回傳 401 / 403 / 410</b></summary>

abuse.ch 已強制 Auth-Key，且必須放在 URL 中[^abusech-auth]。免費申請：https://auth.abuse.ch/
Token 本身有額度限制，别把 key 寫進公開 repo。
</details>

<details>
<summary><b>/import 顯示 Use verbose mode for large files</b></summary>

檔案太大且沒加 `verbose=yes`。解法是用 `chunk_*.rsc` 切塊檔匯入，或改小 `CHUNK_SIZE`。
</details>

<details>
<summary><b>匯入後連不上 router</b></summary>

一定是被自己的封鎖規則鎖住。用 MAC-WinBox 進去，把 `trusted` 白名單先建好，或暫時把 drop 規則移除：

```
/ip firewall filter print
/ip firewall filter remove [find where comment="Drop threat"]
```
</details>

<details>
<summary><b>RAM 不夠 / 匯入後 router 很卡</b></summary>

1. 從 `feeds.txt` 移除 `fh_l4`（約 18.6 萬筆，佔最多 RAM 且最容易誤擋）
2. 再考慮移除 `ipsum_1`（13.6 萬筆）
3. 保留 `fh_l1` + `fh_l2` + `hg_tif` + `c2_tracker` + `et_compromised` 即可覆蓋多數威脅
</details>

<details>
<summary><b>某個來源筆數是 0 或 FAIL</b></summary>

腳本會在最後顯示 `failed_feeds=N` 並以 exit code 1 結束，方便 cron / CI 監控。
常見原因：token 過期、來源改路徑、暫時性網路故障。
</details>

---

## 授權

### 本專案程式碼

`build_feeds.sh`、`feeds.txt` 及本 repo 的其他原始碼檔案以
[MIT License](LICENSE) 授權釋出。

### 產生的資料（`feeds/` 目錄）

本專案**不在 repo 中散布**任何威脅情資資料。所有資料在使用者
本機由 `build_feeds.sh` 即時抓取產生，並受各自上游來源的授權與
服務條款約束：

| 來源 | 授權／條款 |
|---|---|
| [HaGeZi dns-blocklists](https://github.com/hagezi/dns-blocklists) | GPL-3.0（僅涵蓋其發布的清單本身，上游資料權利另計） |
| [stamparm/ipsum](https://github.com/stamparm/ipsum) | Unlicense（公有領域奉獻） |
| [firehol/blocklist-ipsets](https://github.com/firehol/blocklist-ipsets) | 各子清單授權不一，請查其原始來源 |
| [abuse.ch](https://abuse.ch/) ThreatFox / URLhaus | 免費供商業與非商業使用；受 API 規範與速率限制 |
| [Q-Feeds](https://www.qfeeds.com/) | ! 僅限內部使用，不得散布／再授權／轉售 |
| [Emerging Threats](https://rules.emergingthreats.net/) | 請查其原始來源條款 |
| [Tor Project](https://check.torproject.org/) | 出口節點清單，公開資料 |

> **特別提醒**：本專案產生的清單若包含 Q-Feeds 資料，**不得**公開
> 發佈或再散布。設定 `INCLUDE_QFEEDS=0` 可排除該來源。

### 免責聲明

本專案僅提供資料聚合與格式轉換工具，不對資料內容做任何背書。使用者在採用任何封鎖清單前，務必自行評估誤報率並建立自己的白名單。

---

## 致謝

- [FireHOL](https://github.com/firehol/blocklist-ipsets)
- [HaGeZi](https://github.com/hagezi/dns-blocklists)
- [stamparm/ipsum](https://github.com/stamparm/ipsum)
- [abuse.ch](https://abuse.ch/)
- [Q-Feeds](https://www.qfeeds.com/)
