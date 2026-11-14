#!/usr/bin/env bash
#
# build_feeds.sh — 為 MikroTik RouterOS 產生 threat-intelligence address-list
#
# 產出:
#   feeds/threat_all.cidr       合併去重 + 網段合併後的 CIDR 清單
#   feeds/threat_all.rsc        RouterOS 匯入檔（整包）
#   feeds/chunk_XX.rsc          RouterOS 匯入檔（切塊，避免 "Use verbose mode for large files"）
#   feeds/threat_strict.rsc     高信心子集（給 input 鏈）
#   feeds/schunk_XX.rsc         高信心子集切塊
#   feeds/manifest.txt          本次產出的統計與 SHA256
#
# 用法:
#   read -rs -p "QF token: " QF_TOKEN; echo
#   read -rs -p "abuse.ch key: " ABUSECH_KEY; echo
#   export QF_TOKEN ABUSECH_KEY
#   bash build_feeds.sh
#   unset QF_TOKEN ABUSECH_KEY
#
set -uo pipefail

VERSION="1.1.0"

# ------------------------------------------------------------------
# 0. 可調參數
# ------------------------------------------------------------------
QF_TOKEN="${QF_TOKEN:-}"                   # Q-Feeds API token (https://tip.qfeeds.com/)
ABUSECH_KEY="${ABUSECH_KEY:-}"             # abuse.ch Auth-Key (https://auth.abuse.ch/)
QF_LIMIT="${QF_LIMIT:-4000}"               # Q-Feeds 每頁筆數（官方腳本值）
QF_MAXPAGE="${QF_MAXPAGE:-999}"
QF_INCLUDE_IPV6="${QF_INCLUDE_IPV6:-0}"    # 1 = 保留 Q-Feeds 的 IPv6
INCLUDE_QFEEDS="${INCLUDE_QFEEDS:-1}"
INCLUDE_THREATFOX="${INCLUDE_THREATFOX:-1}"
INCLUDE_URLHAUS="${INCLUDE_URLHAUS:-1}"
COLLAPSE_CIDR="${COLLAPSE_CIDR:-1}"        # 1 = 把完全涵蓋的相鄰 IP 合併成 CIDR
CHUNK_SIZE="${CHUNK_SIZE:-25000}"          # 每個 chunk 行數；匯入報錯就減半
OUT_DIR="${OUT_DIR:-feeds}"

UA='Mozilla/5.0 (X11; Linux x86_64) threatfeeds-routeros/1.1'
FALLBACK_DNS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
RX4='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEEDS_FILE="${FEEDS_FILE:-$SCRIPT_DIR/feeds.txt}"

command -v python3 >/dev/null 2>&1 || { echo "ERROR: 需要 python3"; exit 1; }
command -v curl    >/dev/null 2>&1 || { echo "ERROR: 需要 curl"; exit 1; }

mkdir -p "$OUT_DIR" && cd "$OUT_DIR" || exit 1

# ------------------------------------------------------------------
# 1. 工具函式
# ------------------------------------------------------------------
trim() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "$v"
}

# 多層 DNS 解析備援：getent → resolvectl → dig @公共DNS
resolve_ip() {
  local host="$1" ip="" r=""
  ip=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
  [ -n "$ip" ] && { printf '%s' "$ip"; return 0; }

  if command -v resolvectl >/dev/null 2>&1; then
    ip=$(resolvectl query --type=A "$host" 2>/dev/null \
         | awk '/: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/{print $NF; exit}')
    [ -n "$ip" ] && { printf '%s' "$ip"; return 0; }
  fi

  if command -v dig >/dev/null 2>&1; then
    for r in "${FALLBACK_DNS[@]}"; do
      ip=$(dig +short +time=3 +tries=1 "@$r" "$host" A 2>/dev/null \
           | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | head -1)
      [ -n "$ip" ] && break
    done
    [ -n "$ip" ] && { printf '%s' "$ip"; return 0; }
  fi
  return 1
}

# 下載；DNS 壞掉時改用 --resolve 直連
fetch_to() {
  local url="$1" out="$2"; shift 2
  local common=(--retry 2 --retry-delay 2 --retry-connrefused
                --connect-timeout 15 --max-time 300 -A "$UA" -fsSL)
  if curl "${common[@]}" "$@" "$url" -o "$out" 2>/dev/null; then return 0; fi
  local host ip
  host=$(printf '%s' "$url" | sed -E 's#^https?://([^/]+).*#\1#')
  ip=$(resolve_ip "$host") || return 1
  curl "${common[@]}" "$@" --resolve "${host}:443:${ip}" "$url" -o "$out" 2>/dev/null
}

# ------------------------------------------------------------------
# 2. 來源定義
# ------------------------------------------------------------------
if [ ! -f "$FEEDS_FILE" ]; then
  echo "找不到 $FEEDS_FILE，請從 README 複製 feeds.txt 過來。" >&2
  exit 1
fi

# ------------------------------------------------------------------
# 3. 抓取靜態來源
# ------------------------------------------------------------------
echo "=== 抓取靜態來源 ==="
FAILED=0
STRICT_PARTS=()

while IFS= read -r line; do
  line=$(trim "$line")
  [ -z "$line" ] && continue
  case "$line" in \#*) continue ;; esac

  IFS='|' read -r f_name f_url1 f_url2 f_min f_strict <<< "$line"
  f_name=$(trim "$f_name"); f_url1=$(trim "$f_url1"); f_url2=$(trim "$f_url2")
  f_min=$(trim "$f_min"); f_strict=$(trim "$f_strict")
  [ -z "$f_name" ] && continue
  [ -z "$f_min" ] && f_min=1

  ok=0
  for url in "$f_url1" "$f_url2"; do
    [ -z "$url" ] && continue
    if fetch_to "$url" "$f_name.raw"; then ok=1; break; fi
  done

  if [ "$ok" != 1 ]; then
    printf '%-14s FAIL (download)\n' "$f_name"
    : > "$f_name.ip"
    FAILED=$((FAILED+1))
    continue
  fi

  sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$f_name.raw" \
    | grep -E "$RX4" | sort -u > "$f_name.ip" || true
  cnt=$(wc -l < "$f_name.ip")

  if [ "$cnt" -lt "$f_min" ]; then
    printf '%-14s %-8s  ⚠ 低於預期 %s（來源可能改版）\n' "$f_name" "$cnt" "$f_min"
  else
    printf '%-14s %s\n' "$f_name" "$cnt"
  fi

  case "$f_strict" in
    yes|1|true) STRICT_PARTS+=("$f_name.ip") ;;
  esac
done < "$FEEDS_FILE"

# ------------------------------------------------------------------
# 4. ThreatFox (abuse.ch) — 自 2025-10 起匯出必須帶 Auth-Key
# ------------------------------------------------------------------
echo
echo "=== ThreatFox (abuse.ch) ==="
: > tf_recent.ip
if [ "$INCLUDE_THREATFOX" = "1" ]; then
  if [ -z "$ABUSECH_KEY" ]; then
    echo "SKIP  threatfox （未設定 ABUSECH_KEY）"
  else
    tf_zip="tf_full.csv.zip"
    if fetch_to "https://threatfox-api.abuse.ch/v2/files/exports/${ABUSECH_KEY}/full.csv.zip" "$tf_zip"; then
      python3 - "$tf_zip" <<'PY' || echo "FAIL  threatfox (unzip)"
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    name = z.namelist()[0]
    data = z.read(name).decode('utf-8', 'replace')
open('tf_full.csv', 'w', encoding='utf-8').write(data)
PY
      if [ -s tf_full.csv ]; then
        python3 - <<'PY' || echo "FAIL  threatfox (parse)"
import csv, re
rx = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$')
out = set()
with open('tf_full.csv', newline='', encoding='utf-8', errors='replace') as f:
    r = csv.reader(f)
    header = []
    try:
        header = next(r)
    except StopIteration:
        pass
    try:
        idx = [h.strip().lower() for h in header].index('ioc_value')
    except ValueError:
        idx = 2
    for row in r:
        if len(row) <= idx:
            continue
        v = row[idx].strip()
        if ':' in v:
            v = v.split(':')[0]
        if rx.match(v):
            out.add(v)
with open('tf_recent.ip', 'w', encoding='utf-8') as f:
    f.write('\n'.join(sorted(out)) + ('\n' if out else ''))
PY
      fi
    else
      echo "FAIL  threatfox (download，請確認 ABUSECH_KEY 與額度)"
    fi
  fi
fi
printf '%-14s %s\n' "tf_recent" "$(wc -l < tf_recent.ip)"

# ------------------------------------------------------------------
# 5. URLhaus (abuse.ch)
# ------------------------------------------------------------------
echo
echo "=== URLhaus (abuse.ch) ==="
: > urlhaus.ip
if [ "$INCLUDE_URLHAUS" = "1" ]; then
  if [ -z "$ABUSECH_KEY" ]; then
    echo "SKIP  urlhaus （未設定 ABUSECH_KEY）"
  else
    uh_ok=0
    for uh_url in \
      "https://urlhaus-api.abuse.ch/v1/hostfile/" \
      "https://urlhaus.abuse.ch/downloads/hostfile/" \
      "https://urlhaus-api.abuse.ch/v1/hostfile/${ABUSECH_KEY}/"; do
      if fetch_to "$uh_url" uh.raw -H "Auth-Key: $ABUSECH_KEY"; then uh_ok=1; break; fi
    done
    if [ "$uh_ok" = 1 ] && [ -s uh.raw ]; then
      sed -E 's#^[A-Za-z]+://##; s#/.*$##; s#:[0-9]+$##' uh.raw \
        | grep -E "$RX4" | sort -u > urlhaus.ip || true
    else
      echo "FAIL  urlhaus (download，請確認 ABUSECH_KEY 與額度)"
    fi
  fi
fi
printf '%-14s %s\n' "urlhaus" "$(wc -l < urlhaus.ip)"

# ------------------------------------------------------------------
# 6. Q-Feeds（分頁，每頁 4,000 筆）
# ------------------------------------------------------------------
echo
echo "=== Q-Feeds ==="
: > qf_malware.ip
if [ "$INCLUDE_QFEEDS" = "1" ]; then
  if [ -z "$QF_TOKEN" ]; then
    echo "SKIP  qfeeds （未設定 QF_TOKEN）"
  else
    qf_raw="qf_malware.raw"; : > "$qf_raw"
    page=1
    while [ "$page" -le "$QF_MAXPAGE" ]; do
      tmp="qf_page_${page}.txt"
      qf_url="https://api.qfeeds.com/api.php?feed_type=malware_ip&api_token=${QF_TOKEN}&page=${page}&limit=${QF_LIMIT}"
      [ "$QF_INCLUDE_IPV6" = "0" ] && qf_url="${qf_url}&ipv6=0"
      if ! fetch_to "$qf_url" "$tmp"; then
        echo "FAIL  qfeeds page ${page}"; break
      fi
      n=$(wc -l < "$tmp")
      if [ "$n" -eq 0 ]; then
        echo "      qfeeds: 沒有更多資料（停在 page ${page}）"; break
      fi
      cat "$tmp" >> "$qf_raw"
      printf '      qfeeds page %-4s %s lines\n' "$page" "$n"
      if [ "$n" -lt "$QF_LIMIT" ]; then
        echo "      qfeeds: 最後一頁 = ${page}"; break
      fi
      page=$((page+1))
    done
    sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$qf_raw" \
      | grep -E "$RX4" | sort -u > qf_malware.ip || true
    rm -f qf_page_*.txt "$qf_raw"
  fi
fi
printf '%-14s %s\n' "qf_malware" "$(wc -l < qf_malware.ip)"

# ------------------------------------------------------------------
# 7. 合併去重（排除輸出檔本身，避免自我截斷）
# ------------------------------------------------------------------
echo
echo "=== 合併去重 ==="
find . -maxdepth 1 -type f -name '*.ip' \
  ! -name 'threat_all.ip' ! -name 'threat_strict.ip' ! -name 'merged.tmp' \
  -print0 | xargs -0 cat | sort -u > merged.tmp
mv merged.tmp threat_all.ip
echo "merged unique : $(wc -l < threat_all.ip)"

STRICT_PARTS+=("tf_recent.ip" "urlhaus.ip")
cat ${STRICT_PARTS[@]+"${STRICT_PARTS[@]}"} 2>/dev/null | sort -u > threat_strict.ip
echo "strict unique : $(wc -l < threat_strict.ip)"

# ------------------------------------------------------------------
# 8. CIDR 等價合併（不會多擋任何 IP）
# ------------------------------------------------------------------
echo
echo "=== CIDR 合併 ==="
python3 - <<'PY'
import ipaddress
nets, bad = [], 0
for line in open('threat_all.ip', encoding='utf-8', errors='replace'):
    s = line.strip()
    if not s:
        continue
    try:
        nets.append(ipaddress.ip_network(s, strict=False))
    except ValueError:
        bad += 1
v4 = [n for n in nets if n.version == 4]
v6 = [n for n in nets if n.version == 6]
merged = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
with open('threat_all.cidr', 'w', encoding='utf-8') as f:
    for n in merged:
        f.write(str(n) + '\n')
print(f'CIDR merge   : {len(nets)} -> {len(merged)} entries '
      f'({100*len(merged)/max(1,len(nets)):.1f}% retained, {bad} invalid)')
PY

if [ "$COLLAPSE_CIDR" = "1" ]; then SRC_ALL="threat_all.cidr"; else SRC_ALL="threat_all.ip"; fi

# ------------------------------------------------------------------
# 9. 產生 .rsc + 切塊
# ------------------------------------------------------------------
echo
echo "=== 產生 .rsc ==="
awk '{printf "/ip firewall address-list add list=threat_all address=%s timeout=1d\n", $1}' \
  "$SRC_ALL" > threat_all.rsc
awk '{printf "/ip firewall address-list add list=threat_strict address=%s timeout=1d\n", $1}' \
  threat_strict.ip > threat_strict.rsc

rm -f chunk_*.rsc schunk_*.rsc
split -l "$CHUNK_SIZE" -d -a 2 --additional-suffix=.rsc threat_all.rsc chunk_
split -l "$CHUNK_SIZE" -d -a 2 --additional-suffix=.rsc threat_strict.rsc schunk_

# ------------------------------------------------------------------
# 10. manifest
# ------------------------------------------------------------------
{
  echo "# generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by build_feeds.sh v$VERSION"
  echo "threat_all_entries=$(wc -l < "$SRC_ALL")"
  echo "threat_strict_entries=$(wc -l < threat_strict.ip)"
  echo "chunks=$(ls chunk_*.rsc 2>/dev/null | wc -l)"
  echo "strict_chunks=$(ls schunk_*.rsc 2>/dev/null | wc -l)"
  echo "failed_feeds=$FAILED"
  echo "## sha256"
  sha256sum threat_all.rsc threat_strict.rsc chunk_*.rsc schunk_*.rsc 2>/dev/null
} > manifest.txt

ls -lh threat_all.rsc threat_strict.rsc
echo "chunks: $(ls chunk_*.rsc 2>/dev/null | wc -l) + strict $(ls schunk_*.rsc 2>/dev/null | wc -l)"
echo "manifest.txt"

if [ "$FAILED" -gt 0 ]; then
  echo
  echo "⚠ 有 $FAILED 個來源下載失敗，請檢查上面的輸出。"
  exit 1
fi
echo
echo "✅ 完成"
