#!/usr/bin/env bash
# wp_ioc_scan.sh — WordPress IOC sweep -> self-contained HTML report.
#
# Runs filesystem, core-integrity, config, database and access-log checks and
# writes an HTML report with PASS/FAIL/WARN/INFO per check and drill-down detail.
# Read-only. Safe to run on a live host or a copied webroot.
#
# Usage:
#   ./wp_ioc_scan.sh [--webroot DIR] [--access-log FILE] [--output report.html]
#                    [--json report.json] [--no-html] [--wp /usr/local/bin/wp]
#   (in the lab)  docker compose exec -T wordpress bash /tmp/wp_ioc_scan.sh --output /tmp/report.html
#   JSON for a SIEM:  ./wp_ioc_scan.sh --no-html --json report.json
# Exit code: non-zero if any check FAILed (usable in CI / cron alerting).
set -u

WEBROOT=/var/www/html
ACCESS_LOG=""
OUT="wp_ioc_report.html"
JSONOUT=""
WP="$(command -v wp 2>/dev/null || true)"

while [ $# -gt 0 ]; do
  case "$1" in
    --webroot)    WEBROOT="$2"; shift 2;;
    --access-log) ACCESS_LOG="$2"; shift 2;;
    --output)     OUT="$2"; shift 2;;
    --json)       JSONOUT="$2"; shift 2;;
    --no-html)    OUT=""; shift;;
    --wp)         WP="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

# auto-detect an access log if not given
if [ -z "$ACCESS_LOG" ]; then
  for c in /var/log/apache2/access_file.log /var/log/apache2/access.log \
           /var/log/nginx/access.log "$WEBROOT/../logs/access.log"; do
    [ -f "$c" ] && [ -s "$c" ] && { ACCESS_LOG="$c"; break; }
  done
fi

ALLOW=""; [ "$(id -u)" = "0" ] && ALLOW="--allow-root"
wpcli() { [ -n "$WP" ] && "$WP" $ALLOW --path="$WEBROOT" "$@" 2>/dev/null; }

PREFIX="wp_"; [ -n "$WP" ] && PREFIX="$(wpcli config get table_prefix 2>/dev/null || echo wp_)"
WPVER="$( [ -n "$WP" ] && wpcli core version 2>/dev/null || grep -oE "'7\.[0-9.]+'|'[0-9]+\.[0-9.]+'" "$WEBROOT/wp-includes/version.php" 2>/dev/null | head -1 | tr -d "'" )"
HOST="$(hostname 2>/dev/null || echo unknown)"
NOW="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || echo '')"

# ---- detection patterns ----
SINK_INPUT='(eval|assert|system|shell_exec|passthru|proc_open|popen|pcntl_exec|exec)[[:space:]]*\(.*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
WRITE_INPUT='(file_put_contents|fwrite|fputs)[[:space:]]*\(.*\$_(GET|POST|REQUEST|COOKIE)'
OBF='base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode'
MARKERS='__LABSHELL|c99shell|r57shell|FilesMan|b374k|weevely|WSOsh'

PASS=0; FAIL=0; WARN=0; INFO=0
BODY="$(mktemp)"; JSONBODY="$(mktemp)"; trap 'rm -f "$BODY" "$JSONBODY"' EXIT

hesc() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
# JSON string escaper. First sed escapes backslash/quote/tab/CR on EVERY line;
# second sed collapses embedded newlines to \n. (Doing the slurp first would
# only escape line 1 — a subtle bug when details span multiple lines.)
jesc() {
  printf '%s' "$1" \
    | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' \
    | sed -e ':a;N;$!ba;s/\n/\\n/g'
}
cap()  { head -n 60; }   # cap detail blocks

add() { # status  title  summary  details
  case "$1" in
    PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));;
    WARN) WARN=$((WARN+1));; INFO) INFO=$((INFO+1));;
  esac
  {
    echo "<section class=\"card $1\">"
    echo "<h3><span class=\"badge $1\">$1</span> $(hesc "$2")</h3>"
    echo "<p class=sum>$(hesc "$3")</p>"
    if [ -n "$4" ]; then
      echo "<details><summary>details</summary><pre>$(hesc "$4")</pre></details>"
    fi
    echo "</section>"
  } >> "$BODY"
  printf '{"status":"%s","title":"%s","summary":"%s","details":"%s"},\n' \
    "$1" "$(jesc "$2")" "$(jesc "$3")" "$(jesc "$4")" >> "$JSONBODY"
}

# helper: FAIL if grep hits, else PASS
fs_grep() { # title  summary_noun  pattern
  local det
  det=$(grep -rnIE --include='*.php' "$3" "$WEBROOT/wp-content" 2>/dev/null | cap)
  if [ -n "$det" ]; then
    add FAIL "$1" "$(printf '%s\n' "$det" | grep -c .) match(es) — $2" "$det"
  else
    add PASS "$1" "No $2" ""
  fi
}

echo "[*] scanning $WEBROOT ..."

########## FILESYSTEM ##########
det=$(find "$WEBROOT/wp-content/uploads" -type f -iname '*.php' 2>/dev/null | cap)
if [ -n "$det" ]; then add FAIL "PHP files in uploads" "$(printf '%s\n' "$det"|grep -c .) PHP file(s) under uploads/ (never legitimate)" "$det"
else add PASS "PHP files in uploads" "No PHP files under uploads/" ""; fi

fs_grep "Command/eval sink fed by request input" "request input reaching an exec/eval sink" "$SINK_INPUT"
fs_grep "File-write sink fed by request input" "request input reaching a file-write sink" "$WRITE_INPUT"

det=$(grep -rlIE --include='*.php' "$OBF" "$WEBROOT/wp-content" 2>/dev/null | while read -r f; do grep -qiE 'eval[[:space:]]*\(|assert[[:space:]]*\(|create_function' "$f" && echo "$f"; done | cap)
if [ -n "$det" ]; then add FAIL "Obfuscated code near eval" "$(printf '%s\n' "$det"|grep -c .) file(s) with decoder+eval (packed webshell pattern)" "$det"
else add PASS "Obfuscated code near eval" "No decoder+eval packing found" ""; fi

det=$(grep -rlIE --include='*.php' --include='*.inc' "$MARKERS" "$WEBROOT/wp-content" 2>/dev/null | cap)
if [ -n "$det" ]; then add FAIL "Known webshell markers" "$(printf '%s\n' "$det"|grep -c .) file(s) contain known webshell/infection markers" "$det"
else add PASS "Known webshell markers" "No known webshell markers" ""; fi

REF="$WEBROOT/wp-includes/version.php"
if [ -f "$REF" ]; then
  det=$(find "$WEBROOT/wp-content" -type f -iname '*.php' -newer "$REF" 2>/dev/null | cap)
  if [ -n "$det" ]; then add WARN "PHP newer than core" "$(printf '%s\n' "$det"|grep -c .) PHP file(s) modified after core install — review (could be legit updates)" "$det"
  else add PASS "PHP newer than core" "No PHP modified after core install" ""; fi
fi

# auto-loaded drop-ins (executed with no activation)
det=""
for d in object-cache.php advanced-cache.php db.php maintenance.php; do
  [ -f "$WEBROOT/wp-content/$d" ] && det="$det$WEBROOT/wp-content/$d ($(stat -c '%y' "$WEBROOT/wp-content/$d" 2>/dev/null))\n"
done
if [ -n "$det" ]; then add WARN "Auto-loaded drop-ins present" "Drop-ins run on every request with no dashboard entry — verify each is expected" "$(printf "$det")"
else add PASS "Auto-loaded drop-ins" "No wp-content drop-ins present" ""; fi

# mu-plugins (auto-load, cannot be deactivated from UI)
if [ -d "$WEBROOT/wp-content/mu-plugins" ]; then
  det=$(find "$WEBROOT/wp-content/mu-plugins" -maxdepth 2 -type f -iname '*.php' 2>/dev/null | cap)
  [ -n "$det" ] && add WARN "Must-use plugins present" "mu-plugins auto-load and can't be disabled in the UI — confirm each is expected" "$det" \
                 || add PASS "Must-use plugins" "mu-plugins dir present but empty" ""
else add PASS "Must-use plugins" "No mu-plugins directory" ""; fi

# .htaccess / .user.ini stealth persistence
det=$(grep -rniE 'auto_prepend_file|AddType .*x-httpd-php|SetHandler .*php' "$WEBROOT" --include='.htaccess' --include='.user.ini' 2>/dev/null | cap)
if [ -n "$det" ]; then add FAIL ".htaccess/.user.ini PHP handler" "auto_prepend_file / PHP handler directive found (stealth include or PHP-in-uploads)" "$det"
else add PASS ".htaccess/.user.ini PHP handler" "No auto_prepend_file / PHP-handler injection" ""; fi

# wp-config infection
det=$(grep -niE 'eval[[:space:]]*\(|base64_decode|gzinflate|auto_prepend|shell_exec|__LABSHELL' "$WEBROOT/wp-config.php" 2>/dev/null | cap)
if [ -n "$det" ]; then add FAIL "wp-config.php integrity" "Suspicious code found in wp-config.php" "$det"
else add PASS "wp-config.php integrity" "No obvious injection in wp-config.php" ""; fi

########## CORE / PLUGIN INTEGRITY ##########
if [ -n "$WP" ]; then
  out=$(wpcli core verify-checksums 2>&1)
  bad=$(printf '%s\n' "$out" | grep -iE "doesn't verify against checksum|should not exist" | cap)
  if [ -n "$bad" ]; then add FAIL "Core checksum verification" "Modified or extra core files vs WordPress.org checksums" "$bad"
  elif printf '%s\n' "$out" | grep -qi "verif"; then add PASS "Core checksum verification" "Core files verify against WordPress.org checksums" ""
  else add WARN "Core checksum verification" "Could not verify (version not on WP.org?)" "$out"; fi

  pout=$(wpcli plugin verify-checksums --all 2>&1)
  pbad=$(printf '%s\n' "$pout" | grep -iE "does not verify|Warning|Error" | cap)
  [ -n "$pbad" ] && add WARN "Plugin checksum verification" "One or more plugin files differ from the .org copy (review)" "$pbad" \
                 || add PASS "Plugin checksum verification" "Installed plugins verify against .org checksums" ""
else
  add INFO "Core/plugin checksums" "Skipped — wp-cli not available" ""
fi

########## DATABASE ##########
if [ -n "$WP" ]; then
  admins=$(wpcli user list --role=administrator --fields=ID,user_login,user_email,user_registered --format=csv 2>/dev/null)
  add INFO "Administrator accounts" "Review the admin list for accounts you don't recognise" "$admins"

  su=$(wpcli option get siteurl 2>/dev/null); ho=$(wpcli option get home 2>/dev/null)
  if printf '%s%s' "$su" "$ho" | grep -qiE '<|script|%3c'; then add FAIL "siteurl/home injection" "siteurl/home contains markup — likely injected redirect/script" "siteurl=$su
home=$ho"
  else add PASS "siteurl/home injection" "siteurl/home are clean URLs" ""; fi

  opt=$(wpcli db query "SELECT option_name FROM ${PREFIX}options WHERE autoload='yes' AND (option_value LIKE '%base64_decode%' OR option_value LIKE '%eval(%' OR option_value LIKE '%<script%' OR option_value LIKE '%gzinflate%')" --skip-column-names 2>/dev/null | cap)
  [ -n "$opt" ] && add FAIL "Poisoned autoload options" "Autoloaded wp_options contain eval/base64/script — executed on every load" "$opt" \
                || add PASS "Poisoned autoload options" "No suspicious payloads in autoloaded options" ""

  ap=$(wpcli db query "SELECT user_id FROM ${PREFIX}usermeta WHERE meta_key='_application_passwords' AND meta_value NOT IN ('','a:0:{}')" --skip-column-names 2>/dev/null | cap)
  [ -n "$ap" ] && add WARN "Application passwords" "User(s) have application passwords (persistent auth surviving password resets) — verify" "user_id(s): $ap" \
               || add PASS "Application passwords" "No application passwords set" ""

  cron=$(wpcli cron event list --fields=hook,next_run --format=csv 2>/dev/null | grep -viE '^hook,|wp_|akismet|recovery_mode|delete_expired|wp-cron' | cap)
  [ -n "$cron" ] && add INFO "Scheduled (cron) events" "Non-core cron hooks — confirm each belongs to an installed plugin" "$cron" \
                 || add PASS "Scheduled (cron) events" "No unexpected cron hooks" ""
else
  add INFO "Database checks" "Skipped — wp-cli not available" ""
fi

########## ACCESS LOG ##########
if [ -n "$ACCESS_LOG" ] && [ -r "$ACCESS_LOG" ]; then
  log_check() { # title  summary  pattern  status
    local det cnt
    det=$(grep -aE "$3" "$ACCESS_LOG" 2>/dev/null); cnt=$(printf '%s\n' "$det" | grep -c .)
    if [ "$cnt" -gt 0 ]; then add "$4" "$1" "$cnt request(s) — $2" "$(printf '%s\n' "$det" | tail -n 40)"
    else add PASS "$1" "No $2" ""; fi
  }
  log_check "batch/v1 route-confusion SQLi" "hits on the batch/v1 endpoint (the wp2shell vector)" 'rest_route=/?batch/v1|/wp-json/batch/v1' FAIL
  log_check "Blind SQLi payloads" "requests carrying SQL injection markers" 'SLEEP\(|BENCHMARK\(|UNION.*SELECT|information_schema|author_exclude|%2D%2D|--[[:space:]]' FAIL
  log_check "Webshell access (PHP in uploads)" "requests to a .php file under uploads/" '/wp-content/uploads/[^ "]*\.php' FAIL
  log_check "Command-exec parameters" "requests with cmd/exec-style params" '[?&](cmd|exec|shell|shell_exec|passthru|wp_debug_exec|backdoor)=' FAIL
  log_check "Plugin/theme upload" "plugin/theme upload POSTs (shell delivery)" 'action=upload-plugin|action=upload-theme|/theme-install.php' WARN
  log_check "xmlrpc.php abuse" "xmlrpc requests (brute-force / pingback DDoS)" '/xmlrpc\.php' WARN
  log_check "User enumeration" "author/user-listing probes" '[?&]author=[0-9]|/wp-json/wp/v2/users|rest_route=/wp/v2/users' WARN
else
  add INFO "Access-log checks" "Skipped — no readable access log (pass --access-log FILE)" ""
fi

########## RENDER ##########
TOTAL=$((PASS+FAIL+WARN+INFO))

# ---- JSON ----
if [ -n "$JSONOUT" ]; then
  findings=$(tr -d '\n' < "$JSONBODY"); findings="${findings%,}"
  {
    printf '{\n'
    printf '  "meta": {"host":"%s","webroot":"%s","wp_version":"%s","access_log":"%s","generated":"%s"},\n' \
      "$(jesc "$HOST")" "$(jesc "$WEBROOT")" "$(jesc "${WPVER:-unknown}")" "$(jesc "${ACCESS_LOG:-}")" "$(jesc "$NOW")"
    printf '  "summary": {"pass":%d,"fail":%d,"warn":%d,"info":%d,"total":%d},\n' "$PASS" "$FAIL" "$WARN" "$INFO" "$TOTAL"
    printf '  "findings": [%s]\n' "$findings"
    printf '}\n'
  } > "$JSONOUT"
  echo "[*] json written:   $JSONOUT"
fi

# ---- HTML ----
[ -z "$OUT" ] && { echo "    PASS=$PASS FAIL=$FAIL WARN=$WARN INFO=$INFO (of $TOTAL checks)"; [ "$FAIL" -gt 0 ] && exit 1 || exit 0; }
{
cat <<HTML
<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>WordPress IOC report — $HOST</title>
<style>
:root{color-scheme:light dark}
body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
header{padding:1.4em 1.6em;background:#161a22;border-bottom:1px solid #262c38}
h1{margin:0 0 .2em;font-size:1.35em}
.meta{color:#9aa4b2;font-size:.9em}
.tiles{display:flex;gap:.8em;flex-wrap:wrap;margin:1em 1.6em}
.tile{flex:1;min-width:120px;background:#161a22;border:1px solid #262c38;border-radius:10px;padding:.8em 1em;text-align:center}
.tile b{display:block;font-size:1.8em}
.tile.PASS b{color:#3fb950}.tile.FAIL b{color:#f85149}.tile.WARN b{color:#d29922}.tile.INFO b{color:#58a6ff}
main{padding:0 1.6em 2em}
.card{background:#161a22;border:1px solid #262c38;border-left-width:5px;border-radius:8px;padding:.8em 1em;margin:.7em 0}
.card.PASS{border-left-color:#3fb950}.card.FAIL{border-left-color:#f85149}
.card.WARN{border-left-color:#d29922}.card.INFO{border-left-color:#58a6ff}
.card h3{margin:.1em 0;font-size:1.02em}
.sum{margin:.3em 0;color:#c9d1d9}
.badge{display:inline-block;min-width:3.4em;text-align:center;padding:.05em .5em;border-radius:5px;font-size:.78em;font-weight:700;color:#0b0e13;margin-right:.5em}
.badge.PASS{background:#3fb950}.badge.FAIL{background:#f85149}.badge.WARN{background:#d29922}.badge.INFO{background:#58a6ff}
details{margin-top:.4em}summary{cursor:pointer;color:#9aa4b2}
pre{background:#0b0e13;border:1px solid #262c38;border-radius:6px;padding:.7em;overflow:auto;max-height:340px;white-space:pre-wrap;word-break:break-all}
footer{color:#6b7280;font-size:.82em;padding:1em 1.6em}
</style></head><body>
<header>
  <h1>WordPress IOC report</h1>
  <div class=meta>host <b>$HOST</b> &middot; webroot <code>$WEBROOT</code> &middot; WP <b>${WPVER:-unknown}</b>
   &middot; access log <code>${ACCESS_LOG:-none}</code> &middot; generated $NOW</div>
</header>
<div class=tiles>
  <div class="tile PASS"><b>$PASS</b>pass</div>
  <div class="tile FAIL"><b>$FAIL</b>fail</div>
  <div class="tile WARN"><b>$WARN</b>warn</div>
  <div class="tile INFO"><b>$INFO</b>info</div>
  <div class="tile"><b>$TOTAL</b>checks</div>
</div>
<main>
HTML
cat "$BODY"
cat <<HTML
</main>
<footer>wp_ioc_scan.sh &middot; read-only IOC sweep &middot; FAIL = investigate now, WARN = review, INFO = context.
Not a substitute for full forensic imaging on a confirmed compromise.</footer>
</body></html>
HTML
} > "$OUT"

echo "[*] report written: $OUT"
echo "    PASS=$PASS FAIL=$FAIL WARN=$WARN INFO=$INFO (of $TOTAL checks)"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
