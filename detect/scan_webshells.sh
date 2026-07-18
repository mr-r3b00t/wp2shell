#!/usr/bin/env bash
# Webshell / PHP-backdoor scanner for a WordPress webroot.
# Run inside the container:  docker compose exec -T wordpress bash /tmp/scan_webshells.sh
# or on the host against a copied webroot:  ./scan_webshells.sh /path/to/webroot
#
# Heuristics (each prints WHY it fired so findings are triageable, not opaque):
#   1. PHP files under wp-content/uploads    (uploads must never contain PHP)
#   2. Dangerous sinks fed directly by request input (eval/system/... + $_GET/POST/REQUEST)
#   3. Obfuscation: base64_decode/gzinflate/str_rot13 next to eval/assert
#   4. PHP files newer than WordPress core     (recently dropped/modified)
#   5. Single-file "plugins" that call exec-family functions
set -u
ROOT="${1:-/var/www/html}"
WPINC_VER="$ROOT/wp-includes/version.php"
echo "== webshell scan: $ROOT =="

# Reference mtime = when core was laid down; anything much newer is suspect.
REF=""
[ -f "$WPINC_VER" ] && REF="$WPINC_VER"

# A sink call followed on the SAME LINE by a request superglobal — e.g.
# system($_GET[..]), eval(base64_decode($_POST[..])), shell_exec((string)$_REQUEST[..]).
# Using .* (not [^)]*) so casts/nested calls like (string)$_REQUEST still match —
# TAs add those exact casts to evade [^)]*-style signatures. Same-line keeps it precise.
SINK_INPUT='(eval|assert|system|shell_exec|passthru|proc_open|popen|pcntl_exec|exec)[[:space:]]*\(.*\$_(GET|POST|REQUEST|COOKIE|SERVER)'
# File-write sinks fed by request input — arbitrary write / webshell file editors.
WRITE_INPUT='(file_put_contents|fwrite|fputs)[[:space:]]*\(.*\$_(GET|POST|REQUEST|COOKIE)'
OBF='base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode|hex2bin'

flag () { echo "[!] $1"; echo "      $2"; }

echo "--- (1) PHP in uploads ---"
find "$ROOT/wp-content/uploads" -type f -iname '*.php' 2>/dev/null | while read -r f; do
    flag "$f" "PHP file inside uploads/ — uploads should only hold media"
done

echo "--- (2) request input into a dangerous sink (same-line) ---"
# -I skips binary; --include limits to PHP; -n gives the line for triage.
grep -rnIE --include='*.php' "$SINK_INPUT" "$ROOT/wp-content" 2>/dev/null | while IFS=: read -r f ln rest; do
    flag "$f" "line $ln: request var inside exec/eval call :: $(echo "$rest" | sed 's/^[[:space:]]*//' | cut -c1-60)"
done
grep -rnIE --include='*.php' "$WRITE_INPUT" "$ROOT/wp-content" 2>/dev/null | while IFS=: read -r f ln rest; do
    flag "$f" "line $ln: request var inside file-WRITE sink :: $(echo "$rest" | sed 's/^[[:space:]]*//' | cut -c1-60)"
done

echo "--- (3) obfuscation near eval/assert ---"
grep -rilIE --include='*.php' "$OBF" "$ROOT/wp-content" 2>/dev/null | while read -r f; do
    if grep -qiE 'eval[[:space:]]*\(|assert[[:space:]]*\(|create_function' "$f" 2>/dev/null; then
        flag "$f" "decode/obfuscation + eval — classic packed webshell"
    fi
done

echo "--- (4) PHP newer than core ---"
if [ -n "$REF" ]; then
    find "$ROOT/wp-content" -type f -iname '*.php' -newer "$REF" 2>/dev/null | while read -r f; do
        flag "$f" "modified after core install ($(date -r "$f" '+%Y-%m-%d %H:%M'))"
    done
fi

echo "--- (5) infected legit files (marker/comment tells) ---"
# -I skips binary (fonts/images won't false-positive); text files only.
grep -rilIE --include='*.php' --include='*.inc' '__LABSHELL|c99shell|r57shell|FilesMan|b374k|weevely|WSOsh' "$ROOT/wp-content" 2>/dev/null | while read -r f; do
    flag "$f" "known-webshell / infection marker present"
done

echo "== scan complete =="
