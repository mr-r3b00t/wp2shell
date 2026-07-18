# wp2shell assurance & DFIR pack

Target: WordPress core `batch/v1` REST **route-confusion → `author__not_in` blind SQLi**
(unauthenticated). Affected **6.9.0–6.9.4, 7.0.0–7.0.1**; patched **6.9.5 / 7.0.2**.
Full chain adds offline hash-crack → authenticated plugin upload → webshell.

## Contents
| File | Purpose |
|------|---------|
| `ATTACKER_PACKETS.md`          | Annotated wire-level view of the exact requests sent |
| `wp2shell_check.py`            | Non-destructive PoC: version / check / prove / dump |
| `IR_RUNBOOK.md`                | Incident-response runbook (detect→preserve→contain→eradicate→recover) |
| `detect/wp2shell.suricata.rules` | IDS/IPS signatures (URI + body) |
| `detect/wp2shell.sigma.yml`    | SIEM detection (webserver/WAF logs) |
| `detect/hunt_logs.py`          | Offline log hunt: SQLi + webshell-access + timing |
| `detect/scan_webshells.sh`     | Filesystem webshell scanner for a WP webroot |
| `detect/webshells.yar`         | YARA rules for PHP webshells / backdoors |

## Webshell detect-and-respond (paired with the lab)
Emulates real post-exploitation, then detects and cleans it. **Lab only.**
```
# plant (3 vectors: malicious plugin, PHP-in-uploads, theme-file infection)
docker compose exec -T wordpress bash /tmp/plant_webshell.sh
# detect on disk
docker compose exec -T wordpress bash /tmp/scan_webshells.sh
yara -r detect/webshells.yar <webroot>/wp-content
# detect in logs (after the shell is used)
docker compose logs --no-log-prefix wordpress | python3 detect/hunt_logs.py -
# respond
docker compose exec -T wordpress bash /tmp/eradicate_webshell.sh
```
Key IR lesson baked in: **opcache serves the malicious bytecode from memory even
after the file is clean on disk** — restoring a file with an older mtime does not
invalidate it. Eradication must bump mtime or restart PHP (`docker compose
restart wordpress`). See `IR_RUNBOOK.md`.

## PoC (authorized targets only) — needs Python 3, stdlib only
```
python3 wp2shell_check.py version http://TARGET             # fingerprint
python3 wp2shell_check.py check   http://TARGET --sleep 3   # confirm (time-based)
python3 wp2shell_check.py prove   http://TARGET --expr "@@version"   # prove read
python3 wp2shell_check.py dump    http://TARGET --rows 1    # extract credentials
python3 wp2shell_check.py check   http://TARGET -A chrome   # spoof UA past a WAF
```
`-A/--user-agent` (all subcommands) takes a preset (`chrome`/`firefox`/`safari`/
`default`) or a literal UA. The default UA identifies the tool; override it only
when a customer WAF blocks the honest one during authorized testing. Note the
DFIR detections here key on the batch/v1 **body/behaviour**, not the UA — so a
spoofed User-Agent does NOT evade them (which is exactly why body-based
signatures matter).
`check` exits 0 if vulnerable, 1 if not. `dump` blind-extracts `wp_users`
(login / password hash / email) — the account-takeover impact proof a pentest
report needs, and it reports the hash format it observed. Note WP 6.8+ stores
`$wp$2y$` **bcrypt** hashes (bcrypt over base64(sha384(pw))), so legacy
`hashcat -m 400` (phpass) does NOT apply to a 7.0.x target — use your hashcat
build's WordPress-bcrypt mode. The plugin-upload webshell is the follow-on and
lives in the public tool.

### Extraction modes (`prove` / `dump`)
- `--mode content` **(default, fast)** — reads the boolean from the mis-dispatched
  posts array in the nested batch response (`responses[1].body.responses[1].body`):
  TRUE keeps posts visible, FALSE hides them. ~1 fast request per test, no sleeps,
  so a full hash extracts in seconds. Auto-calibrates (`1=1` vs `1=2`) before use.
- `--mode time` **(fallback)** — `IF(cond, SLEEP(n), 0)`, verdict from latency.
  Use when responses are cached/uniform, a WAF normalizes bodies, or the site has
  0 published posts (content oracle can't distinguish TRUE/FALSE there).

Both modes use the same binary-search extractor (verified: reconstructs strings
with `$ | . /` and integers from boolean answers alone). `--rows 1` proves impact
with just the admin row.

## DFIR
```
python3 detect/hunt_logs.py /var/log/nginx/access.log
cat modsec_audit.log | python3 detect/hunt_logs.py -      # body-bearing capture
```

### Indicators of compromise / attack
- `POST /wp-json/batch/v1/` or `POST /?rest_route=/batch/v1/` from untrusted IPs
- request body containing `"///"` (desync primer) **and** `author_exclude`
- `author_exclude` values containing `)`, `SLEEP(`, `BENCHMARK(`, `-- -`, `OR`, `AND`
- nested `requests` arrays (a `requests` key inside a sub-request `body`)
- clusters of same-endpoint POSTs with response times in ~N-second multiples
  (time-based blind); many requests + long runtime = extraction in progress
- follow-on: `/wp-login.php` success from the same IP, then
  `POST /wp-admin/update.php?action=upload-plugin`, then GETs to a new
  `/wp-content/plugins/<slug>/<slug>.php?t=...&c=...`

### Triage priority
1. Is the host in the vulnerable range? (`wp2shell_check.py version`)
2. Any batch/v1 traffic with the body/timing IOCs above in logs?
3. If yes → assume `wp_users` hashes exfiltrated: force admin password resets,
   rotate salts (`wp-config.php` keys), audit for rogue plugins/admin users.
4. Patch to 7.0.2 / 6.9.5; stopgap: block `/wp-json/batch/v1` + `rest_route=/batch/v1`
   at the WAF/edge.

## Caveats
- Body-based detection requires a log source that captures request bodies
  (WAF, mod_security audit log, reverse proxy). Stock access logs only see the
  URI — for the pretty-permalink `POST /wp-json/batch/v1/` form the payload is in
  the body and will NOT appear there; rely on IDS body rules or timing analysis.
- The `rest_route=/batch/v1` form still shows the endpoint (and, for GET-smuggled
  variants, the query string) in access logs.
- Characterised from the 7.0.1→7.0.2 code delta + public PoC; cross-check the
  assigned CVE/CVSS before finalising the report.
```
