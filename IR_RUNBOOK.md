# Incident response runbook — WordPress wp2shell (batch/v1 SQLi → webshell)

Scope: a WordPress host compromised via the batch/v1 route-confusion SQLi
(6.9.0–6.9.4 / 7.0.0–7.0.1) leading to credential theft and webshell deployment.
Maps to the lab: plant with `lab/plant_webshell.sh`, hunt with `assurance/detect/*`.

## 1. Detect / confirm
- **Server-side:** run the filesystem scanner on the webroot
  `docker compose exec -T wordpress bash /tmp/scan_webshells.sh`
  (or `scan_webshells.sh /path/to/webroot` on a copied-out copy).
  YARA: `yara -r assurance/detect/webshells.yar /webroot/wp-content`.
- **Log-side:** run `hunt_logs.py access.log`. Confirm the kill-chain order:
  1. `POST …/batch/v1` with `///` + `author_exclude` + SQL tokens  → the SQLi
  2. long/`SLEEP`-shaped response times from one IP                → extraction
  3. `POST /wp-admin/update.php?action=upload-plugin`              → shell drop
  4. `webshell-access(plugin)` / `php-in-uploads` / `exec-param`   → RCE
- **Indicators to pivot on:** attacker IP(s), user-agent, the shell path(s),
  the token parameter value, and the timestamp of first shell access.

## 2. Preserve evidence (before changing anything)
- Snapshot the container/volume: `docker commit <wp-container> ir-evidence:<date>`
  and copy the DB volume. Do NOT `down -v`.
- Export logs: `docker compose logs --no-log-prefix wordpress > access_$(date +%F).log`.
- Copy the webroot out read-only: `docker cp <wp-container>:/var/www/html ./ir-webroot`.
- Record hashes of every flagged file (`sha256sum`) for the report and to compare
  against a clean core.

## 3. Contain
- Take the site offline or WAF-block the attacker IP and `/wp-json/batch/v1`
  + `?rest_route=/batch/v1` immediately (stops re-exploitation while you clean).
- Rotate everything the SQLi could read: **all** `wp_users` passwords, and the
  `wp-config.php` salts/keys (invalidates stolen sessions/cookies).
- Disable file editing: `define('DISALLOW_FILE_EDIT', true);`.

## 4. Eradicate
- Remove dropped artifacts and restore infected files:
  `docker compose exec -T wordpress bash /tmp/eradicate_webshell.sh`
  (lab helper — in production, delete flagged files and restore infected ones
  from a known-good backup/VCS, don't trust an attacker-modified file).
- Reinstall core + plugins/themes from official sources; never "clean in place"
  a file you can't diff against a pristine copy.
- Re-run the scanner + YARA until **clean**. Assume persistence you haven't found
  yet: check cron/wp-cron scheduled events, `mu-plugins/`, admin users created
  during the window, and options like `active_plugins`.

## 5. Recover
- Patch to **7.0.2 / 6.9.5** (closes the SQLi vector), then bring the site back.
- Force re-login for all users; monitor for repeat access from the known IOCs.

## 6. Lessons / hardening
- Patch latency was the root cause — track WP core CVEs and auto-update minors.
- Least-privilege DB user, WAF in front of REST, PHP execution disabled in
  `uploads/` (Apache: deny `.php` under uploads), file-integrity monitoring.

## Detection gaps this incident taught (feed back into tooling)
- Casts like `shell_exec((string)$_REQUEST[..])` evade `[^)]*` signatures — the
  scanner uses same-line `.*` matching to catch them.
- Eval-based shells expect PHP payloads; a burst of `500`s on a static-looking
  `.php` (e.g. in uploads) is itself a signal — correlate 5xx + PHP-in-uploads.
