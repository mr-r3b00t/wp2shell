#!/usr/bin/env python3
"""
hunt_logs.py — DFIR log hunt for the WP batch/v1 route-confusion SQLi (wp2shell).

Scans web-server access logs (Apache/Nginx combined or common), optionally with a
%D/%T response-time field, plus any full-capture / mod_security audit text that
includes request bodies. Flags:

  * requests to the batch/v1 endpoint (both permalink styles)
  * author_exclude smuggle parameter and SQL tokens (in URI or body text)
  * time-based-blind timing clusters (repeated ~N-second responses to one IP)
  * post-exploitation: plugin upload + new plugin-path shell access

Usage:
  ./hunt_logs.py access.log [more.log ...]
  cat modsec_audit.log | ./hunt_logs.py -           # read body-bearing text on stdin
  ./hunt_logs.py access.log --sleep-buckets         # emphasise timing analysis
"""
import argparse, re, sys, collections

BATCH   = re.compile(r'(?:/wp-json/batch/v1|rest_route=/?batch/v1)', re.I)
SMUGGLE = re.compile(r'author_exclude', re.I)
SQLI    = re.compile(r'(SLEEP\(|BENCHMARK\(|--\s|-{2}\+-|%2D%2D|\)\s*(?:OR|AND)\b|'
                     r'%29(?:\+|%20)(?:OR|AND)|information_schema|wp_users)', re.I)
PRIMER  = re.compile(r'///')
UPLOAD  = re.compile(r'/wp-admin/update\.php.*action=upload-plugin', re.I)
# Webshell access, three vectors TAs use:
SHELL_PLUGIN = re.compile(r'/wp-content/plugins/[^/\s]+/[^/\s]+\.php\?.*[?&][tc]=', re.I)
SHELL_UPLOAD = re.compile(r'/wp-content/uploads/\S*\.php', re.I)  # PHP in uploads = never legit
SHELL_PARAM  = re.compile(r'[?&](cmd|exec|shell|shell_exec|passthru|system|'
                          r'wp_debug_exec|backdoor)=', re.I)

# Common/combined access line, tolerant; captures ip, request, status, and a
# trailing numeric that may be bytes or response time.
LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"[^"]*"\s+"[^"]*")?(?:\s+(?P<extra>[\d.]+))?')


def scan(streams, sleep_buckets):
    findings = []
    timings  = collections.defaultdict(list)   # ip -> [response_time,...]
    for name, fh in streams:
        for n, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            m = LINE.match(line)
            ip  = m.group("ip") if m else "-"
            req = m.group("req") if m else line
            reason = []
            if BATCH.search(line):
                reason.append("batch/v1")
                if SMUGGLE.search(line): reason.append("author_exclude")
                if SQLI.search(line):    reason.append("sqli-token")
                if PRIMER.search(line):  reason.append("desync-primer(///)")
            if UPLOAD.search(line):       reason.append("plugin-upload")
            if SHELL_PLUGIN.search(line): reason.append("webshell-access(plugin)")
            if SHELL_UPLOAD.search(line): reason.append("php-in-uploads")
            if SHELL_PARAM.search(line):  reason.append("exec-param")
            # timing on batch requests
            if m and m.group("extra") and BATCH.search(line):
                try:
                    t = float(m.group("extra"))
                    # %D is microseconds; normalise the obvious case
                    if t > 1000: t = t / 1_000_000
                    timings[ip].append(t)
                except ValueError:
                    pass
            if reason:
                findings.append((name, n, ip, ";".join(sorted(set(reason))), req[:120]))

    print("== indicator hits ==")
    if not findings:
        print("  (none)")
    for name, n, ip, why, req in findings:
        sev = "!!" if ("author_exclude" in why or "sqli-token" in why
                       or "webshell" in why or "php-in-uploads" in why
                       or "exec-param" in why) else " *"
        print(f"[{sev}] {name}:{n} {ip:>15}  {why}\n        {req}")

    if sleep_buckets or any(timings.values()):
        print("\n== batch response-time analysis (time-based-blind signal) ==")
        for ip, ts in sorted(timings.items(), key=lambda kv: -len(kv[1])):
            if not ts:
                continue
            slow = [t for t in ts if t >= 1.5]
            flag = " <== timing cluster" if len(slow) >= 3 else ""
            print(f"  {ip:>15}  n={len(ts):3d}  max={max(ts):.1f}s  "
                  f">=1.5s:{len(slow)}{flag}")

    print(f"\n[i] {len(findings)} indicator lines flagged.")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+", help="log files, or - for stdin")
    ap.add_argument("--sleep-buckets", action="store_true")
    a = ap.parse_args()
    streams = []
    for p in a.logs:
        if p == "-":
            streams.append(("<stdin>", sys.stdin))
        else:
            streams.append((p, open(p, "r", encoding="utf-8", errors="replace")))
    scan(streams, a.sleep_buckets)


if __name__ == "__main__":
    main()
