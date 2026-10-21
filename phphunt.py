#!/usr/bin/env python3
"""Read-only hunt for PHP exploitation signs in Apache access + error logs.
Prints counts and samples only; writes nothing.

Usage: phphunt.py [--logdir /var/log/apache2] [--trusted-ua SUBSTRING ...]
  --trusted-ua  user-agent substring of a known client (repeatable); its POSTs are
                left out of the "unexpected POSTs" and "PHP user agents" sections."""
import argparse, glob, gzip, re, sys
from collections import Counter, defaultdict

ap = argparse.ArgumentParser(description='Read-only hunt for PHP exploitation signs in Apache logs.')
ap.add_argument('--logdir', default='/var/log/apache2', help='Apache log directory (default: %(default)s)')
ap.add_argument('--trusted-ua', action='append', default=[], metavar='SUBSTRING',
                help='user-agent substring of a known client; repeatable')
args = ap.parse_args()

LOGDIR = args.logdir
TRUSTED_UA = args.trusted_ua
SAMPLES = 6

def trusted(ua):
    return any(t in ua for t in TRUSTED_UA)

def lines(path):
    op = gzip.open if path.endswith('.gz') else open
    try:
        with op(path, 'rt', errors='replace') as f:
            yield from f
    except OSError as e:
        print(f'  !! cannot read {path}: {e}')

access = sorted(p for p in glob.glob(f'{LOGDIR}/*access*.log*'))
errors = sorted(p for p in glob.glob(f'{LOGDIR}/*error*.log*'))

# ---------- error logs: crashes and PHP engine errors ----------
CRASH = re.compile(r'exit signal|Segmentation fault|segfault|Aborted|core dump|zend_mm_heap corrupted|heap corrupt|double free|stack smashing|AH00052|AH00051', re.I)
PHPERR = re.compile(r'PHP (Fatal error|Parse error|Warning|Notice|Deprecated|Catchable)[^:]*:\s*(.{0,140})')
ENGINE = re.compile(r'Input variables exceeded|POST Content-Length|Missing boundary|multipart|Request body limit|Allowed memory size|Maximum execution time|Unable to allocate|file created in the system|max_file_uploads|Invalid argument supplied for foreach\(\) in Unknown', re.I)
crash, engine, phperr_by_msg = [], [], Counter()
err_days = Counter()
for p in errors:
    for ln in lines(p):
        m = re.match(r'\[(\w{3}) (\w{3}) (\d{2})', ln)
        day = f'{m.group(2)} {m.group(3)}' if m else '?'
        if CRASH.search(ln): crash.append((p, ln.strip()[:260]))
        if ENGINE.search(ln): engine.append((p, ln.strip()[:260]))
        pm = PHPERR.search(ln)
        if pm:
            msg = re.sub(r'\d+', 'N', pm.group(1) + ': ' + pm.group(2))
            phperr_by_msg[msg] += 1
            err_days[day] += 1

print('=== 1. WORKER CRASHES (segfault/abort/heap corruption) ===')
print(f'  total: {len(crash)}')
for p, l in crash[:20]: print(f'  {p.split("/")[-1]}: {l}')
print('\n=== 2. PHP ENGINE/REQUEST-PARSING ERRORS (multipart, limits, memory) ===')
print(f'  total: {len(engine)}')
for p, l in engine[:15]: print(f'  {p.split("/")[-1]}: {l}')
print('\n=== 3. PHP errors in error logs (top messages, numbers normalised) ===')
for msg, n in phperr_by_msg.most_common(15): print(f'  {n:6d}  {msg}')

# ---------- access logs ----------
REQ = re.compile(r'^(?:(?P<vhost>\S+) )?(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<st>\d{3}) (?P<sz>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
IOC = {
  'php ini injection (allow_url_include/auto_prepend/-d)': re.compile(r'allow_url_include|auto_prepend_file|auto_append_file|%2[dD]d\+|(\?|&)-d[+ %]|\?-[sdn]\b', re.I),
  'soft-hyphen arg injection (CVE-2024-4577 style %AD)': re.compile(r'%[aA][dD]'),
  'php:// / data:// / expect:// / phar:// wrappers': re.compile(r'php(%3A|:)(%2F|/){2}|data(%3A|:)(%2F|/)*text|expect(%3A|:)|phar(%3A|:)', re.I),
  'php-cgi / cgi-bin probing': re.compile(r'/cgi-bin/|php-cgi|php5?\.cgi', re.I),
  'phpunit eval-stdin / known PHP RCE paths': re.compile(r'eval-stdin|invokefunction|call_user_func|_ignition|think\\\\app|vendor/phpunit', re.I),
  'code in URL (system/exec/base64/<?php)': re.compile(r'(<|%3C)\?php|base64_decode|shell_exec|passthru|\bsystem\(|\bexec\(|assert\(|phpinfo|die\(|md5\(', re.I),
  'PHP2Shell / calif / watchtowr UA or path': re.compile(r'php2shell|calif\.io|watchtowr', re.I),
  'path traversal': re.compile(r'\.\./|%2e%2e', re.I),
  'xdebug / php debug triggers': re.compile(r'XDEBUG_SESSION|XDEBUG_TRIGGER|XDEBUG_PROFILE', re.I),
}
ioc_hits = defaultdict(list)
day_tot, day_5xx, day_post = Counter(), Counter(), Counter()
post_paths, s5xx_paths, odd_methods, big = Counter(), Counter(), Counter(), []
ua_counter_php = Counter()
bad_req = []
for p in access:
    for ln in lines(p):
        m = REQ.match(ln)
        if not m:
            continue
        ts, req, st, ua = m['ts'], m['req'], int(m['st']), (m['ua'] or '')
        day = ts.split(':')[0]
        day_tot[day] += 1
        parts = req.split(' ')
        meth = parts[0] if parts else ''
        path = parts[1] if len(parts) > 1 else req
        host = (m['vhost'] or p.split('/')[-1]).split(':')[0]
        if st >= 500:
            day_5xx[day] += 1; s5xx_paths[(host, path.split('?')[0], st)] += 1
        if meth == 'POST':
            day_post[day] += 1
            if not trusted(ua):
                post_paths[(host, path.split('?')[0], st)] += 1
        if meth not in ('GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH'):
            odd_methods[meth[:30]] += 1
            if len(bad_req) < 8: bad_req.append(ln.strip()[:220])
        for name, rx in IOC.items():
            if rx.search(req) or rx.search(ua):
                ioc_hits[name].append((day, m['ip'], st, ln.strip()[:240]))
        if re.search(r'php', ua, re.I) and not trusted(ua):
            ua_counter_php[ua[:90]] += 1

print('\n=== 4. KNOWN PHP-ATTACK PATTERNS IN REQUESTS ===')
for name in IOC:
    hits = ioc_hits.get(name, [])
    ok = sum(1 for h in hits if 200 <= h[2] < 300)
    print(f'  [{len(hits):5d} hits, {ok} answered 2xx] {name}')
    for d, ip, st, l in hits[:SAMPLES]: print(f'        {l}')
    if hits:
        days = Counter(h[0] for h in hits)
        print('        by day: ' + ', '.join(f'{d}={n}' for d, n in sorted(days.items(), key=lambda x: x[0])[-8:]))
        print('        top IPs: ' + ', '.join(f'{ip}={n}' for ip, n in Counter(h[1] for h in hits).most_common(5)))

print('\n=== 5. POST requests from untrusted user agents (host, path, status) ===')
for k, n in post_paths.most_common(25): print(f'  {n:6d}  {k}')
print('\n=== 6. 5xx responses (host, path, status) ===')
for k, n in s5xx_paths.most_common(15): print(f'  {n:6d}  {k}')
print('\n=== 7. Unusual HTTP methods / malformed requests ===')
for k, n in odd_methods.most_common(10): print(f'  {n:6d}  {k!r}')
for l in bad_req: print(f'        {l}')
print('\n=== 8. Untrusted user agents mentioning PHP ===')
for k, n in ua_counter_php.most_common(8): print(f'  {n:6d}  {k}')
print('\n=== 9. Traffic per day (total / POST / 5xx) ===')
import datetime
def dkey(d):
    try: return datetime.datetime.strptime(d, '%d/%b/%Y')
    except ValueError: return datetime.datetime.min
for d in sorted(day_tot, key=dkey)[-16:]:
    print(f'  {d}: {day_tot[d]:7d} / {day_post[d]:6d} / {day_5xx[d]:5d}')
print('\n=== 10. PHP errors per day (error logs) ===')
print('  ' + ', '.join(f'{d}={n}' for d, n in sorted(err_days.items())[-16:]))
