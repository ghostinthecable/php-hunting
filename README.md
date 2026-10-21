# phphunt

A small, read-only Python script that scans Apache access and error logs for signs of PHP exploitation attempts.

It changes nothing, it only reads logs and prints a report.

## What it checks

- PHP/Apache worker crashes (segfaults, aborts, heap corruption)
- PHP request-parsing and memory-limit errors
- PHP-CGI argument injection (CVE-2024-4577 style `%AD` / `allow_url_include`)
- `php://`, `data://`, `expect://`, `phar://` wrappers in requests
- phpunit `eval-stdin.php`, Laravel Ignition and similar known PHP RCE paths
- Code in URLs (`<?php`, `base64_decode`, `system(`, `phpinfo` …)
- Path traversal and Xdebug triggers
- Unexpected POST requests, 5xx responses and malformed requests
- Requests per day, so you can spot spikes

## Requirements

Python 3, no extra packages. Reads plain and `.gz` rotated logs.

## Usage

```bash
sudo python3 phphunt.py
```

Options:

```
--logdir DIR            Apache log directory (default: /var/log/apache2)
--trusted-ua SUBSTRING  User-agent of a known client to leave out of the POST and
                        user-agent sections (repeatable)
```

Example:

```bash
sudo python3 phphunt.py --logdir /var/log/httpd --trusted-ua "MyMonitor/"
```

## Notes

- It looks for general signs of PHP attacks, not a signature for any one CVE.
- Access logs don't record POST bodies, so payloads sent in a request body won't show up.
  Crashes and unexpected file changes are the better signal for those.
- The report can contain visitor IPs and your hostnames. Don't publish it.

## License

MIT
