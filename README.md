# phphunt

Two small, read-only scripts for checking an Apache + PHP server for signs of exploitation:

- **`phphunt.py`** scans Apache access and error logs for PHP attack attempts.
- **`postex.sh`** checks the server itself for traces a successful PHP exploit would leave behind.

Neither changes anything. They only read and print a report.

## phphunt.py

### What it checks

- PHP/Apache worker crashes (segfaults, aborts, heap corruption)
- PHP request-parsing and memory-limit errors
- PHP-CGI argument injection (CVE-2024-4577 style `%AD` / `allow_url_include`)
- `php://`, `data://`, `expect://`, `phar://` wrappers in requests
- phpunit `eval-stdin.php`, Laravel Ignition and similar known PHP RCE paths
- Code in URLs (`<?php`, `base64_decode`, `system(`, `phpinfo` …)
- Path traversal and Xdebug triggers
- Unexpected POST requests, 5xx responses and malformed requests
- Requests per day, so you can spot spikes

### Requirements

Python 3, no extra packages. Reads plain and `.gz` rotated logs.

### Usage

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

## postex.sh

### What it checks

- PHP files (`.php`, `.phtml`, `.phar`, `.htaccess`, `.user.ini`) in `/var/www` changed since a set date
- PHP files in `/var/www` owned by `www-data` (writable by the web server)
- PHP files in upload, cache, tmp or image folders
- Web-shell-style code (`eval($_POST[...])`, `eval(base64_decode(...))`, `assert($_GET[...])` …)
- Processes running as `www-data` other than Apache
- Files owned by `www-data` in `/tmp`, `/var/tmp` and `/dev/shm`
- Network connections owned by Apache/`www-data` other than ports 80/443
- A crontab or SSH keys for `www-data`

### Usage

```bash
sudo bash postex.sh
```

Before running it, edit the date in the first check (`-newermt 2026-10-14`) to the start of the
window you want to inspect.

Written for Debian/Ubuntu (`www-data`, `apache2`, webroot `/var/www`). On RHEL-family systems,
change `www-data` to `apache` and `apache2` to `httpd`.

A file changed by a PHP exploit is owned by the web server user, so changed files owned by root
are usually your own deploys.

## Notes

- They look for general signs of PHP attacks, not a signature for any one CVE.
- Access logs don't record POST bodies, so payloads sent in a request body won't show up in
  `phphunt.py`. That is what `postex.sh` is for: crashes, unexpected files and processes.
- The reports can contain visitor IPs, hostnames and file paths. Don't publish them.

## License

MIT
