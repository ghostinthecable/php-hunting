# read-only post-exploitation checks
echo "== PHP-executable files changed in webroots since 2026-10-14 (newest first)"
find /var/www -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.htaccess' -o -name '.user.ini' \) -newermt 2026-10-14 -printf '%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n' 2>/dev/null | sort -r | head -40
echo "   total: $(find /var/www -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.htaccess' -o -name '.user.ini' \) -newermt 2026-10-14 2>/dev/null | wc -l)"
echo "== files owned by www-data in webroots (writable by the web user)"
find /var/www -xdev -user www-data -type f \( -name '*.php' -o -name '*.phtml' -o -name '.htaccess' -o -name '.user.ini' \) 2>/dev/null | head -20
echo "== PHP files under upload/cache/tmp-like dirs in webroots"
find /var/www -xdev -type f -name '*.php' \( -path '*upload*' -o -path '*cache*' -o -path '*/tmp/*' -o -path '*/images/*' -o -path '*/img/*' \) 2>/dev/null | head -10
echo "== webshell-ish code in webroot PHP (eval/assert on request input, base64+eval)"
grep -rlE --include='*.php' 'eval\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|str_rot13)|assert\s*\(\s*\$_(GET|POST|REQUEST)|preg_replace\s*\(.*/e[^a-z]|\$_(GET|POST|REQUEST)\[[^]]+\]\s*\(' /var/www 2>/dev/null | head -10
echo "== processes running as www-data (anything other than apache2 is suspicious)"
ps -u www-data -o pid,ppid,lstart,cmd --no-headers 2>/dev/null | grep -v '/usr/sbin/apache2' | head; echo "   apache2 workers: $(ps -u www-data -o cmd --no-headers | grep -c /usr/sbin/apache2)"
echo "== files owned by www-data in /tmp /var/tmp /dev/shm"
find /tmp /var/tmp /dev/shm -xdev -user www-data -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | grep -v '/sess_' | head -15
echo "   (php session files: $(find /tmp /var/lib/php/sessions -user www-data -name 'sess_*' 2>/dev/null | wc -l))"
echo "== outbound/listening sockets owned by www-data"
ss -tunap 2>/dev/null | grep -E 'apache2|www-data' | grep -vE ':(80|443)\s' | grep -vE 'LISTEN' | awk '{print $1,$2,$5,$6}' | sort | uniq -c | sort -rn | head -12
echo "== www-data crontab / authorized_keys"
crontab -u www-data -l 2>&1 | head -3; ls -la /var/www/.ssh 2>/dev/null
