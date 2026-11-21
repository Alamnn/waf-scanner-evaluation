#!/bin/bash
set -e
systemctl stop vuln-backend 2>/dev/null || true
cat <<'SVC' > /etc/systemd/system/vuln-backend.service
[Unit]
Description=Vulnerable Backend for WAF Evaluation

[Service]
ExecStart=/usr/bin/python3 /tmp/vuln_backend.py
Restart=always

[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload
systemctl enable --now vuln-backend
sleep 1

a2enmod proxy proxy_http security2 headers >/dev/null 2>&1 || true
grep -q 'Listen 8080' /etc/apache2/ports.conf || echo 'Listen 8080' >> /etc/apache2/ports.conf
cat <<'VHOST' > /etc/apache2/sites-available/waf-eval.conf
<VirtualHost *:8080>
    ServerName localhost
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8081/
    ProxyPassReverse / http://127.0.0.1:8081/
    ErrorLog /var/log/apache2/waf_error.log
    CustomLog /var/log/apache2/waf_access.log combined
</VirtualHost>
VHOST
a2ensite waf-eval.conf >/dev/null 2>&1 || true

# Restore clean CRS exclusion file first
git -C /etc/modsecurity/crs checkout -- . 2>/dev/null || true
echo "# clean" > /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf

# STAGE 1: Default ModSecurity config (DetectionOnly)
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
systemctl restart apache2
python3 /tmp/run_eval.py http://127.0.0.1:8080 "1_Default_DetectionOnly" > /tmp/stage1.json

# STAGE 2: Untuned OWASP CRS Blocking (Paranoia Level 1)
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
systemctl restart apache2
python3 /tmp/run_eval.py http://127.0.0.1:8080 "2_Untuned_CRS_PL1_Blocking" > /tmp/stage2.json

# STAGE 3: Hardened + Tuned OWASP CRS (Paranoia Level 2 + FP exclusion for /note + custom SSRF rule)
cp /tmp/hardened_tuning.conf /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
systemctl restart apache2
python3 /tmp/run_eval.py http://127.0.0.1:8080 "3_Hardened_Tuned_CRS_PL2" > /tmp/stage3.json

# Run open-source scanners (sqlmap + nikto) against the Hardened WAF
sqlmap -u "http://127.0.0.1:8080/user?id=1" --batch --level=1 --risk=1 --timeout=4 --retries=0 > /tmp/sqlmap_hardened.txt 2>&1 || true
nikto -h http://127.0.0.1:8080 -maxtime 10s > /tmp/nikto_hardened.txt 2>&1 || true
grep -i "ModSecurity: Access denied" /var/log/apache2/waf_error.log | tail -15 > /tmp/modsec_audit_tail.txt || true
echo "WAF_EVAL_DONE"
