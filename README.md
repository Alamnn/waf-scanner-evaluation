# WAF & Scanner Evaluation Study (ModSecurity + OWASP CRS v3.3.9)

**Problem:** Deploying a Web Application Firewall (WAF) with out-of-the-box settings leaves critical security and availability gaps:
1. **Default Installation (`SecRuleEngine DetectionOnly`)** logs alerts passively without blocking a single exploit (`0/7` blocked), allowing `sqlmap` and manual attackers to dump database tables.
2. **Untuned Blocking (`SecRuleEngine On`, OWASP CRS Paranoia Level 1)** blocks common SQLi/XSS/LFI payloads (`6/7` blocked) but suffers from both **detection gaps / bypasses** (short chained UNIX command injection `; id` on `/ping` evades CRS `932100`/`932150` heuristics) and **false positives** (`FP-01`: legitimate technical notes containing SQL examples on `/note` are blocked with HTTP `403`, and numeric `Host` headers at Paranoia Level 2 trigger CRS `920350` + `920300`).
3. **Hardened & Tuned Configuration (Paranoia Level 2 + targeted `ctl:ruleRemoveTargetByTag` exclusions + custom virtual-patching rules)** achieves **100% attack blocking (`7/7`)** with **0 false positives (`0/2`)**.

## Lab Architecture (Executed Live on Kali VM `172.16.167.131`)

```mermaid
flowchart LR
    S["Open-Source Scanners & Harness<br/>(sqlmap 1.8.7, Nikto 2.6.1, run_eval.py)"] -->|"HTTP :8080"| WAF["Apache2 + ModSecurity v2.9.13<br/>OWASP CRS v3.3.9 + Custom Tuning"]
    WAF -- "HTTP 403 Forbidden<br/>(Anomaly Score >= 5 or Custom Rule)" --> BLK["Audit Log:<br/>/var/log/apache2/waf_error.log"]
    WAF -- "Allowed Traffic" --> APP["Vulnerable Backend (:8081)<br/>(SQLi /user, XSS /search, LFI /read, RCE /ping, /note)"]
```

## Comparative Evaluation Matrix (Default vs. Untuned CRS vs. Hardened CRS)

| Metric | Stage 1: Default (`DetectionOnly`) | Stage 2: Untuned Blocking (`CRS PL1`) | Stage 3: Hardened & Tuned (`CRS PL2 + Custom`) |
|---|---|---|---|
| **Attacks Blocked** | `0 / 7` (0%) | `6 / 7` (85.7%) | **`7 / 7` (100%)** |
| **Bypasses / Detection Gaps** | `7` | `1` (`TC-05`: `; id` RCE bypass) | **`0`** |
| **False Positives on Benign Traffic** | `0 / 2` | `1 / 2` (`FP-01` blocked with 403) | **`0 / 2` (0%)** |
| **`sqlmap` Exploitation Result** | Database dumped | Blocked (`403 Forbidden`) | **Blocked (`403 Forbidden`)** |

### Per-Test Case Breakdown

| ID | Category / Payload | Kind | Stage 1 (`DetectionOnly`) | Stage 2 (`Untuned PL1`) | Stage 3 (`Hardened PL2`) | Technical Analysis / Rule ID |
|---|---|---|---|---|---|---|
| `TC-01` | Classic UNION SQLi (`1 UNION SELECT 1,username,role,secret FROM users--`) | Attack | `200 OK` (Bypassed) | `403` (Blocked) | **`403` (Blocked)** | Matched CRS `942100` (libinjection SQLi) & `942190` |
| `TC-02` | Comment-Obfuscated SQLi (`1'/**/OR/**/'1'='1`) | Attack | `500` (Reached DB) | `403` (Blocked) | **`403` (Blocked)** | Matched CRS `942100` / PL2 `942200` |
| `TC-03` | Reflected XSS (`<script>alert(document.cookie)</script>`) | Attack | `200 OK` (Bypassed) | `403` (Blocked) | **`403` (Blocked)** | Matched CRS `941100`, `941110`, `941160`, `941180` |
| `TC-04` | Path Traversal / LFI (`../../../../etc/passwd`) | Attack | `200 OK` (Bypassed) | `403` (Blocked) | **`403` (Blocked)** | Matched CRS `930100`, `930110`, `930120` |
| `TC-05` | OS Command Injection (`127.0.0.1; id`) | Attack | `200 OK` (Bypassed) | **`200 OK` (Detection Gap!)** | **`403` (Blocked)** | CRS PL1/PL2 `932100` missed short `; id`; closed by Custom Rule `100030` |
| `TC-06` | Cloud Metadata SSRF (`http://169.254.169.254/latest/meta-data/...`) | Attack | `200 OK` (Bypassed) | `403` (Blocked) | **`403` (Blocked)** | Blocked by Custom Virtual Patch Rule `100020` (`attack-ssrf`) |
| `TC-07` | Automated Scanner Fingerprint (`User-Agent: sqlmap/1.8.7`) | Attack | `200 OK` (Bypassed) | `403` (Blocked) | **`403` (Blocked)** | Matched CRS `913100` (Security Scanner Detected) |
| `FP-01` | Benign Documentation Note containing SQL example (`' OR '1'='1 --` on `/note`) | Benign | `200 OK` | **`403` (False Positive!)** | **`200 OK` (Allowed)** | Tuned via scoped rule `100010`: `ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:text` on `/note` |
| `FP-02` | Benign Product Search (`wireless keyboard` on `/search` with IP `Host` header) | Benign | `200 OK` | `200 OK` | **`200 OK` (Allowed)** | At PL2, CRS `920350` (IP Host) + `920300` (Missing Accept) score 5 (403); tuned via `100005` |

## Visual Proof

### 1. Three-Stage WAF Benchmark & Scanner Comparison
![benchmark](docs/screenshots/01_waf_comparison.png)

### 2. ModSecurity Audit Log & Hardened Rule Configuration
![logs](docs/screenshots/02_modsec_logs_and_rules.png)

## Artifacts & Deliverables
- Hardened ModSecurity & OWASP CRS tuning rules: [waf/hardened_tuning.conf](waf/hardened_tuning.conf)
- Vulnerable backend target: [app/vuln_backend.py](app/vuln_backend.py)
- Automated evaluation harness: [scripts/run_eval.py](scripts/run_eval.py)
- Raw JSON results & scanner logs: [docs/stage1.json](docs/stage1.json), [docs/stage2.json](docs/stage2.json), [docs/stage3.json](docs/stage3.json), [docs/sqlmap_hardened.txt](docs/sqlmap_hardened.txt), [docs/nikto_hardened.txt](docs/nikto_hardened.txt), [docs/modsec_audit_tail.txt](docs/modsec_audit_tail.txt)

## Resume Bullet
*Deployed an intentionally vulnerable web application behind Apache ModSecurity v2.9.13 and OWASP CRS v3.3.9; benchmarked default, untuned PL1, and hardened PL2 configurations against sqlmap, Nikto, and custom exploit payloads—authoring custom SecRules and targeted `ctl:ruleRemoveTargetByTag` exclusions that closed command-injection/SSRF detection gaps (100% block rate) while eliminating false positives.*
