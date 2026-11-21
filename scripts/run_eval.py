#!/usr/bin/env python3
"""Evaluates HTTP attack payloads, bypasses, and false-positive test cases against the WAF."""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

TESTS = [
    {
        "id": "TC-01",
        "category": "SQL Injection (Classic UNION)",
        "kind": "attack",
        "path": "/user?id=" + urllib.parse.quote("1 UNION SELECT 1,username,role,secret FROM users--"),
        "expected_hardened": 403,
    },
    {
        "id": "TC-02",
        "category": "SQL Injection (Comment-Obfuscated Tautology '1'/**/OR/**/'1'='1')",
        "kind": "attack",
        "path": "/user?id=" + urllib.parse.quote("1'/**/OR/**/'1'='1"),
        "expected_hardened": 403,
    },
    {
        "id": "TC-03",
        "category": "Reflected XSS (<script> tag)",
        "kind": "attack",
        "path": "/search?q=" + urllib.parse.quote("<script>alert(document.cookie)</script>"),
        "expected_hardened": 403,
    },
    {
        "id": "TC-04",
        "category": "Path Traversal / LFI (/etc/passwd)",
        "kind": "attack",
        "path": "/read?file=" + urllib.parse.quote("../../../../etc/passwd"),
        "expected_hardened": 403,
    },
    {
        "id": "TC-05",
        "category": "OS Command Injection (; id)",
        "kind": "attack",
        "path": "/ping?host=" + urllib.parse.quote("127.0.0.1; id"),
        "expected_hardened": 403,
    },
    {
        "id": "TC-06",
        "category": "Cloud Metadata SSRF (Detection Gap in CRS PL1)",
        "kind": "attack",
        "path": "/ping?host=" + urllib.parse.quote("http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        "expected_hardened": 403,
    },
    {
        "id": "TC-07",
        "category": "Scanner User-Agent (sqlmap/1.8)",
        "kind": "attack",
        "path": "/user?id=1",
        "headers": {"User-Agent": "sqlmap/1.8.7#stable (https://sqlmap.org)"},
        "expected_hardened": 403,
    },
    {
        "id": "FP-01",
        "category": "False Positive Check: Documentation note containing SQL tutorial ('1' OR '1'='1')",
        "kind": "benign",
        "path": "/note?text=" + urllib.parse.quote("Tutorial example: never allow ' OR '1'='1 -- in raw SQL strings"),
        "expected_hardened": 200,
    },
    {
        "id": "FP-02",
        "category": "False Positive Check: Normal product search",
        "kind": "benign",
        "path": "/search?q=" + urllib.parse.quote("wireless keyboard"),
        "expected_hardened": 200,
    },
]


def run_suite(base_url: str, mode_name: str) -> dict:
    results = []
    for tc in TESTS:
        url = base_url + tc["path"]
        headers = tc.get("headers", {"User-Agent": "Mozilla/5.0 (SecurityEval/1.0)"})
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception:
            code = 0

        blocked = (code == 403)
        results.append({
            "id": tc["id"],
            "category": tc["category"],
            "kind": tc["kind"],
            "status_code": code,
            "blocked": blocked,
        })
    attacks = [r for r in results if r["kind"] == "attack"]
    benign = [r for r in results if r["kind"] == "benign"]
    return {
        "mode": mode_name,
        "attacks_blocked": f"{sum(1 for r in attacks if r['blocked'])}/{len(attacks)}",
        "bypasses_or_gaps": sum(1 for r in attacks if not r["blocked"]),
        "false_positives": sum(1 for r in benign if r["blocked"]),
        "results": results,
    }


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    mode = sys.argv[2] if len(sys.argv) > 2 else "test"
    print(json.dumps(run_suite(base, mode), indent=2))
