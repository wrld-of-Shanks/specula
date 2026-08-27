"""
DAST Evaluation Harness for HORUS
Runs HORUS DAST and OWASP ZAP against known-vulnerable targets,
compares against labeled ground truth, reports precision/recall/F1.

Targets:
  - DVWA (Damn Vulnerable Web Application)
  - OWASP Juice Shop
  - OWASP WebGoat

Usage:
  python scripts/evaluate_dast.py [--horus-only] [--zap-only] [--target dvwa|juice_shop|webgoat|all]
"""

import os
import sys
import json
import time
import subprocess
import requests
import argparse
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, 'scripts', 'dast_eval_results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# Service endpoints. Overridable so the harness deterministically targets the
# containerized DAST (OrbStack forwards it on IPv6 ::1:5003). If a stale native
# `python app.py` is also bound to 127.0.0.1:5003, plain "localhost" routing is
# nondeterministic AND the native process cannot resolve host.docker.internal,
# which silently produces zero findings. Use http://[::1]:5003 to force the
# container regardless of other listeners.
HORUS_BASE_URL = os.environ.get("HORUS_BASE_URL", "http://localhost:5003")

# Port overrides for target apps (defaults match the original Jul 26 eval run).
WEBGOAT_PORT = os.environ.get("WEBGOAT_PORT", "8082")
BWAPP_PORT = os.environ.get("BWAPP_PORT", "4281")
MUTILLIDAE_PORT = os.environ.get("MUTILLIDAE_PORT", "4282")

# Used by the fail-loud startup probe to verify the DAST service can actually
# resolve/reach host.docker.internal targets before a run starts.
HORUS_PROBE_URL = os.environ.get("HORUS_PROBE_URL", "http://host.docker.internal:4280")

# ─── Ground Truth Definitions ───────────────────────────────────────────────
# Each target has a list of TRUE vulnerabilities that a perfect scanner should find.
# check_type maps to HORUS's finding vocabulary.
# zap_alert maps to ZAP's alert names.

GROUND_TRUTH = {
    "dvwa": {
        "name": "DVWA (Damn Vulnerable Web Application)",
        "base_url": "http://host.docker.internal:4280",
        "description": "Deliberately vulnerable PHP/MySQL web app with known vulns at every level.",
        "vulnerabilities": [
            # --- Verified via raw HTTP headers (curl -sI) ---
            {"id": "gt_dvwa_01", "check_type": "missing_csp", "category": "header", "endpoint": "/", "description": "No Content-Security-Policy header (confirmed: header absent in response)"},
            {"id": "gt_dvwa_02", "check_type": "missing_xfo", "category": "header", "endpoint": "/", "description": "No X-Frame-Options header (confirmed: header absent in response)"},
            {"id": "gt_dvwa_03", "check_type": "insecure_cookies", "category": "header", "endpoint": "/", "description": "PHPSESSID cookie lacks HttpOnly/Secure/SameSite flags (confirmed: Set-Cookie: PHPSESSID=...; path=/)"},
            {"id": "gt_dvwa_04", "check_type": "server_banner_disclosure", "category": "header", "endpoint": "/", "description": "Apache/2.4.25 (Debian) version leaked via Server header (confirmed: Server: Apache/2.4.25 (Debian))"},
            {"id": "gt_dvwa_05", "check_type": "missing_hsts", "category": "header", "endpoint": "/", "description": "No Strict-Transport-Security header (confirmed: header absent in response)"},
            {"id": "gt_dvwa_06", "check_type": "weak_tls", "category": "config", "endpoint": "/", "description": "HTTP-only deployment, no TLS (confirmed: HTTPS curl returns empty response)"},
            # --- Based on documented CVEs / public knowledge (not verifiable from headers alone) ---
            {"id": "gt_dvwa_07", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/vulnerabilities/sqli/", "description": "SQL Injection on /vulnerabilities/sqli/ id parameter (documented, requires authentication to test)"},
            {"id": "gt_dvwa_08", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/vulnerabilities/sqli_blind/", "description": "SQL Injection on /vulnerabilities/sqli_blind/ id parameter (documented, requires authentication to test)"},
            {"id": "gt_dvwa_09", "check_type": "xss_reflection", "category": "injection", "endpoint": "/vulnerabilities/xss_r/", "description": "Reflected XSS on /vulnerabilities/xss_r/ name parameter (documented, requires authentication to test)"},
            {"id": "gt_dvwa_10", "check_type": "xss_reflection", "category": "injection", "endpoint": "/vulnerabilities/xss_s/", "description": "Stored XSS on /vulnerabilities/xss_s/ name/message (documented, requires authentication to test)"},
            {"id": "gt_dvwa_11", "check_type": "error_disclosure", "category": "info", "endpoint": "/vulnerabilities/", "description": "PHP error messages on malformed input (documented)"},
            # --- Added for the 5-target corpus (2026-07-31); all interaction-based ---
            {"id": "gt_dvwa_12", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/login.php", "description": "SQL Injection (login bypass) on /login.php user parameter (documented)", "verification": "documented"},
            {"id": "gt_dvwa_13", "check_type": "xss_reflection", "category": "injection", "endpoint": "/vulnerabilities/xss_d/", "description": "DOM-based XSS on /vulnerabilities/xss_d/ (documented, requires authentication to test)", "verification": "documented"},
            {"id": "gt_dvwa_14", "check_type": "error_disclosure", "category": "info", "endpoint": "/vulnerabilities/exec/", "description": "PHP error disclosure on malformed input on /vulnerabilities/exec/ (documented, requires authentication to test)", "verification": "documented"},
        ]
    },
    "juice_shop": {
        "name": "OWASP Juice Shop",
        "base_url": "http://host.docker.internal:3999",
        "description": "Modern Node.js/Angular deliberately vulnerable web app with 100+ challenges.",
        "vulnerabilities": [
            # --- Verified via raw HTTP headers (curl -sI) ---
            {"id": "gt_js_01", "check_type": "missing_csp", "category": "header", "endpoint": "/", "description": "No Content-Security-Policy header (confirmed: header absent in response)"},
            {"id": "gt_js_02", "check_type": "missing_hsts", "category": "header", "endpoint": "/", "description": "No Strict-Transport-Security header (confirmed: header absent in response)"},
            {"id": "gt_js_03", "check_type": "weak_tls", "category": "config", "endpoint": "/", "description": "HTTP-only deployment, no TLS (confirmed: HTTPS curl returns empty response)"},
            {"id": "gt_js_04", "check_type": "exposed_path", "category": "info", "endpoint": "/robots.txt", "description": "/robots.txt reveals /ftp directory (confirmed: curl http://localhost:3999/robots.txt returns Disallow: /ftp)"},
            # --- Based on documented CVEs / public knowledge (not verifiable from headers alone) ---
            {"id": "gt_js_05", "check_type": "xss_reflection", "category": "injection", "endpoint": "/rest/products/search", "description": "Reflected XSS on /rest/products/search q parameter (documented)"},
            {"id": "gt_js_06", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/rest/products/search", "description": "SQL Injection on /rest/products/search (SQLite backend, documented)"},
            {"id": "gt_js_07", "check_type": "idor_indicator", "category": "access_control", "endpoint": "/api/Feedbacks/", "description": "IDOR on /api/Feedbacks/{id} and /api/Products/{id} (documented)"},
            {"id": "gt_js_08", "check_type": "exposed_path", "category": "info", "endpoint": "/api/", "description": "/api/ endpoint discoverable (documented)"},
            {"id": "gt_js_09", "check_type": "error_disclosure", "category": "info", "endpoint": "/rest/", "description": "Error messages leak stack traces on malformed input (documented)"},
            # --- Added for the 5-target corpus (2026-07-31); all interaction-based ---
            {"id": "gt_js_10", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/rest/products/reviews", "description": "SQL Injection on /rest/products/reviews id parameter (documented)", "verification": "documented"},
            {"id": "gt_js_11", "check_type": "xss_reflection", "category": "injection", "endpoint": "/api/Feedbacks", "description": "Stored XSS via /api/Feedbacks comment field (documented)", "verification": "documented"},
            {"id": "gt_js_12", "check_type": "idor_indicator", "category": "access_control", "endpoint": "/rest/basket/", "description": "IDOR on /rest/basket/{id} (documented)", "verification": "documented"},
            {"id": "gt_js_13", "check_type": "exposed_path", "category": "info", "endpoint": "/ftp/", "description": "/ftp/ directory listing accessible (documented)", "verification": "documented"},
            {"id": "gt_js_14", "check_type": "error_disclosure", "category": "info", "endpoint": "/rest/admin/login", "description": "Error disclosure on malformed /rest/admin/login requests (documented)", "verification": "documented"},
            {"id": "gt_js_15", "check_type": "xss_reflection", "category": "injection", "endpoint": "/rest/products/search", "description": "Reflected XSS via POST on /rest/products/search q parameter (documented)", "verification": "documented"},
        ]
        # NOTE: missing_xfo removed — X-Frame-Options: SAMEORIGIN is present (verified via curl -sI)
        # NOTE: server_banner_disclosure removed — no Server header in response (verified via curl -sI)
        # NOTE: exposed_metadata removed — no X-Powered-By header in response (verified via curl -sI)
        # NOTE: insecure_cookies removed — Juice Shop uses JWT tokens, not session cookies (not applicable)
    },
    "webgoat": {
        "name": "OWASP WebGoat",
        "base_url": f"http://host.docker.internal:{WEBGOAT_PORT}/WebGoat",
        "description": "Java-based intentionally insecure application for teaching web security.",
        "vulnerabilities": [
            # --- Verified via raw HTTP headers (curl -sI) ---
            {"id": "gt_wg_01", "check_type": "missing_csp", "category": "header", "endpoint": "/", "description": "No Content-Security-Policy header (confirmed: header absent in response)"},
            {"id": "gt_wg_02", "check_type": "missing_xfo", "category": "header", "endpoint": "/", "description": "No X-Frame-Options header (confirmed: header absent in response)"},
            {"id": "gt_wg_03", "check_type": "missing_hsts", "category": "header", "endpoint": "/", "description": "No Strict-Transport-Security header (confirmed: header absent in response)"},
            {"id": "gt_wg_04", "check_type": "weak_tls", "category": "config", "endpoint": "/", "description": "HTTP-only deployment, no TLS (confirmed: HTTPS curl returns empty response)"},
            # --- Based on documented CVEs / public knowledge (not verifiable from headers alone) ---
            {"id": "gt_wg_05", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/WebGoat/attack", "description": "SQL Injection in Lesson 13 (documented, requires authentication to test)"},
            {"id": "gt_wg_06", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/WebGoat/attack", "description": "SQL Injection in Query Injection lesson (documented, requires authentication to test)"},
            {"id": "gt_wg_07", "check_type": "xss_reflection", "category": "injection", "endpoint": "/WebGoat/attack", "description": "Reflected XSS in various input reflection lessons (documented, requires authentication to test)"},
            {"id": "gt_wg_08", "check_type": "xss_reflection", "category": "injection", "endpoint": "/WebGoat/attack", "description": "Stored XSS in stored XSS lesson (documented, requires authentication to test)"},
            {"id": "gt_wg_09", "check_type": "idor_indicator", "category": "access_control", "endpoint": "/WebGoat/attack", "description": "IDOR on profile/user endpoints (documented, requires authentication to test)"},
            {"id": "gt_wg_10", "check_type": "error_disclosure", "category": "info", "endpoint": "/WebGoat/attack", "description": "Java stack traces on malformed input (documented)"},
            # --- Added for the 5-target corpus (2026-07-31); all interaction-based ---
            {"id": "gt_wg_11", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/WebGoat/attack", "description": "SQL Injection in Numeric SQL Injection lesson (documented, requires authentication to test)", "verification": "documented"},
            {"id": "gt_wg_12", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/WebGoat/attack", "description": "SQL Injection in SQL Injection Mitigation lesson (documented, requires authentication to test)", "verification": "documented"},
            {"id": "gt_wg_13", "check_type": "xss_reflection", "category": "injection", "endpoint": "/WebGoat/attack", "description": "Reflected XSS in XSS lessons on the post-lesson input reflection (documented, requires authentication to test)", "verification": "documented"},
            {"id": "gt_wg_14", "check_type": "idor_indicator", "category": "access_control", "endpoint": "/WebGoat/attack", "description": "IDOR in Insecure Direct Object References lesson (documented, requires authentication to test)", "verification": "documented"},
            {"id": "gt_wg_15", "check_type": "error_disclosure", "category": "info", "endpoint": "/WebGoat/attack", "description": "Stack-trace disclosure in Exception Handling lesson (documented, requires authentication to test)", "verification": "documented"},
        ]
        # NOTE: server_banner_disclosure removed — no Server header in response (verified via curl -sI)
        # NOTE: exposed_metadata removed — no X-Powered-By header in response (verified via curl -sI)
        # NOTE: insecure_cookies removed — JSESSIONID cookie set after login, not verifiable without credentials
    },
    "bwapp": {
        "name": "bWAPP (buggy Web Application)",
        "base_url": f"http://host.docker.internal:{BWAPP_PORT}",
        "description": "PHP/MySQL deliberately vulnerable app (100+ bugs) by Malik Mesellem; used as a security-training benchmark.",
        "vulnerabilities": [
            # --- Verified via raw HTTP headers (curl -sI, 2026-07-31) ---
            {"id": "gt_bw_01", "check_type": "missing_csp", "category": "header", "endpoint": "/", "description": "No Content-Security-Policy header (confirmed: header absent on /login.php)", "verification": "header-verified"},
            {"id": "gt_bw_02", "check_type": "missing_xfo", "category": "header", "endpoint": "/", "description": "No X-Frame-Options header (confirmed: header absent on /login.php)", "verification": "header-verified"},
            {"id": "gt_bw_03", "check_type": "missing_hsts", "category": "header", "endpoint": "/", "description": "No Strict-Transport-Security header (confirmed: header absent on /login.php)", "verification": "header-verified"},
            {"id": "gt_bw_04", "check_type": "insecure_cookies", "category": "header", "endpoint": "/", "description": "PHPSESSID cookie lacks HttpOnly/Secure/SameSite flags (confirmed: Set-Cookie: PHPSESSID=...; path=/ on /portal.php)", "verification": "header-verified"},
            {"id": "gt_bw_05", "check_type": "server_banner_disclosure", "category": "header", "endpoint": "/", "description": "Apache/2.4.7 (Ubuntu) version leaked via Server header (confirmed: Server: Apache/2.4.7 (Ubuntu))", "verification": "header-verified"},
            {"id": "gt_bw_06", "check_type": "weak_tls", "category": "config", "endpoint": "/", "description": "HTTP-only deployment, no TLS (confirmed: HTTPS curl returns empty response)", "verification": "header-verified"},
            # --- Based on the published bWAPP bug list (requires authentication to test) ---
            {"id": "gt_bw_07", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/sqli_1.php", "description": "SQL Injection on sqli_1.php id parameter (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_08", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/sqli_2.php", "description": "SQL Injection (login bypass) on sqli_2.php (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_09", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/sqli_4.php", "description": "Blind SQL Injection on sqli_4.php (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_10", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/sqli_8.php", "description": "SQL Injection on sqli_8.php (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_11", "check_type": "xss_reflection", "category": "injection", "endpoint": "/xss_get.php", "description": "Reflected XSS on xss_get.php firstname parameter (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_12", "check_type": "xss_reflection", "category": "injection", "endpoint": "/xss_post.php", "description": "POST-based reflected XSS on xss_post.php (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_13", "check_type": "xss_reflection", "category": "injection", "endpoint": "/xss_stored_1.php", "description": "Stored XSS in guestbook on xss_stored_1.php (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_14", "check_type": "idor_indicator", "category": "access_control", "endpoint": "/idor_1.php", "description": "IDOR on idor_1.php — change any user's credentials by uid (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_15", "check_type": "idor_indicator", "category": "access_control", "endpoint": "/idor_2.php", "description": "IDOR on idor_2.php (bWAPP bug list, documented)", "verification": "documented"},
            {"id": "gt_bw_16", "check_type": "error_disclosure", "category": "info", "endpoint": "/", "description": "PHP error messages on malformed input across bug pages (bWAPP bug list, documented)", "verification": "documented"},
        ]
    },
    "mutillidae": {
        "name": "OWASP Mutillidae II",
        "base_url": f"http://host.docker.internal:{MUTILLIDAE_PORT}",
        "description": "PHP/MySQL deliberately vulnerable app (OWASP Top 10 mapped) maintained by OWASP; web-security training benchmark.",
        "vulnerabilities": [
            # --- Verified via raw HTTP headers (curl -sI, 2026-07-31) ---
            {"id": "gt_mu_01", "check_type": "missing_csp", "category": "header", "endpoint": "/", "description": "No Content-Security-Policy header (confirmed: header absent on /index.php)", "verification": "header-verified"},
            {"id": "gt_mu_02", "check_type": "missing_xfo", "category": "header", "endpoint": "/", "description": "No X-Frame-Options header (confirmed: header absent on /index.php)", "verification": "header-verified"},
            {"id": "gt_mu_03", "check_type": "missing_hsts", "category": "header", "endpoint": "/", "description": "No Strict-Transport-Security header (confirmed: header absent on /index.php)", "verification": "header-verified"},
            {"id": "gt_mu_04", "check_type": "insecure_cookies", "category": "header", "endpoint": "/", "description": "PHPSESSID and showhints cookies lack HttpOnly/Secure/SameSite flags (confirmed: Set-Cookie: PHPSESSID=...; path=/, Set-Cookie: showhints=1)", "verification": "header-verified"},
            {"id": "gt_mu_05", "check_type": "server_banner_disclosure", "category": "header", "endpoint": "/", "description": "Apache/2.4.7 (Ubuntu) version leaked via Server header (confirmed: Server: Apache/2.4.7 (Ubuntu))", "verification": "header-verified"},
            {"id": "gt_mu_06", "check_type": "weak_tls", "category": "config", "endpoint": "/", "description": "HTTP-only deployment, no TLS (confirmed: HTTPS curl returns empty response)", "verification": "header-verified"},
            {"id": "gt_mu_07", "check_type": "exposed_path", "category": "info", "endpoint": "/robots.txt", "description": "/robots.txt discloses passwords/, config.inc, classes/, javascript/ (confirmed via curl)", "verification": "header-verified"},
            # --- Based on Mutillidae's documented OWASP Top 10 mapping (requires authentication to test) ---
            {"id": "gt_mu_08", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/login.php", "description": "SQL Injection on user-info.php login form (documented OWASP mapping)", "verification": "documented"},
            {"id": "gt_mu_09", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/dns-lookup.php", "description": "SQL Injection on dns-lookup.php hostname parameter (documented OWASP mapping)", "verification": "documented"},
            {"id": "gt_mu_10", "check_type": "sqli_indicator", "category": "injection", "endpoint": "/pen-test-tool-lookup.php", "description": "SQL Injection (GET / Search) page (documented OWASP mapping)", "verification": "documented"},
            {"id": "gt_mu_11", "check_type": "xss_reflection", "category": "injection", "endpoint": "/register.php", "description": "Reflected XSS on reflected_xss.php (documented OWASP mapping)", "verification": "documented"},
            {"id": "gt_mu_12", "check_type": "xss_reflection", "category": "injection", "endpoint": "/add-to-your-blog.php", "description": "Stored XSS on xss.php (documented OWASP mapping)", "verification": "documented"},
            {"id": "gt_mu_13", "check_type": "xss_reflection", "category": "injection", "endpoint": "/", "description": "Reflected XSS via Cookie header (documented OWASP mapping)", "verification": "documented"},
            {"id": "gt_mu_14", "check_type": "idor_indicator", "category": "access_control", "endpoint": "/user-info.php", "description": "IDOR on user profile endpoints (documented OWASP A01 broken access control)", "verification": "documented"},
            {"id": "gt_mu_15", "check_type": "idor_indicator", "category": "access_control", "endpoint": "/user-info-xpath.php", "description": "IDOR on password change endpoint (documented OWASP A01 broken access control)", "verification": "documented"},
            {"id": "gt_mu_16", "check_type": "error_disclosure", "category": "info", "endpoint": "/php-errors.php", "description": "Debug error pages leak SQL errors/stack traces on malformed input (documented)", "verification": "documented"},
        ]
    }
}

# Map ZAP plugin IDs to our check_type vocabulary.
# VERIFIED against real ZAP 2.17.0 output from spider + passive scan on DVWA, Juice Shop, WebGoat.
# Previous version of this table had 10+ incorrect mappings (e.g., 10020 mapped to missing_csp
# when it's actually "Missing Anti-clickjacking Header"; 40012 mapped to sqli_indicator when
# it's actually "Cross Site Scripting (Reflected)"). All entries below confirmed against real output.
ZAP_TO_CHECKTYPE = {
    # Passive scan rules — header/config findings
    "10010": "insecure_cookies",      # Cookie No HttpOnly Flag (verified: DVWA)
    "10020": "missing_xfo",           # Missing Anti-clickjacking Header = X-Frame-Options (verified: DVWA, WebGoat)
    "10021": "missing_xcto",          # X-Content-Type-Options Header Missing (verified: DVWA) — no GT match
    "10035": "missing_hsts",          # Strict-Transport-Security Header Not Set
    "10036": "server_banner_disclosure", # Server Leaks Version via "Server" HTTP Response Header (verified: DVWA)
    "10037": "server_banner_disclosure", # Server Leaks Info via X-Powered-By
    "10038": "missing_csp",           # Content Security Policy Header Not Set (verified: all 3 targets)
    "10054": "insecure_cookies",      # Cookie without SameSite Attribute (verified: DVWA)
    "10055": "cors_misconfiguration",  # CORS Misconfiguration
    "10015": "info_disclosure",        # Re-examine Cache-control (verified: ZAP docs) — no GT match
    "10017": "cross_domain_source",    # Cross-domain JavaScript source inclusion
    "10096": "timestamp_disclosure",   # Timestamp Disclosure (verified: Juice Shop)
    "10098": "cross_domain",          # Cross-Domain Misconfiguration (verified: Juice Shop)
    # Passive scan rules — info disclosure
    "10009": "info_disclosure",        # In Page Banner Information Leak (verified: DVWA)
    "10023": "error_disclosure",       # Information Disclosure - Debug Error Messages (verified: DVWA)
    "10024": "info_disclosure",        # Information Disclosure - Sensitive information in URL
    "10025": "info_disclosure",        # Information Disclosure - Suspicious Comments
    "10027": "info_disclosure",        # Information Disclosure - Suspicious Comments (verified: DVWA)
    # Active scan rules — injection
    "40012": "xss_reflection",        # Cross Site Scripting (Reflected) (verified: ZAP docs)
    "40014": "xss_reflection",        # Cross Site Scripting (Persistent) (verified: ZAP docs)
    "40018": "sqli_indicator",        # SQL Injection
    "40019": "sqli_indicator",        # SQL Injection - MySQL
    "40020": "sqli_indicator",        # SQL Injection - Hypersonic
    "40021": "sqli_indicator",        # SQL Injection - Oracle
    "40022": "sqli_indicator",        # SQL Injection - PostgreSQL
    "90020": "remote_os_command",     # Remote OS Command Injection
    "90022": "error_disclosure",      # Application Error Disclosure (verified: ZAP docs)
    "90023": "xml_external",          # XML External Entity Attack
    "90024": "sqli_indicator",        # Generic SQL Injection
    "90025": "xss_reflection",        # Cross Site Scripting (DOM Based)
}


def run_horus_scan(target_url, mode="active"):
    """Run HORUS DAST scan via the DAST service directly."""
    try:
        resp = requests.post(
            f"{HORUS_BASE_URL}/scan",
            json={"target_url": target_url, "mode": mode, "verbose_evidence": True},
            timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        if not data.get("findings") and not data.get("error"):
            print(f"  [HORUS] FAIL-LOUD WARNING: zero findings for {target_url}.")
            print(f"    Possible causes: (1) a stale native DAST process is shadowing the container on"
                  f" {HORUS_BASE_URL} (it cannot resolve host.docker.internal);"
                  f" (2) host.docker.internal does not resolve inside the DAST container;"
                  f" (3) the target is unreachable from inside the container.")
            print(f"    Fix: kill stray `python app.py` processes, re-run with"
                  f" HORUS_BASE_URL=http://[::1]:5003, and verify target containers are up.")
        return data
    except Exception as e:
        print(f"  [HORUS] Error scanning {target_url}: {e}")
        return {"findings": [], "error": str(e)}


def verify_horus_service():
    """Fail-loud pre-flight check: the DAST service must be up and able to reach
    host.docker.internal targets, otherwise every scan silently returns zero findings."""
    try:
        r = requests.get(f"{HORUS_BASE_URL}/health", timeout=5)
        r.raise_for_status()
        print(f"  [HORUS] service {HORUS_BASE_URL}: {r.json().get('status')}")
    except Exception as e:
        print(f"\n  [HORUS] FATAL: DAST service unreachable at {HORUS_BASE_URL}: {e}")
        print("  Is the containerized DAST running? `docker compose ps` should show sentinelai-dast-1 up.")
        sys.exit(1)

    try:
        resp = requests.post(
            f"{HORUS_BASE_URL}/scan",
            json={"target_url": HORUS_PROBE_URL, "mode": "passive", "verbose_evidence": True},
            timeout=60
        )
        resp.raise_for_status()
        data = resp.json()
        n = len(data.get("findings", []))
        if n == 0:
            print(f"\n  [HORUS] FATAL: probe scan of {HORUS_PROBE_URL} returned zero findings.")
            print("  The DAST service cannot resolve/reach host.docker.internal — every target will")
            print("  silently produce zero findings. This is the Jul 29 anomaly. Fixes:")
            print("    1. Kill any stale native `python app.py` shadowing port 5003 (lsof -iTCP:5003).")
            print("    2. Set HORUS_BASE_URL=http://[::1]:5003 to force the container.")
            print("    3. Verify the probe target is up (dvwa-eval container) and reachable from inside")
            print("       the DAST container: docker exec sentinelai-dast-1 python3 -c "
                  '"import requests; print(requests.get(\'http://host.docker.internal:4280\', timeout=5).status_code)"')
            sys.exit(1)
        print(f"  [HORUS] probe scan of {HORUS_PROBE_URL}: {n} findings — host.docker.internal reachable ✓")
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n  [HORUS] FATAL: probe scan failed: {e}")
        sys.exit(1)


def run_zap_baseline(target_url, zap_port=8090):
    """Run ZAP full scan (spider + passive + active) against target and return alerts.
    
    Steps:
    1. Spider the target to discover URLs
    2. Wait for passive scan to complete
    3. Run active scan on discovered URLs
    4. Collect all alerts
    """
    try:
        base = f"http://localhost:{zap_port}"

        # Step 1: Spider
        print(f"    [ZAP] Spidering {target_url}...")
        r = requests.get(f"{base}/JSON/spider/action/scan/",
                         params={"url": target_url, "recurse": "true"}, timeout=10)
        spider_id = r.json().get("scan", "0")
        print(f"    [ZAP] Spider spider_id={spider_id}")
        for i in range(120):
            time.sleep(3)
            s = requests.get(f"{base}/JSON/spider/view/status/",
                             params={"scanId": spider_id}, timeout=10)
            try:
                progress = int(s.json().get("status", "100"))
            except (ValueError, TypeError):
                print(f"    [ZAP] Spider poll {i}: parse failed — raw={s.text[:100]}")
                progress = 100
            if i % 5 == 0 or progress >= 100:
                print(f"    [ZAP] Spider poll {i}: progress={progress}")
            if progress >= 100:
                break
        print(f"    [ZAP] Spider complete")

        # Step 2: Wait for passive scan
        print(f"    [ZAP] Waiting for passive scan...")
        for _ in range(60):
            time.sleep(2)
            r = requests.get(f"{base}/JSON/pscan/action/status/", timeout=10)
            if int(r.json().get("recordsToScan", "0")) == 0:
                break
        print(f"    [ZAP] Passive scan complete")

        # Step 3: Active scan
        print(f"    [ZAP] Running active scan...")
        r = requests.get(f"{base}/JSON/ascan/action/scan/",
                         params={"url": target_url, "recurse": "true", "inScopeOnly": "false"},
                         timeout=10)
        scan_id = r.json().get("scan", "0")
        print(f"    [ZAP] Active scan_id={scan_id}")
        for i in range(600):
            time.sleep(5)
            s = requests.get(f"{base}/JSON/ascan/view/status/",
                             params={"scanId": scan_id}, timeout=10)
            resp_text = s.text
            try:
                progress = int(s.json().get("status", "100"))
            except (ValueError, TypeError):
                print(f"    [ZAP] Poll {i}: progress parse failed — raw={resp_text[:100]}")
                progress = 100
            if i % 4 == 0 or progress >= 100:
                print(f"    [ZAP] Poll {i}: progress={progress}")
            if progress >= 100:
                break
        print(f"    [ZAP] Active scan complete (scan_id={scan_id})")

        # Step 4: Collect all alerts
        # Use host-only URL for baseurl filter (ZAP requires exact prefix match;
        # e.g., "http://localhost:8082/WebGoat" won't match alerts on "/sitemap.xml")
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host_url = f"{parsed.scheme}://{parsed.netloc}"
        r = requests.get(f"{base}/JSON/core/view/alerts/",
                         params={"baseurl": host_url, "start": 0, "count": 2000},
                         timeout=60)
        return r.json().get("alerts", [])
    except Exception as e:
        print(f"  [ZAP] Error: {e}")
        return []


# Raw HORUS JSON schema (verified against all 6 check types × 3 targets):
#   Top level:  check_name (str), certainty_type ("confirmed"), severity ("info"|"medium"|"high")
#   Nested:     explanation.location (URL str), explanation.confidence_note (str, NOT numeric)
#   No numeric confidence field exists — certainty_type is the only confidence signal.
def normalize_finding(finding):
    """Normalize a HORUS finding to a standard dict.
    Schema paths: check_type ← check_name, severity ← severity,
    location ← explanation.location, confidence ← certainty_type mapped to numeric."""
    check_type = finding.get("check_name") or finding.get("check_type")
    certainty = finding.get("certainty_type")
    severity = finding.get("severity")
    location = (finding.get("explanation") or {}).get("location")
    # Binary proxy derived from certainty_type; HORUS's DAST engine has no native
    # numeric confidence output, unlike NIDS/SAST which produce calibrated probabilities.
    return {
        "check_type": check_type or "",
        "confidence": 1.0 if certainty == "confirmed" else (0.5 if certainty else None),
        "severity": severity,
        "location": location,
    }


def normalize_zap_alert(alert):
    """Normalize a ZAP alert to match our vocabulary.
    
    Note: /JSON/core/view/alerts/ returns risk as a string (e.g., "Medium", "Low",
    "Informational") while /JSON/ascan/view/results/ returns it as an int.
    Handle both formats."""
    plugin_id = str(alert.get("pluginId", ""))
    check_type = ZAP_TO_CHECKTYPE.get(plugin_id, f"zap_{plugin_id}")
    risk_raw = alert.get("risk", "High")
    risk_str_to_int = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3}
    if isinstance(risk_raw, int):
        risk = risk_raw
    else:
        risk = risk_str_to_int.get(str(risk_raw).lower(), 2)
    risk_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
    return {
        "check_type": check_type,
        "confidence": 1.0 if risk >= 2 else 0.5,
        "severity": risk_map.get(risk, "medium"),
        "location": alert.get("url", ""),
        "zap_name": alert.get("name", ""),
        "zap_plugin_id": plugin_id,
    }


def compute_metrics(tool_findings, ground_truth, target_name):
    """
    Compute precision, recall, F1 for a tool against ground truth.

    Matching logic:
    - A tool finding MATCHES a ground truth item if:
      - check_type matches (exact or category-level match)
      - At least one finding of that check_type exists in tool output
    """
    gt_by_check = defaultdict(list)
    for v in ground_truth:
        gt_by_check[v["check_type"]].append(v)

    tool_checks = set(f["check_type"] for f in tool_findings)
    gt_checks = set(v["check_type"] for v in ground_truth)

    # True Positives: GT check_types that the tool also found
    tp_checks = tool_checks & gt_checks
    # False Positives: tool found checks not in GT
    fp_checks = tool_checks - gt_checks
    # False Negatives: GT checks the tool missed
    fn_checks = gt_checks - tool_checks

    # Count individual findings
    tp_count = sum(len(gt_by_check[c]) for c in tp_checks)
    fp_count = sum(1 for f in tool_findings if f["check_type"] in fp_checks)
    fn_count = sum(len(gt_by_check[c]) for c in fn_checks)

    # Also count duplicate TPs (tool found same vuln type multiple times)
    for c in tp_checks:
        tool_of_type = [f for f in tool_findings if f["check_type"] == c]
        gt_of_type = gt_by_check[c]
        # Extra tool findings beyond GT count are FPs
        if len(tool_of_type) > len(gt_of_type):
            fp_count += len(tool_of_type) - len(gt_of_type)

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "target": target_name,
        "tp": tp_count,
        "fp": fp_count,
        "fn": fn_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "gt_count": len(ground_truth),
        "tool_finding_count": len(tool_findings),
        "tp_checks": sorted(tp_checks),
        "fp_checks": sorted(fp_checks),
        "fn_checks": sorted(fn_checks),
    }


def normalize_path(url):
    """Reduce a finding URL to a comparable path string (segment-level).
    Strips scheme/host/port/query/fragment, collapses trailing slashes and
    index files, so 'http://host:4280/vulnerabilities/sqli/index.php?id=1'
    becomes '/vulnerabilities/sqli'. Returns '' for empty/unparseable URLs."""
    if not url:
        return ""
    from urllib.parse import urlparse
    try:
        p = urlparse(url).path
    except Exception:
        return ""
    if not p:
        return "/"
    # strip trailing index file / slash
    if p.endswith("/"): p = p[:-1]
    if p.endswith("/index.php"): p = p[:-len("/index.php")]
    if p.endswith("/index.html"): p = p[:-len("/index.html")]
    if p.endswith("/default.asp"): p = p[:-len("/default.asp")]
    if p == "": p = "/"
    return p


def path_prefix(a, b):
    """Segment-wise prefix test: True if path a is a directory-prefix of path b
    (or equal). '/rest/products/search' is NOT a prefix of '/rest/products'."""
    as_ = [s for s in a.split("/") if s]
    bs_ = [s for s in b.split("/") if s]
    return len(as_) <= len(bs_) and all(x == y for x, y in zip(as_, bs_))


def compute_endpoint_metrics(tool_findings, ground_truth, target_name):
    """Per-endpoint matching: the unit is the unique (target, endpoint,
    check_type) triple rather than the check_type.

    - GT unit: (check_type, endpoint); header/config entries use endpoint '/'
      (site-wide — a same-type finding anywhere on the target matches).
    - Tool unit: (check_type, normalized_path) after deduplicating findings
      that share both check_type and path.
    - A GT unit matches a tool unit when check_type matches AND the finding
      path equals/falls under the GT endpoint (segment-wise prefix), or the
      GT endpoint is '/' (site-wide).
    """
    gt_units = set()
    for v in ground_truth:
        ep = v.get("endpoint", "/")
        gt_units.add((v["check_type"], ep))

    tool_units = set()
    for f in tool_findings:
        ct = f["check_type"]
        if not ct:
            continue
        p = normalize_path(f.get("location"))
        tool_units.add((ct, p))

    def unit_matches(gt_unit, tool_unit):
        gct, gep = gt_unit
        tct, tp = tool_unit
        if gct != tct:
            return False
        if gep == "/":
            return True
        if not tp:
            return False
        if tp == "/":
            return False
        return path_prefix(gep, tp) or path_prefix(tp, gep)

    matched_gt = set()
    matched_tool = set()
    for gu in gt_units:
        for tu in tool_units:
            if unit_matches(gu, tu):
                matched_gt.add(gu)
                matched_tool.add(tu)

    tp = len(matched_gt)
    fn = len(gt_units) - tp
    fp = len(tool_units) - len(matched_tool)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    tp_units = sorted(matched_gt)
    fp_units = sorted(tool_units - matched_tool)
    fn_units = sorted(gt_units - matched_gt)
    return {
        "target": target_name,
        "gt_unit_count": len(gt_units),
        "tool_unit_count": len(tool_units),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp_units": [list(u) for u in tp_units],
        "fp_units": [list(u) for u in fp_units],
        "fn_units": [list(u) for u in fn_units],
    }


def evaluate_target(target_key, run_horus=True, run_zap=False):
    """Run evaluation for a single target."""
    gt = GROUND_TRUTH[target_key]
    target_url = gt["base_url"]
    target_name = gt["name"]

    print(f"\n{'='*70}")
    print(f"EVALUATING: {target_name}")
    print(f"URL: {target_url}")
    print(f"Ground truth: {len(gt['vulnerabilities'])} labeled vulnerabilities")
    print(f"{'='*70}")

    # Check target is up (use localhost for host-side check; host.docker.internal for container-side)
    health_url = target_url.replace("host.docker.internal", "localhost")
    try:
        resp = requests.get(health_url, timeout=5)
        print(f"  Target is UP (HTTP {resp.status_code})")
    except Exception as e:
        print(f"\n  [FATAL] Target {target_url} is DOWN: {e}")
        print("  Skipping would silently change the aggregate metrics (the Jul 29 run ambiguity).")
        print("  Start the target (docker start juice-eval; docker run webgoat) and re-run.")
        sys.exit(1)

    results = {}

    # --- HORUS ---
    if run_horus:
        print(f"\n  Running HORUS DAST scan (active mode)...")
        t0 = time.time()
        horus_raw = run_horus_scan(target_url, mode="active")
        horus_time = time.time() - t0
        horus_findings = [normalize_finding(f) for f in horus_raw.get("findings", [])]
        # Deduplicate by check_type (same rationale as ZAP: check_type-level matching)
        seen_types = set()
        deduped = []
        for f in horus_findings:
            if f["check_type"] not in seen_types:
                seen_types.add(f["check_type"])
                deduped.append(f)
        horus_findings = deduped
        print(f"  HORUS: {len(horus_findings)} unique findings (from {len(horus_raw.get('findings', []))} raw) in {horus_time:.1f}s")

        horus_metrics = compute_metrics(horus_findings, gt["vulnerabilities"], target_name)
        horus_metrics["tool"] = "HORUS DAST"
        horus_metrics["scan_time_seconds"] = round(horus_time, 1)
        results["horus"] = {
            "findings": horus_findings,
            "raw": horus_raw,
            "metrics": horus_metrics
        }

        print(f"  HORUS Metrics: P={horus_metrics['precision']:.3f} R={horus_metrics['recall']:.3f} F1={horus_metrics['f1']:.3f}")
        print(f"    TP={horus_metrics['tp']} FP={horus_metrics['fp']} FN={horus_metrics['fn']}")
        print(f"    Matched: {horus_metrics['tp_checks']}")
        print(f"    Missed:  {horus_metrics['fn_checks']}")

    # --- ZAP ---
    if run_zap:
        print(f"\n  Running OWASP ZAP full scan (spider + passive + active)...")
        zap_url = target_url.replace("host.docker.internal", "localhost")
        t0 = time.time()
        zap_raw = run_zap_baseline(zap_url)
        zap_time = time.time() - t0
        zap_findings = [normalize_zap_alert(a) for a in zap_raw]
        # Deduplicate by check_type: ZAP reports the same vulnerability on every URL,
        # but we compare at the check_type level (does the tool detect this vuln TYPE?)
        seen_types = set()
        deduped_findings = []
        for f in zap_findings:
            if f["check_type"] not in seen_types:
                seen_types.add(f["check_type"])
                deduped_findings.append(f)
        zap_findings = deduped_findings
        print(f"  ZAP: {len(zap_findings)} unique findings (from {len(zap_raw)} raw) in {zap_time:.1f}s")
        print(f"  ZAP RAW TIMING: target={target_name}  start={t0:.3f}  end={t0+zap_time:.3f}  elapsed={zap_time:.3f}s")

        zap_metrics = compute_metrics(zap_findings, gt["vulnerabilities"], target_name)
        zap_metrics["tool"] = "OWASP ZAP"
        zap_metrics["scan_time_seconds"] = round(zap_time, 1)
        results["zap"] = {
            "findings": zap_findings,
            "raw": zap_raw,
            "metrics": zap_metrics
        }

        print(f"  ZAP Metrics: P={zap_metrics['precision']:.3f} R={zap_metrics['recall']:.3f} F1={zap_metrics['f1']:.3f}")
        print(f"    TP={zap_metrics['tp']} FP={zap_metrics['fp']} FN={zap_metrics['fn']}")
        print(f"    Matched: {zap_metrics['tp_checks']}")
        print(f"    Missed:  {zap_metrics['fn_checks']}")

    return results


def print_summary(all_results):
    """Print aggregated comparison table."""
    print(f"\n\n{'='*90}")
    print("DAST EVALUATION SUMMARY")
    print(f"{'='*90}")

    horus_all = {"tp": 0, "fp": 0, "fn": 0}
    zap_all = {"tp": 0, "fp": 0, "fn": 0}
    rows = []

    for target_key, results in all_results.items():
        if results is None:
            continue
        gt_count = GROUND_TRUTH[target_key]["vulnerabilities"].__len__()

        if "horus" in results:
            m = results["horus"]["metrics"]
            horus_all["tp"] += m["tp"]
            horus_all["fp"] += m["fp"]
            horus_all["fn"] += m["fn"]
            rows.append(("HORUS", target_key, m))

        if "zap" in results:
            m = results["zap"]["metrics"]
            zap_all["tp"] += m["tp"]
            zap_all["fp"] += m["fp"]
            zap_all["fn"] += m["fn"]
            rows.append(("ZAP", target_key, m))

    # Print per-target table
    print(f"\n{'Tool':<12} {'Target':<20} {'GT':>4} {'Found':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec':>7} {'Recall':>7} {'F1':>7}")
    print("-" * 90)
    for tool, target, m in rows:
        print(f"{tool:<12} {target:<20} {m['gt_count']:>4} {m['tool_finding_count']:>6} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4} {m['precision']:>7.3f} {m['recall']:>7.3f} {m['f1']:>7.3f}")

    # Aggregate
    def agg_metrics(a):
        p = a["tp"] / (a["tp"] + a["fp"]) if (a["tp"] + a["fp"]) > 0 else 0
        r = a["tp"] / (a["tp"] + a["fn"]) if (a["tp"] + a["fn"]) > 0 else 0
        f1 = 2*p*r/(p+r) if (p+r) > 0 else 0
        return round(p, 4), round(r, 4), round(f1, 4)

    hp, hr, hf1 = agg_metrics(horus_all)
    zp, zr, zf1 = agg_metrics(zap_all)

    print("-" * 90)
    print(f"{'HORUS':<12} {'AGGREGATE':<20} {'':>4} {'':>6} {horus_all['tp']:>4} {horus_all['fp']:>4} {horus_all['fn']:>4} {hp:>7.3f} {hr:>7.3f} {hf1:>7.3f}")
    print(f"{'ZAP':<12} {'AGGREGATE':<20} {'':>4} {'':>6} {zap_all['tp']:>4} {zap_all['fp']:>4} {zap_all['fn']:>4} {zp:>7.3f} {zr:>7.3f} {zf1:>7.3f}")
    print()

    return {
        "horus": {"tp": horus_all["tp"], "fp": horus_all["fp"], "fn": horus_all["fn"], "precision": hp, "recall": hr, "f1": hf1},
        "zap": {"tp": zap_all["tp"], "fp": zap_all["fp"], "fn": zap_all["fn"], "precision": zp, "recall": zr, "f1": zf1},
    }


def main():
    parser = argparse.ArgumentParser(description="DAST Evaluation Harness")
    parser.add_argument("--target", choices=["dvwa", "juice_shop", "webgoat", "bwapp", "mutillidae", "all"], default="all")
    parser.add_argument("--horus-only", action="store_true", help="Only run HORUS (skip ZAP)")
    parser.add_argument("--zap-only", action="store_true", help="Only run ZAP (skip HORUS)")
    args = parser.parse_args()

    run_horus = not args.zap_only
    run_zap = not args.horus_only

    if run_horus:
        verify_horus_service()

    targets = list(GROUND_TRUTH.keys()) if args.target == "all" else [args.target]
    all_results = {}

    for t in targets:
        result = evaluate_target(t, run_horus=run_horus, run_zap=run_zap)
        all_results[t] = result

        # Save per-target results
        out_path = os.path.join(RESULTS_DIR, f"{t}_results.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n  Results saved to: {out_path}")

    summary = print_summary(all_results)

    # Save summary
    summary_path = os.path.join(RESULTS_DIR, "evaluation_summary.json")
    with open(summary_path, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "targets": targets,
            "summary": summary,
            "per_target": {
                t: (all_results[t]["horus"]["metrics"] if all_results[t] and "horus" in all_results[t] else None)
                for t in targets
            }
        }, f, indent=2, default=str)

    print(f"\nFull results saved to: {RESULTS_DIR}/")


if __name__ == "__main__":
    main()
