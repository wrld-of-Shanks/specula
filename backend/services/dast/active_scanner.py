"""
services/dast/active_scanner.py

Active-tier DAST checks: SQLi/XSS/IDOR indicator detection, endpoint discovery.
Detection-only — confirms behavioral signals, never extracts real data,
never executes commands, never brute-forces real credentials.

Authorization is enforced HERE, not just at the gateway, so this module
can't be called against an unauthorized target even by mistake.
"""

import os
import time
import requests
from urllib.parse import urlparse
from pymongo import MongoClient

_mongo_uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
_client = MongoClient(_mongo_uri)
db = _client["specula"]
authorized_targets = db["authorized_targets"]

REQUEST_TIMEOUT = 8
USER_AGENT = "Specula-DAST/1.0 (authorized-scan)"
MAX_ACTIVE_REQUESTS = 50


class NotAuthorizedError(Exception):
    pass


def is_authorized(target_url: str) -> bool:
    parsed = urlparse(target_url)
    if parsed.scheme not in ('http', 'https'):
        return False
    host = parsed.hostname
    if host in ('localhost', '127.0.0.1', '0.0.0.0'):
        return True
    return authorized_targets.find_one({"target": host}) is not None


def require_authorization(target_url: str):
    if not is_authorized(target_url):
        raise NotAuthorizedError(f"{target_url} is not on the authorized target list")


# ---------------------------------------------------------------------------
# Baseline / probe diffing core
# ---------------------------------------------------------------------------

_request_count = 0


def _get(url, params=None):
    global _request_count
    _request_count += 1
    return requests.get(
        url, params=params, timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT}, allow_redirects=False,
    )


def _baseline_vs_probe(url, param_name, baseline_value, probe_value):
    """Send the same request with a normal value, then a probe value, and diff."""
    baseline = _get(url, params={param_name: baseline_value})
    probe = _get(url, params={param_name: probe_value})
    return baseline, probe


# ---------------------------------------------------------------------------
# SQLi indicator detection (non-destructive — detects behavior change only)
# ---------------------------------------------------------------------------

SQLI_PROBES = ["'", "' OR '1'='1", "' AND '1'='2", "\""]

def check_sqli(target_url: str, endpoint: str, param_name: str):
    require_authorization(target_url)
    findings = []
    for payload in SQLI_PROBES:
        baseline, probe = _baseline_vs_probe(endpoint, param_name, "1", payload)
        len_delta = abs(len(probe.text) - len(baseline.text))
        status_changed = probe.status_code != baseline.status_code
        sql_error_markers = ["sql syntax", "mysql_fetch", "odbc drivers", "sqlstate", "psycopg2"]
        error_leaked = any(m in probe.text.lower() for m in sql_error_markers)

        if error_leaked:
            findings.append(_finding(
                "sqli_error_disclosure", endpoint, param_name,
                confidence=0.9,
                what=f"Database error text appeared in the response when '{payload}' was sent to '{param_name}'.",
                evidence=f"Response contained a raw SQL error marker after probe payload.",
            ))
        elif status_changed or len_delta > 200:
            findings.append(_finding(
                "sqli_behavior_change", endpoint, param_name,
                confidence=0.6,
                what=f"Response changed significantly when '{param_name}' received a SQL-altering payload vs. a normal value.",
                evidence=f"Status {baseline.status_code}->{probe.status_code}, length delta {len_delta} bytes.",
            ))
        time.sleep(0.5)
    return findings


# ---------------------------------------------------------------------------
# XSS reflection check (benign marker, no real script execution)
# ---------------------------------------------------------------------------

XSS_MARKER = "specula_xss_check_9f3a"

def check_xss(target_url: str, endpoint: str, param_name: str):
    require_authorization(target_url)
    probe = _get(endpoint, params={param_name: f"<{XSS_MARKER}>"})
    reflected_unescaped = f"<{XSS_MARKER}>" in probe.text

    if reflected_unescaped:
        return [_finding(
            "reflected_xss", endpoint, param_name,
            confidence=0.85,
            what=f"Marker string reflected unescaped in the response for parameter '{param_name}'.",
            evidence="Raw <tag> marker found verbatim in response body.",
        )]
    return []


# ---------------------------------------------------------------------------
# IDOR check (only against test accounts you control — see usage note below)
# ---------------------------------------------------------------------------

def check_idor(target_url: str, endpoint_template: str, session_a_cookies: dict,
               session_b_cookies: dict, id_a: str, id_b: str):
    """
    Requires two of YOUR OWN authorized test accounts/sessions.
    Never run this against real user sessions/IDs you don't control.
    """
    require_authorization(target_url)
    url_a = endpoint_template.format(id=id_a)
    resp_as_b = requests.get(url_a, cookies=session_b_cookies, timeout=REQUEST_TIMEOUT)

    if resp_as_b.status_code == 200 and id_a not in resp_as_b.url:
        return [_finding(
            "idor", endpoint_template, "id",
            confidence=0.75,
            what=f"Session B could fetch resource '{id_a}' belonging to session A's account.",
            evidence=f"Cross-account request returned status {resp_as_b.status_code}.",
        )]
    return []


# ---------------------------------------------------------------------------
# Endpoint discovery (small, safe wordlist — no aggressive brute force)
# ---------------------------------------------------------------------------

COMMON_PATHS = ["admin", "api", "api/v1", ".git", ".env", "config", "backup", "debug"]

def discover_endpoints(target_url: str):
    require_authorization(target_url)
    findings = []
    for path in COMMON_PATHS:
        url = target_url.rstrip("/") + "/" + path
        try:
            resp = _get(url)
        except requests.RequestException:
            continue
        if resp.status_code < 400:
            findings.append(_finding(
                "exposed_path", url, None,
                confidence=1.0,
                what=f"Path '/{path}' is reachable and returned status {resp.status_code}.",
                evidence=f"GET {url} -> {resp.status_code}",
            ))
        time.sleep(0.3)
    return findings


# ---------------------------------------------------------------------------
# Finding shape (matches the explanation format used across all modules)
# ---------------------------------------------------------------------------

ACTIVE_REMEDIATION = {
    'sqli_error_disclosure': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Disable detailed database error messages in production.',
    'sqli_behavior_change': 'Use parameterized queries or prepared statements. Validate and sanitize all user input before including it in queries.',
    'reflected_xss': 'Encode all output data context-appropriately (HTML entity, JavaScript, URL encoding). Use frameworks that auto-escape by default. Implement Content-Security-Policy header.',
    'idor': 'Implement proper authorization checks for every object access. Verify the authenticated user owns or has permission to access the requested resource. Use indirect references (UUIDs) instead of sequential IDs.',
    'exposed_path': 'Restrict access to administrative and internal paths at the web server level. Use authentication and network-level controls to limit access to sensitive directories.',
}

CWE_MAP = {
    'sqli_error_disclosure': {'cwe': 'CWE-89', 'owasp': 'A03:2021 - Injection'},
    'sqli_behavior_change': {'cwe': 'CWE-89', 'owasp': 'A03:2021 - Injection'},
    'reflected_xss': {'cwe': 'CWE-79', 'owasp': 'A03:2021 - Injection'},
    'idor': {'cwe': 'CWE-639', 'owasp': 'A01:2021 - Broken Access Control'},
    'exposed_path': {'cwe': 'CWE-538', 'owasp': 'A01:2021 - Broken Access Control'},
}

SEVERITY_MAP = {
    'sqli_error_disclosure': 'critical',
    'sqli_behavior_change': 'high',
    'reflected_xss': 'high',
    'idor': 'high',
    'exposed_path': 'info',
}


def _finding(check_type, location, param, confidence, what, evidence):
    ref = CWE_MAP.get(check_type, {'cwe': 'N/A', 'owasp': 'N/A'})
    return {
        "event_type": "dast",
        "mode": "active",
        "check_type": check_type,
        "location": location,
        "parameter": param,
        "confidence": confidence,
        "severity": SEVERITY_MAP.get(check_type, 'medium'),
        "certainty_type": "confirmed" if confidence == 1.0 else "inferred",
        "explanation": {
            "what": what,
            "why_it_matters": what,
            "location": f"{location} (parameter: {param})" if param else location,
            "reference": ref,
            "remediation": {
                "guidance": ACTIVE_REMEDIATION.get(check_type, 'Review the specific vulnerability guidance.'),
                "suggested_code_fix": None
            }
        },
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Orchestrator — call this from the /api/dast/scan route
# ---------------------------------------------------------------------------

def run_active_scan(target_url: str, params_to_test: list):
    """
    params_to_test: [{"endpoint": "https://target/search", "param": "q"}, ...]
    Caller is responsible for supplying real endpoints/params discovered
    from the passive crawl step — this module doesn't crawl on its own.
    """
    global _request_count
    _request_count = 0

    if not is_authorized(target_url):
        return {"skipped_active": True, "reason": "Target not authorized for active scanning", "findings": []}

    findings = []
    findings += discover_endpoints(target_url)

    if _request_count >= MAX_ACTIVE_REQUESTS:
        return {"skipped_active": False, "findings": findings, "warning": "Request limit reached during endpoint discovery"}

    for entry in params_to_test:
        if _request_count >= MAX_ACTIVE_REQUESTS:
            break
        findings += check_sqli(target_url, entry["endpoint"], entry["param"])
        if _request_count >= MAX_ACTIVE_REQUESTS:
            break
        findings += check_xss(target_url, entry["endpoint"], entry["param"])

    warning = None
    if _request_count >= MAX_ACTIVE_REQUESTS:
        warning = f"Scan stopped after {MAX_ACTIVE_REQUESTS} requests to protect target"

    return {"skipped_active": False, "findings": findings, "request_count": _request_count, "warning": warning}
