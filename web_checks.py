# web_checks.py
# Simple HTTP/HTTPS hygiene checks

from __future__ import annotations
from typing import Dict, List

import requests
from requests.exceptions import RequestException

# Silence urllib3 InsecureRequestWarning for verify=False on lab targets
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

WANTED_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    # For HTTPS only (added dynamically): "Strict-Transport-Security",
]

def _finding(host: str, port: int, category: str, issue: str, severity: str, rec: str = "") -> Dict:
    return {
        "host": host,
        "port": port,
        "category": category,
        "issue": issue,
        "severity": severity,
        "recommendation": rec,
    }

def check_http(host: str, port: int, scheme: str = "http", timeout: float = 2.5) -> List[Dict]:
    """
    Performs a simple GET and checks for missing security headers, redirects, and basic hygiene.
    For HTTPS, certificate validation is disabled here (verify=False) because TLS findings are handled in tls_checks.
    """
    findings: List[Dict] = []
    url = f"{scheme}://{host}:{port}/"
    verify = False if scheme == "https" else True

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify)
    except RequestException as e:
        issue = f"Web service unreachable: {type(e).__name__}"
        findings.append(_finding(host, port, "web", issue, "Info", "Ensure the service is reachable and not blocking requests."))
        return findings

    # Status codes
    if resp.status_code >= 500:
        findings.append(_finding(host, port, "web", f"HTTP {resp.status_code} (server error)", "Low", "Check server/application logs."))
    elif resp.status_code >= 400:
        findings.append(_finding(host, port, "web", f"HTTP {resp.status_code} (client error)", "Info", "May be expected; verify access paths."))

    # Redirects
    if len(resp.history) > 0:
        first = resp.history[0]
        findings.append(_finding(host, port, "web", f"Redirects {first.status_code} -> {resp.status_code}", "Info", "Ensure redirects enforce HTTPS where applicable."))

    # Header hygiene
    wanted = list(WANTED_HEADERS)
    if scheme == "https":
        wanted.append("Strict-Transport-Security")
    missing = [h for h in wanted if h not in resp.headers]
    if missing:
        sev = "Medium" if scheme == "https" or "Content-Security-Policy" in missing else "Low"
        rec = "Add recommended security headers via server config."
        findings.append(_finding(host, port, "web", f"Missing headers: {', '.join(missing)}", sev, rec))

    # Server banner (informational)
    server = resp.headers.get("Server")
    if server:
        findings.append(_finding(host, port, "web", f"Server banner: {server}", "Info", "Avoid disclosing detailed version info when possible."))

    # Mixed-content heuristic
    if scheme == "https":
        body_sample = resp.text[:5000]
        if "http://" in body_sample:
            findings.append(_finding(host, port, "web", "Page includes http:// references over HTTPS", "Low", "Avoid mixed content; use https:// URLs."))

    return findings