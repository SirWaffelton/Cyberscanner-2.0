import re
import warnings
from typing import Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

# Suppress TLS verify=False warning for controlled scanning context
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

DIR_LISTING_PATTERNS = [
    re.compile(r"Index of /", re.I),
    re.compile(r"Directory listing for", re.I),
    re.compile(r"<title>Index of", re.I),
]

# CMS indicators
WP_INDICATORS = [
    ("/wp-login.php", re.compile(r"WordPress|wp-login", re.I)),
    ("/readme.html", re.compile(r"WordPress", re.I)),
    ("/wp-json/", re.compile(r'"name"\s*:\s*".+?"', re.I)),
]
JOOMLA_INDICATORS = [
    ("/administrator/", re.compile(r"joomla", re.I)),
]
DRUPAL_INDICATORS = [
    ("/CHANGELOG.txt", re.compile(r"drupal", re.I)),
    ("/core/CHANGELOG.txt", re.compile(r"drupal", re.I)),
]

# Default credentials heuristics (advisory only)
DEFAULT_CREDS_PATTERNS = [
    {"name": "MikroTik RouterOS", "patterns": [re.compile(r"mikrotik|routeros", re.I)], "creds": "admin (no password) or admin/admin (varies by version)"},
    {"name": "TP-Link Router", "patterns": [re.compile(r"tp-link|tplink|archer", re.I)], "creds": "admin/admin"},
    {"name": "D-Link Router", "patterns": [re.compile(r"d-link|dlink|dir-\d+", re.I)], "creds": "admin/(blank) or admin/admin"},
    {"name": "NETGEAR Router", "patterns": [re.compile(r"netgear", re.I)], "creds": "admin/password"},
    {"name": "Ubiquiti/UniFi", "patterns": [re.compile(r"ubiquiti|unifi", re.I)], "creds": "ubnt/ubnt (older defaults)"},
    {"name": "Apache Tomcat", "patterns": [re.compile(r"apache tomcat", re.I)], "creds": "tomcat/tomcat (manager app; varies)"},
]


def _session(timeout: float, retries: int, user_agent: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})

    # Retry config compatible with both newer and older urllib3
    try:
        retry = Retry(
            total=retries,
            backoff_factor=0.2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
    except TypeError:
        retry = Retry(
            total=retries,
            backoff_factor=0.2,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["GET", "HEAD"],
        )

    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))

    # Bind default timeout to all requests
    _orig_request = s.request

    def _req(method, url, **kw):
        kw.setdefault("timeout", timeout)
        return _orig_request(method, url, **kw)

    s.request = _req
    return s


def _title_from_html(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    return None


def check_security_headers(
    host: str,
    port: int,
    use_https: bool,
    expected_headers: List[str],
    timeout: float,
    retries: int,
    user_agent: str,
) -> List[Dict]:
    findings: List[Dict] = []
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"
    sess = _session(timeout, retries, user_agent)
    try:
        resp = sess.get(url, allow_redirects=True, verify=False)
        present = {k.lower(): v for k, v in resp.headers.items()}
        for h in expected_headers:
            if h.lower() == "strict-transport-security" and not use_https:
                continue
            if h.lower() not in present:
                findings.append({
                    "severity": "LOW",
                    "type": "web.missing_header",
                    "target": f"{host}:{port}",
                    "message": f"Missing security header: {h}",
                    "recommendation": f"Set the {h} header. See OWASP Secure Headers Project for safe defaults."
                })
        if use_https and "strict-transport-security" in present:
            findings.append({
                "severity": "INFO",
                "type": "web.hsts_present",
                "target": f"{host}:{port}",
                "message": "Strict-Transport-Security is present",
                "recommendation": "Ensure max-age is sufficiently long and includeSubDomains if applicable."
            })
    except requests.RequestException as e:
        findings.append({
            "severity": "INFO",
            "type": "web.fetch_error",
            "target": f"{host}:{port}",
            "message": f"Failed to fetch headers: {e}",
            "recommendation": "Check service availability/firewall rules or increase timeouts."
        })
    return findings


def check_https_redirect(host: str, timeout: float, retries: int, user_agent: str) -> List[Dict]:
    findings: List[Dict] = []
    sess = _session(timeout, retries, user_agent)
    try:
        resp = sess.get(f"http://{host}:80/", allow_redirects=False)
        loc = resp.headers.get("Location", "")
        if not (300 <= resp.status_code < 400 and loc.lower().startswith("https://")):
            findings.append({
                "severity": "LOW",
                "type": "web.no_https_redirect",
                "target": f"{host}:80",
                "message": "HTTP does not redirect to HTTPS",
                "recommendation": "Enforce HTTP->HTTPS redirect (301/302) for all requests."
            })
    except requests.RequestException:
        # HTTP not responsive; ignore (other checks will report)
        pass
    return findings


def check_sensitive_paths(
    host: str,
    port: int,
    use_https: bool,
    paths: List[str],
    timeout: float,
    retries: int,
    user_agent: str,
    max_paths: int = 20,
) -> List[Dict]:
    findings: List[Dict] = []
    scheme = "https" if use_https else "http"
    base = f"{scheme}://{host}:{port}"
    sess = _session(timeout, retries, user_agent)

    tested = 0
    for path in paths:
        if tested >= max_paths:
            break
        url = f"{base}{path}"
        try:
            resp = sess.get(url, allow_redirects=True, stream=True, verify=False)
            code = resp.status_code
            ct = resp.headers.get("Content-Type", "")
            chunk = next(resp.iter_content(chunk_size=2048), b"")
            body_snippet = chunk.decode(errors="ignore") if chunk else ""

            if any(p.search(body_snippet) for p in DIR_LISTING_PATTERNS):
                findings.append({
                    "severity": "MEDIUM",
                    "type": "web.directory_listing",
                    "target": f"{host}:{port}",
                    "message": f"Probable directory listing at {path} ({code})",
                    "recommendation": "Disable directory listings or provide an index file. Adjust server configuration."
                })
            elif code in (200, 206):
                pl = path.lower()
                if any(name in pl for name in [".git", ".env", "config.php", ".svn", ".hg", ".ds_store", "backup"]):
                    sev = "HIGH"
                elif any(name in pl for name in ["admin", "console", "manager"]):
                    sev = "MEDIUM"
                else:
                    sev = "LOW"
                findings.append({
                    "severity": sev,
                    "type": "web.sensitive_path",
                    "target": f"{host}:{port}",
                    "message": f"Accessible path {path} returned {code} ({ct})",
                    "recommendation": "Restrict access, remove from web root, or protect with strong authentication."
                })
            elif code in (301, 302, 303, 307, 308) and "login" in (resp.headers.get("Location", "") or "").lower():
                findings.append({
                    "severity": "INFO",
                    "type": "web.admin_redirect",
                    "target": f"{host}:{port}",
                    "message": f"{path} redirects to login/admin",
                    "recommendation": "Ensure strong authentication and rate limiting on admin endpoints."
                })
        except requests.RequestException as e:
            findings.append({
                "severity": "INFO",
                "type": "web.fetch_error",
                "target": f"{host}:{port}",
                "message": f"Fetch error at {path}: {e}",
                "recommendation": "Verify service availability or adjust timeouts."
            })
        finally:
            tested += 1
    return findings


def fingerprint_http(
    host: str,
    port: int,
    use_https: bool,
    timeout: float,
    retries: int,
    user_agent: str,
    max_body_kb: int = 64,
) -> List[Dict]:
    """Collect basic HTTP fingerprints and emit advisories (e.g., Basic over HTTP)."""
    findings: List[Dict] = []
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"
    sess = _session(timeout, retries, user_agent)
    try:
        resp = sess.get(url, allow_redirects=True, verify=False, stream=True)
        chunk = next(resp.iter_content(chunk_size=max_body_kb * 1024), b"")
        body = chunk.decode(errors="ignore") if chunk else ""
        title = _title_from_html(body) or ""
        server = resp.headers.get("Server", "")
        xpb = resp.headers.get("X-Powered-By", "")
        www_auth = resp.headers.get("WWW-Authenticate", "")

        # Basic over HTTP warning
        if not use_https and ("basic" in www_auth.lower()):
            findings.append({
                "severity": "MEDIUM",
                "type": "web.basic_over_http",
                "target": f"{host}:{port}",
                "message": "Endpoint indicates HTTP Basic authentication over plaintext HTTP",
                "recommendation": "Enforce HTTPS and avoid Basic auth or wrap it with TLS-only access."
            })

        # Default creds heuristics (advisory) based on title/server/body snippet
        blob = " ".join([title, server, xpb, body[:2000]])
        for rule in DEFAULT_CREDS_PATTERNS:
            if any(p.search(blob) for p in rule["patterns"]):
                findings.append({
                    "severity": "INFO",
                    "type": "web.default_creds_advisory",
                    "target": f"{host}:{port}",
                    "message": f"Service looks like {rule['name']}; verify defaults are changed",
                    "recommendation": f"Change default credentials; typical default: {rule['creds']}"
                })
                break  # avoid spamming multiple matches

        # Emit a fingerprint record
        findings.append({
            "severity": "INFO",
            "type": "web.fingerprint",
            "target": f"{host}:{port}",
            "message": f"Server={server or 'n/a'}; X-Powered-By={xpb or 'n/a'}; Title={title or 'n/a'}",
            "recommendation": "Harden identified stack; keep software up to date."
        })

    except requests.RequestException as e:
        findings.append({
            "severity": "INFO",
            "type": "web.fetch_error",
            "target": f"{host}:{port}",
            "message": f"Fingerprint fetch failed: {e}",
            "recommendation": "Check service availability or increase timeouts."
        })
    return findings


def check_security_txt(
    host: str,
    port: int,
    use_https: bool,
    timeout: float,
    retries: int,
    user_agent: str,
) -> List[Dict]:
    findings: List[Dict] = []
    scheme = "https" if use_https else "http"
    sess = _session(timeout, retries, user_agent)
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            resp = sess.get(f"{scheme}://{host}:{port}{path}", allow_redirects=True, verify=False)
            if resp.status_code == 200:
                findings.append({
                    "severity": "INFO",
                    "type": "web.security_txt_present",
                    "target": f"{host}:{port}",
                    "message": f"security.txt present at {path}",
                    "recommendation": "Keep contact info and policy up-to-date."
                })
                return findings
        except requests.RequestException:
            pass
    findings.append({
        "severity": "INFO",
        "type": "web.security_txt_missing",
        "target": f"{host}:{port}",
        "message": "No security.txt found",
        "recommendation": "Consider publishing a security.txt with contact/policy details."
    })
    return findings


def check_robots_txt(
    host: str,
    port: int,
    use_https: bool,
    timeout: float,
    retries: int,
    user_agent: str,
) -> List[Dict]:
    findings: List[Dict] = []
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/robots.txt"
    sess = _session(timeout, retries, user_agent)
    try:
        resp = sess.get(url, allow_redirects=True, verify=False)
        if resp.status_code == 200 and resp.text:
            lines = [ln.strip() for ln in resp.text.splitlines()[:500]]
            sensitive_hits = [ln for ln in lines if ln.lower().startswith("disallow:") and any(
                kw in ln.lower() for kw in ["admin", "backup", "private", "secret", "internal"]
            )]
            if sensitive_hits:
                findings.append({
                    "severity": "LOW",
                    "type": "web.robots_sensitive_entries",
                    "target": f"{host}:{port}",
                    "message": f"robots.txt lists potentially sensitive paths: {', '.join(sensitive_hits[:5])}",
                    "recommendation": "Do not rely on robots.txt for access control; restrict or remove sensitive paths."
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "type": "web.robots_present",
                    "target": f"{host}:{port}",
                    "message": "robots.txt present",
                    "recommendation": "Ensure robots.txt aligns with your crawling policy; avoid exposing sensitive paths."
                })
        else:
            findings.append({
                "severity": "INFO",
                "type": "web.robots_missing",
                "target": f"{host}:{port}",
                "message": "robots.txt missing or not accessible",
                "recommendation": "Optional: add robots.txt to control indexing."
            })
    except requests.RequestException:
        findings.append({
            "severity": "INFO",
            "type": "web.fetch_error",
            "target": f"{host}:{port}",
            "message": "Failed to fetch robots.txt",
            "recommendation": "Check availability or increase timeouts."
        })
    return findings


def detect_cms(
    host: str,
    port: int,
    use_https: bool,
    timeout: float,
    retries: int,
    user_agent: str,
) -> List[Dict]:
    findings: List[Dict] = []
    scheme = "https" if use_https else "http"
    base = f"{scheme}://{host}:{port}"
    sess = _session(timeout, retries, user_agent)

    def _probe(path: str, regex: re.Pattern) -> Optional[requests.Response]:
        try:
            resp = sess.get(base + path, allow_redirects=True, verify=False, stream=True)
            chunk = next(resp.iter_content(chunk_size=4096), b"")
            text = chunk.decode(errors="ignore") if chunk else ""
            if regex.search(text) or regex.search(resp.headers.get("Server", "")) or regex.search(resp.headers.get("X-Powered-By", "")):
                return resp
        except requests.RequestException:
            pass
        return None

    # WordPress
    for path, reg in WP_INDICATORS:
        resp = _probe(path, reg)
        if resp:
            # readme version leak
            if path == "/readme.html":
                m = re.search(r"Version\s+([\d\.]+)", resp.text or "", re.I)
                ver = m.group(1) if m else "unknown"
                findings.append({
                    "severity": "LOW",
                    "type": "cms.wordpress_readme",
                    "target": f"{host}:{port}",
                    "message": f"WordPress readme exposed (version {ver})",
                    "recommendation": "Remove readme.html; avoid version leakage."
                })
            findings.append({
                "severity": "INFO",
                "type": "cms.detected",
                "target": f"{host}:{port}",
                "message": "WordPress indicators detected",
                "recommendation": "Keep WordPress core, themes, and plugins updated; restrict /wp-admin."
            })
            # Common endpoints
            try:
                r_xmlrpc = sess.get(base + "/xmlrpc.php", allow_redirects=True, verify=False)
                if r_xmlrpc.status_code in (200, 405):
                    findings.append({
                        "severity": "INFO",
                        "type": "cms.wp_xmlrpc_exposed",
                        "target": f"{host}:{port}",
                        "message": f"xmlrpc.php is reachable (status {r_xmlrpc.status_code})",
                        "recommendation": "If not needed, disable or restrict xmlrpc.php."
                    })
                r_api = sess.get(base + "/wp-json/", allow_redirects=True, verify=False)
                if r_api.status_code == 200:
                    findings.append({
                        "severity": "INFO",
                        "type": "cms.wp_api_exposed",
                        "target": f"{host}:{port}",
                        "message": "WordPress REST API reachable at /wp-json/",
                        "recommendation": "Ensure no sensitive data is exposed via REST endpoints."
                    })
            except requests.RequestException:
                pass
            break

    # Joomla
    for path, reg in JOOMLA_INDICATORS:
        if _probe(path, reg):
            findings.append({
                "severity": "INFO",
                "type": "cms.detected",
                "target": f"{host}:{port}",
                "message": "Joomla indicators detected",
                "recommendation": "Keep Joomla core/extensions updated; secure /administrator/ with MFA and IP allowlists."
            })
            break

    # Drupal
    for path, reg in DRUPAL_INDICATORS:
        resp = _probe(path, reg)
        if resp:
            findings.append({
                "severity": "LOW",
                "type": "cms.drupal_changelog_exposed",
                "target": f"{host}:{port}",
                "message": f"Drupal changelog exposed at {path}",
                "recommendation": "Remove or restrict CHANGELOG files to avoid version leakage."
            })
            findings.append({
                "severity": "INFO",
                "type": "cms.detected",
                "target": f"{host}:{port}",
                "message": "Drupal indicators detected",
                "recommendation": "Keep Drupal core/modules updated and limit access to admin endpoints."
            })
            break

    return findings