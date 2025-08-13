# tls_checks.py
# Basic TLS checks: cert validity, self-signed, hostname mismatch, legacy protocols

from __future__ import annotations
import datetime as _dt
import socket
import ssl
from typing import Dict, List, Tuple

def _finding(host: str, port: int, issue: str, severity: str, rec: str = "") -> Dict:
    return {
        "host": host,
        "port": port,
        "category": "tls",
        "issue": issue,
        "severity": severity,
        "recommendation": rec,
    }

def _parse_cert_dates(cert: dict) -> Tuple[_dt.datetime, _dt.datetime]:
    # notBefore/After are ASN.1 time strings like 'Jun  1 12:00:00 2024 GMT'
    def _parse(s: str) -> _dt.datetime:
        return _dt.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
    not_before = _parse(cert["notBefore"])
    not_after = _parse(cert["notAfter"])
    return not_before, not_after

def _dns_match(pattern: str, host: str) -> bool:
    pattern = pattern.lower()
    host = host.lower()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") >= pattern.count(".")
    return False

def _host_in_cert(cert: dict, host: str) -> bool:
    # Check SAN first
    san = cert.get("subjectAltName", [])
    for typ, val in san:
        if typ.lower() == "dns" and _dns_match(val, host):
            return True
    # Fallback to CN
    for tup in cert.get("subject", []):
        for k, v in tup:
            if k == "commonName" and _dns_match(v, host):
                return True
    return False

def _supports_legacy_tls(host: str, port: int, timeout: float, version: ssl.TLSVersion) -> bool:
    """
    Attempt a handshake with a specific minimum version (TLSv1.0/1.1).
    Returns True if the handshake succeeds (meaning legacy is accepted).
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.do_handshake()
                return True
    except Exception:
        return False

def check_tls(host: str, port: int, timeout: float = 3.0) -> List[Dict]:
    findings: List[Dict] = []

    # Connect with modern defaults to fetch cert
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert()
                proto = s.version() if hasattr(s, "version") else "TLS"
                if cert:
                    # Dates
                    nb, na = _parse_cert_dates(cert)
                    now = _dt.datetime.utcnow()
                    if now < nb:
                        findings.append(_finding(host, port, "Certificate not yet valid", "Medium", "Check server time and cert validity period."))
                    if now > na:
                        findings.append(_finding(host, port, "Certificate expired", "Medium", "Renew certificate."))
                    # Self-signed heuristic
                    if cert.get("issuer") == cert.get("subject"):
                        findings.append(_finding(host, port, "Self-signed certificate", "Low", "Use a CA-signed certificate in production."))
                    # Hostname mismatch
                    if not _host_in_cert(cert, host):
                        findings.append(_finding(host, port, "Certificate host mismatch (CN/SAN vs target)", "Low", "Serve a certificate matching the hostname."))
                # Protocol info
                findings.append(_finding(host, port, f"Negotiated protocol: {proto}", "Info", "Ensure TLS 1.2+ is used whenever possible."))
    except Exception as e:
        findings.append(_finding(host, port, f"TLS handshake failed: {type(e).__name__}", "Info", "Service may require SNI or block plain probes."))
        return findings

    # Legacy protocol support checks (if Python supports TLSVersion attr)
    try:
        if _supports_legacy_tls(host, port, timeout, ssl.TLSVersion.TLSv1):
            findings.append(_finding(host, port, "Server accepts TLS 1.0 (obsolete)", "High", "Disable TLS 1.0. Prefer TLS 1.2+"))
        if _supports_legacy_tls(host, port, timeout, ssl.TLSVersion.TLSv1_1):
            findings.append(_finding(host, port, "Server accepts TLS 1.1 (obsolete)", "High", "Disable TLS 1.1. Prefer TLS 1.2+"))
    except Exception:
        pass

    return findings