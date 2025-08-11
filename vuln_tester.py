import re
import smtplib
import socket
import ftplib
from typing import Callable, Dict, List, Tuple, Optional

from config import ScanConfig
from web_checks import (
    check_security_headers,
    check_sensitive_paths,
    check_https_redirect,
    fingerprint_http,
    check_security_txt,
    check_robots_txt,
    detect_cms,
)
from tls_checks import inspect_tls


FindingCb = Optional[Callable[[Dict], None]]
StageCb = Optional[Callable[[str], None]]


def _emit(stage_cb: StageCb, finding_cb: FindingCb, stage: str, items: List[Dict]) -> List[Dict]:
    if stage_cb:
        try:
            stage_cb(stage)
        except Exception:
            pass
    if finding_cb:
        for f in items:
            try:
                finding_cb(f)
            except Exception:
                pass
    return items


def check_ftp_anonymous(host: str, port: int, cfg: ScanConfig) -> List[Dict]:
    findings: List[Dict] = []
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=cfg.service_timeout)
        resp = ftp.login(user="anonymous", passwd="anonymous@example.com")
        ftp.quit()
        if "230" in resp:
            findings.append({
                "severity": "MEDIUM",
                "type": "ftp.anonymous_enabled",
                "target": f"{host}:{port}",
                "message": "FTP allows anonymous login",
                "recommendation": "Disable anonymous FTP or restrict it to a sandbox with no sensitive content."
            })
    except Exception:
        pass
    return findings


def check_ssh_banner(host: str, port: int, cfg: ScanConfig) -> List[Dict]:
    findings: List[Dict] = []
    try:
        with socket.create_connection((host, port), timeout=cfg.service_timeout) as s:
            banner = s.recv(200).decode(errors="ignore").strip()
            if banner.startswith("SSH-"):
                sev = "INFO"
                msg = f"SSH banner: {banner}"
                m = re.search(r"OpenSSH[_-](\d+)\.(\d+)", banner, re.I)
                if m:
                    major = int(m.group(1))
                    if major <= 6:
                        sev = "MEDIUM"
                        msg += " (ancient OpenSSH version detected)"
                findings.append({
                    "severity": sev,
                    "type": "ssh.banner",
                    "target": f"{host}:{port}",
                    "message": msg,
                    "recommendation": "Ensure SSH is updated and strong KEX/MACs are enforced; disable password auth if possible."
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "type": "ssh.no_banner",
                    "target": f"{host}:{port}",
                    "message": "SSH service did not present a recognizable banner",
                    "recommendation": "Verify SSH configuration; ensure up-to-date server with modern ciphers."
                })
    except Exception:
        pass
    return findings


def check_telnet(host: str, port: int, cfg: ScanConfig) -> List[Dict]:
    return [{
        "severity": "HIGH",
        "type": "telnet.exposed",
        "target": f"{host}:{port}",
        "message": "Telnet service exposed (unencrypted remote access)",
        "recommendation": "Disable Telnet and use SSH."
    }]


def check_smtp_open_relay(host: str, port: int, cfg: ScanConfig) -> List[Dict]:
    findings: List[Dict] = []
    try:
        with smtplib.SMTP(host=host, port=port, timeout=cfg.service_timeout) as s:
            s.ehlo_or_helo_if_needed()
            code, _ = s.mail("probe@external.invalid")
            if code != 250:
                return findings
            code, _ = s.rcpt("test@example.com")
            if code in (250, 251):
                findings.append({
                    "severity": "HIGH",
                    "type": "smtp.open_relay_suspected",
                    "target": f"{host}:{port}",
                    "message": f"Server accepted RCPT for external domain (code {code})",
                    "recommendation": "Disable unauthenticated relaying; restrict to authenticated users and local domains."
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "type": "smtp.relay_denied",
                    "target": f"{host}:{port}",
                    "message": "Server appears to deny open relay",
                    "recommendation": "Ensure relaying is only permitted for authenticated users and authorized networks."
                })
            try:
                s.rset()
                s.quit()
            except Exception:
                pass
    except Exception:
        pass
    return findings


# Minimal DNS recursion helpers
def build_dns_query(name: str = "example.com") -> bytes:
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(len(part).to_bytes(1, "big") + part.encode() for part in name.split(".")) + b"\x00"
    qtype_qclass = b"\x00\x01\x00\x01"
    return header + qname + qtype_qclass


def parse_dns_flags_and_counts(resp: bytes) -> Tuple[int, int, int]:
    if len(resp) < 12:
        return 0, 0, 0
    flags = int.from_bytes(resp[2:4], "big")
    ancount = int.from_bytes(resp[6:8], "big")
    rcode = flags & 0x000F
    return flags, ancount, rcode


def check_dns_recursion(host: str, port: int, cfg: ScanConfig) -> List[Dict]:
    findings: List[Dict] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(cfg.service_timeout)
            q = build_dns_query("example.com")
            s.sendto(q, (host, port))
            resp, _ = s.recvfrom(512)
            flags, ancount, rcode = parse_dns_flags_and_counts(resp)
            ra = bool(flags & 0x0080)
            if ra and ancount > 0 and rcode == 0:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "dns.recursion_enabled",
                    "target": f"{host}:{port}",
                    "message": "DNS server performs recursion for external queries",
                    "recommendation": "Disable open recursion or restrict to internal clients only."
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "type": "dns.recursion_not_open",
                    "target": f"{host}:{port}",
                    "message": "DNS recursion not openly available (or no external answers returned)",
                    "recommendation": "If this is an internal resolver, ensure ACLs restrict recursion to trusted subnets."
                })
    except Exception:
        pass
    return findings


def check_smb_exposure(host: str, port: int, cfg: ScanConfig) -> List[Dict]:
    return [{
        "severity": "MEDIUM",
        "type": "smb.exposed",
        "target": f"{host}:{port}",
        "message": "SMB service exposed on the network",
        "recommendation": "Restrict SMB access, require SMB signing, and ensure SMBv1 is disabled."
    }]


def check_rdp_nla_advisory(host: str, port: int, cfg: ScanConfig) -> List[Dict]:
    return [{
        "severity": "INFO",
        "type": "rdp.exposed",
        "target": f"{host}:{port}",
        "message": "RDP service exposed; NLA requirement not verified",
        "recommendation": "Require Network Level Authentication (NLA) and restrict RDP to VPN or jump hosts."
    }]


def check_snmp_advisory(host: str, port: int, cfg: ScanConfig) -> List[Dict]:
    return [{
        "severity": "INFO",
        "type": "snmp.exposed",
        "target": f"{host}:{port}",
        "message": "SNMP service exposed; default community strings not verified",
        "recommendation": "Disable SNMP or restrict to specific IPs; change default community strings."
    }]


def run_vuln_checks(
    host: str,
    open_ports: List[int],
    cfg: ScanConfig,
    on_progress: StageCb = None,
    on_finding: FindingCb = None
) -> List[Dict]:
    findings: List[Dict] = []

    # Web checks
    if 80 in open_ports:
        findings += _emit(on_progress, on_finding, "web.fingerprint (80)", fingerprint_http(host, 80, False, cfg.http_timeout, cfg.http_retries, cfg.user_agent))
        findings += _emit(on_progress, on_finding, "web.headers (80)", check_security_headers(host, 80, False, cfg.security_headers_expected, cfg.http_timeout, cfg.http_retries, cfg.user_agent))
        findings += _emit(on_progress, on_finding, "web.https_redirect (80)", check_https_redirect(host, cfg.http_timeout, cfg.http_retries, cfg.user_agent))
        findings += _emit(on_progress, on_finding, "web.sensitive_paths (80)", check_sensitive_paths(host, 80, False, cfg.sensitive_paths, cfg.http_timeout, cfg.http_retries, cfg.user_agent, cfg.max_sensitive_paths))
        findings += _emit(on_progress, on_finding, "web.robots (80)", check_robots_txt(host, 80, False, cfg.http_timeout, cfg.http_retries, cfg.user_agent))
        findings += _emit(on_progress, on_finding, "web.security_txt (80)", check_security_txt(host, 80, False, cfg.http_timeout, cfg.http_retries, cfg.user_agent))

    if 443 in open_ports:
        findings += _emit(on_progress, on_finding, "tls.inspect (443)", inspect_tls(host, 443, server_hostname=host, timeout=cfg.http_timeout))
        findings += _emit(on_progress, on_finding, "web.fingerprint (443)", fingerprint_http(host, 443, True, cfg.http_timeout, cfg.http_retries, cfg.user_agent))
        findings += _emit(on_progress, on_finding, "web.headers (443)", check_security_headers(host, 443, True, cfg.security_headers_expected, cfg.http_timeout, cfg.http_retries, cfg.user_agent))
        findings += _emit(on_progress, on_finding, "web.sensitive_paths (443)", check_sensitive_paths(host, 443, True, cfg.sensitive_paths, cfg.http_timeout, cfg.http_retries, cfg.user_agent, cfg.max_sensitive_paths))
        findings += _emit(on_progress, on_finding, "web.cms_detection (443)", detect_cms(host, 443, True, cfg.http_timeout, cfg.http_retries, cfg.user_agent))
        findings += _emit(on_progress, on_finding, "web.robots (443)", check_robots_txt(host, 443, True, cfg.http_timeout, cfg.http_retries, cfg.user_agent))
        findings += _emit(on_progress, on_finding, "web.security_txt (443)", check_security_txt(host, 443, True, cfg.http_timeout, cfg.http_retries, cfg.user_agent))

    # FTP
    if 21 in open_ports:
        findings += _emit(on_progress, on_finding, "ftp.anonymous (21)", check_ftp_anonymous(host, 21, cfg))

    # SSH
    if 22 in open_ports:
        findings += _emit(on_progress, on_finding, "ssh.banner (22)", check_ssh_banner(host, 22, cfg))

    # Telnet
    if 23 in open_ports:
        findings += _emit(on_progress, on_finding, "telnet.exposed (23)", check_telnet(host, 23, cfg))

    # SMTP
    for smtp_port in (25, 587):
        if smtp_port in open_ports:
            findings += _emit(on_progress, on_finding, f"smtp.open_relay ({smtp_port})", check_smtp_open_relay(host, smtp_port, cfg))

    # DNS
    if 53 in open_ports:
        findings += _emit(on_progress, on_finding, "dns.recursion (53)", check_dns_recursion(host, 53, cfg))

    # SMB
    if 445 in open_ports:
        findings += _emit(on_progress, on_finding, "smb.exposed (445)", check_smb_exposure(host, 445, cfg))

    # SNMP
    if 161 in open_ports:
        findings += _emit(on_progress, on_finding, "snmp.exposed (161)", check_snmp_advisory(host, 161, cfg))

    # RDP
    if 3389 in open_ports:
        findings += _emit(on_progress, on_finding, "rdp.exposed (3389)", check_rdp_nla_advisory(host, 3389, cfg))

    return findings