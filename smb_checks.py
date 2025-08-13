# smb_checks.py
# Basic SMB/NetBIOS checks

from __future__ import annotations
import socket
from typing import Dict, List

def _finding(host: str, port: int, issue: str, severity: str, rec: str = "") -> Dict:
    return {
        "host": host,
        "port": port,
        "category": "smb",
        "issue": issue,
        "severity": severity,
        "recommendation": rec,
    }

def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def check_smb(host: str, smb_ports: List[int], timeout: float = 1.5) -> List[Dict]:
    findings: List[Dict] = []
    has_445 = 445 in smb_ports
    has_139 = 139 in smb_ports

    # TCP reachability checks (informational, since banner grabbing is non-trivial without libs)
    if has_445 and _tcp_connect(host, 445, timeout):
        findings.append(_finding(
            host, 445,
            "SMB (445) exposed to network",
            "Medium",
            "If not required, disable file sharing or block inbound TCP 445 on firewall. Require SMB signing; disable SMBv1."
        ))
    if has_139 and _tcp_connect(host, 139, timeout):
        findings.append(_finding(
            host, 139,
            "NetBIOS over TCP (139) exposed",
            "Low",
            "Disable NetBIOS over TCP/IP if not needed; prefer pure SMB over 445 only."
        ))

    if has_445 and has_139:
        findings.append(_finding(
            host, 445,
            "Both SMB (445) and NetBIOS (139) open",
            "Info",
            "Consider disabling legacy NetBIOS (139) and limiting SMB exposure."
        ))

    return findings