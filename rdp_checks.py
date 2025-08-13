# rdp_checks.py
# Basic RDP checks

from __future__ import annotations
import socket
from typing import Dict, List

def _finding(host: str, port: int, issue: str, severity: str, rec: str = "") -> Dict:
    return {
        "host": host,
        "port": port,
        "category": "rdp",
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

def check_rdp(host: str, rdp_ports: List[int], timeout: float = 1.5) -> List[Dict]:
    findings: List[Dict] = []
    for p in rdp_ports:
        if _tcp_connect(host, p, timeout):
            findings.append(_finding(
                host, p,
                "RDP exposed to network",
                "Medium",
                "Enable Network Level Authentication (NLA), restrict by firewall/VPN, use strong auth/MFA, and monitor failed logons."
            ))
    return findings