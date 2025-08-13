# vuln_tester.py
# Orchestrates vulnerability checks based on open ports

from __future__ import annotations
from typing import Callable, Dict, List, Optional

from config import ScanConfig
from web_checks import check_http
from tls_checks import check_tls
from smb_checks import check_smb
from rdp_checks import check_rdp

HTTP_PORTS = {80, 8080, 8000, 3000, 5000}
HTTPS_PORTS = {443, 8443, 4443, 9443}
SMB_PORTS = {445, 139}
RDP_PORTS = {3389}

def run_vuln_checks(
    host: str,
    open_ports: List[int],
    cfg: ScanConfig,
    on_progress: Optional[Callable[[str], None]] = None,
    on_finding: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """
    Given host and open_ports, run relevant checks and return findings list.
    """
    findings: List[Dict] = []

    def emit(stage: str):
        if on_progress:
            try:
                on_progress(stage)
            except Exception:
                pass

    def add_findings(new_items: List[Dict]):
        for f in new_items:
            findings.append(f)
            if on_finding:
                try:
                    on_finding(f)
                except Exception:
                    pass

    # TLS checks (for HTTPS-like ports)
    https_ports = sorted([p for p in open_ports if p in HTTPS_PORTS])
    if https_ports:
        emit("tls")
        for p in https_ports:
            add_findings(check_tls(host, p, timeout=cfg.tls_timeout))

    # HTTP/HTTPS web hygiene checks
    httpish_ports = sorted([p for p in open_ports if p in HTTP_PORTS or p in HTTPS_PORTS])
    if httpish_ports:
        emit("web")
        for p in httpish_ports:
            scheme = "https" if p in HTTPS_PORTS else "http"
            add_findings(check_http(host, p, scheme=scheme, timeout=cfg.http_timeout))

    # SMB checks
    smb_ports = sorted([p for p in open_ports if p in SMB_PORTS])
    if smb_ports:
        emit("smb")
        add_findings(check_smb(host, smb_ports, timeout=cfg.service_timeout))

    # RDP checks
    rdp_ports = sorted([p for p in open_ports if p in RDP_PORTS])
    if rdp_ports:
        emit("rdp")
        add_findings(check_rdp(host, rdp_ports, timeout=cfg.service_timeout))

    return findings