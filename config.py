# config.py
# Central configuration for Cyberscanner

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


# Preset port profiles for convenience
PROFILES = {
    # Focused on web and common alt ports
    "web": [80, 443, 8080, 8443, 3000],
    # Common Windows services
    "windows": [135, 139, 445, 3389, 5985, 5986],
    # Consumer/home router-ish services (mgmt, UPnP, web)
    "home-router": [53, 80, 443, 1900, 5000, 5001, 8080, 8443],
    # Small, practical set to keep scans fast
    "top20": [
        21, 22, 23, 25, 53, 67, 68, 80, 110, 123,
        135, 139, 143, 389, 443, 445, 3389, 5000, 8080, 8443
    ],
}


@dataclass
class ScanConfig:
    # Default ports (used if user doesn't pass --ports or --profile)
    default_ports: List[int] = field(default_factory=lambda: [22, 80, 443, 445, 3389, 8080, 8443, 3000])

    # Timeouts (seconds)
    connect_timeout: float = 1.5
    service_timeout: float = 1.5
    http_timeout: float = 2.5
    tls_timeout: float = 3.0

    # Concurrency (global cap used by scanner)
    max_workers: int = 100

    # Report outputs; HTML is saved only if user passes --html
    save_text_path: str = "scan_report.txt"
    save_json_path: str = "scan_report.json"
    save_html_path: Optional[str] = None

    # Version/meta (optional)
    version: str = "2.2.0"