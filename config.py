from dataclasses import dataclass, field
from typing import List


@dataclass
class ScanConfig:
    # Networking
    connect_timeout: float = 1.0
    service_timeout: float = 3.0
    http_timeout: float = 4.0
    http_retries: int = 1
    user_agent: str = "SecUtil/1.2 (+local scan)"

    # Scanning
    default_ports: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 161, 3389
    ])
    max_workers: int = 200

    # Web checks
    sensitive_paths: List[str] = field(default_factory=lambda: [
        "/", "/.git/", "/.env", "/.git/config", "/.svn/entries", "/.hg/",
        "/admin/", "/uploads/", "/backup.zip", "/backups/", "/config.php",
        "/server-status?auto", "/server-status", "/phpinfo.php", "/actuator",
        "/console", "/manager/html", "/.DS_Store"
    ])
    security_headers_expected: List[str] = field(default_factory=lambda: [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ])
    max_sensitive_paths: int = 20

    # Reporting
    colorize: bool = True
    save_text_path: str = "scan_report.txt"
    save_json_path: str = "scan_report.json"
    save_html_path: str | None = None  # e.g., "scan_report.html"