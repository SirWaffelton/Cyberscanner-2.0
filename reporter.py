# reporter.py
# Handles report aggregation and saving in text, JSON, and HTML formats

from __future__ import annotations
import json
import os
from datetime import datetime
from typing import Any, Dict, List


def _ensure_parent(path: str):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


class Reporter:
    def __init__(self, colorize: bool = True):
        self.colorize = colorize
        # Findings are dicts like:
        # { "host": "192.168.1.254", "port": 443, "category": "web|tls|service",
        #   "issue": "Missing X-Frame-Options", "severity": "Medium",
        #   "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN" }
        self.findings: List[Dict[str, Any]] = []
        self.host_open_ports: Dict[str, List[int]] = {}
        self.started_at = datetime.utcnow()

    def add_finding(self, **finding: Any):
        self.findings.append(finding)

    def add_open_ports(self, host: str, ports: List[int]):
        self.host_open_ports[host] = sorted(ports)

    def to_text(self) -> str:
        lines: List[str] = []
        lines.append(f"== Cyberscanner Report ==")
        lines.append(f"Generated (UTC): {self.started_at.isoformat()}Z")
        lines.append("")

        if self.host_open_ports:
            lines.append("Open Ports by Host:")
            for host, ports in sorted(self.host_open_ports.items()):
                ports_str = ", ".join(map(str, ports)) if ports else "(none)"
                lines.append(f"  - {host}: {ports_str}")
            lines.append("")

        if not self.findings:
            lines.append("No findings.")
        else:
            lines.append("Findings:")
            for f in self.findings:
                host = f.get("host", "?")
                port = f.get("port", "?")
                cat = f.get("category", "general")
                sev = f.get("severity", "Info")
                issue = f.get("issue", "")
                rec = f.get("recommendation", "")
                lines.append(f"- [{sev}] {host}:{port} ({cat}) — {issue}")
                if rec:
                    lines.append(f"    Fix: {rec}")

        return "\n".join(lines)

    def to_json(self) -> str:
        doc = {
            "meta": {
                "generated_utc": self.started_at.isoformat() + "Z",
                "tool": "Cyberscanner 2.2",
            },
            "hosts": [
                {"host": host, "open_ports": ports}
                for host, ports in sorted(self.host_open_ports.items())
            ],
            "findings": self.findings,
        }
        return json.dumps(doc, indent=2)

    def to_html(self) -> str:
        css = """
        body { font-family: Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }
        h1 { margin-bottom: 0; }
        .sub { color: #666; margin-top: 4px; }
        table { border-collapse: collapse; width: 100%; margin-top: 12px; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f5f5f5; }
        .sev-High { color: #b00020; font-weight: 600; }
        .sev-Medium { color: #a15c00; font-weight: 600; }
        .sev-Low { color: #00529b; font-weight: 600; }
        .sev-Info { color: #444; font-weight: 600; }
        """
        html: List[str] = []
        html.append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Cyberscanner Report</title>")
        html.append(f"<style>{css}</style></head><body>")
        html.append("<h1>Cyberscanner Report</h1>")
        html.append(f"<div class='sub'>Generated (UTC): {self.started_at.isoformat()}Z</div>")

        if self.host_open_ports:
            html.append("<h2>Open Ports by Host</h2>")
            html.append("<table><thead><tr><th>Host</th><th>Open Ports</th></tr></thead><tbody>")
            for host, ports in sorted(self.host_open_ports.items()):
                ports_str = ", ".join(map(str, ports)) if ports else "(none)"
                html.append(f"<tr><td>{host}</td><td>{ports_str}</td></tr>")
            html.append("</tbody></table>")

        html.append("<h2>Findings</h2>")
        if not self.findings:
            html.append("<p>No findings.</p>")
        else:
            html.append("<table><thead><tr><th>Severity</th><th>Host:Port</th><th>Category</th><th>Issue</th><th>Recommendation</th></tr></thead><tbody>")
            for f in self.findings:
                host = f.get("host", "?")
                port = f.get("port", "?")
                cat = f.get("category", "general")
                sev = f.get("severity", "Info")
                issue = f.get("issue", "")
                rec = f.get("recommendation", "")
                sev_class = f"sev-{sev}"
                html.append(
                    f"<tr><td class='{sev_class}'>{sev}</td>"
                    f"<td>{host}:{port}</td><td>{cat}</td><td>{issue}</td><td>{rec}</td></tr>"
                )
            html.append("</tbody></table>")

        html.append("</body></html>")
        return "".join(html)

    def save_text(self, path: str):
        _ensure_parent(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_text())

    def save_json(self, path: str):
        _ensure_parent(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    def save_html(self, path: str):
        _ensure_parent(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_html())