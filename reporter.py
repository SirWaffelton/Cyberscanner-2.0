import json
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

# Simple ANSI colors (no external deps)
COLORS = {
    "RESET": "\033[0m",
    "RED": "\033[31m",
    "YELLOW": "\033[33m",
    "GREEN": "\033[32m",
    "BLUE": "\033[34m",
    "CYAN": "\033[36m",
    "GRAY": "\033[90m",
    "BOLD": "\033[1m",
}

SEV_COLOR = {
    "CRITICAL": "RED",
    "HIGH": "RED",
    "MEDIUM": "YELLOW",
    "LOW": "GREEN",
    "INFO": "CYAN",
}


@dataclass
class Finding:
    severity: str
    type: str
    target: str
    message: str
    recommendation: str
    meta: Optional[Dict[str, Any]] = None


class Reporter:
    def __init__(self, colorize: bool = True):
        self.findings: List[Finding] = []
        self.colorize = colorize and sys.stdout.isatty()
        self.start_ts = int(time.time())

    def add_finding(self, severity: str, type: str, target: str, message: str, recommendation: str, **meta):
        self.findings.append(Finding(severity=severity, type=type, target=target, message=message, recommendation=recommendation, meta=meta or None))

    def extend(self, finding_dicts: List[Dict[str, Any]]):
        for f in finding_dicts:
            meta = {k: v for k, v in f.items() if k not in ("severity", "type", "target", "message", "recommendation")}
            self.add_finding(f["severity"], f["type"], f["target"], f["message"], f["recommendation"], **meta)

    def color(self, text: str, color_name: str) -> str:
        if not self.colorize:
            return text
        return f'{COLORS.get(color_name, "")}{text}{COLORS["RESET"]}'

    def to_text(self) -> str:
        lines = []
        lines.append("")
        lines.append("--- Vulnerability Report (colorized) ---")
        lines.append("")
        for f in self.findings:
            sev = f.severity.upper()
            sev_col = SEV_COLOR.get(sev, "BLUE")
            lines.append(f'{self.color("[" + sev + "]", sev_col)} {f.target} - {f.type}')
            lines.append("")
            lines.append(f"  Message: {f.message}")
            lines.append("")
            lines.append(f"  Recommendation: {f.recommendation}")
            lines.append("")
            lines.append("-" * 50)
            lines.append("")
        return "\n".join(lines)

    def to_json(self) -> str:
        obj = {
            "generated_at": self.start_ts,
            "findings": [asdict(f) for f in self.findings],
        }
        return json.dumps(obj, indent=2)

    def to_html(self) -> str:
        # Minimal HTML (no template dependency)
        def sev_color(sev: str) -> str:
            return {
                "CRITICAL": "#b91c1c",
                "HIGH": "#ef4444",
                "MEDIUM": "#f59e0b",
                "LOW": "#10b981",
                "INFO": "#06b6d4",
            }.get(sev.upper(), "#60a5fa")

        items = []
        for f in self.findings:
            items.append(f"""
            <div style="border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin:12px 0;">
              <div style="font-weight:600;color:{sev_color(f.severity)};">[{f.severity.upper()}] {f.target} - {f.type}</div>
              <div style="margin-top:6px;"><strong>Message:</strong> {f.message}</div>
              <div style="margin-top:6px;"><strong>Recommendation:</strong> {f.recommendation}</div>
            </div>
            """)
        html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Scan Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; max-width:960px; margin:20px auto; padding:0 12px;">
  <h1>Vulnerability Report</h1>
  <div>Generated at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.start_ts))}</div>
  {''.join(items) or '<p>No findings.</p>'}
</body>
</html>"""
        return html

    def save_text(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_text())

    def save_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    def save_html(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_html())