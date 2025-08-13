# ui.py
# Minimal terminal UI using rich (optional)

from __future__ import annotations
from typing import Any, Dict, List, Optional

try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.console import Group
    from rich.text import Text
except Exception:  # pragma: no cover
    Live = None  # type: ignore


class ProgressUI:
    def __init__(self, total_hosts: int, total_ports: int):
        self.total_hosts = total_hosts
        self.total_ports = total_ports
        self.hosts_done = 0
        self.ports_done = 0
        self.current_host: Optional[str] = None
        self.last_open_ports: Dict[str, List[int]] = {}
        self.last_findings: List[Dict[str, Any]] = []
        self._live: Optional[Live] = None

    def start(self):
        if Live is None:
            return
        self._live = Live(self._render(), refresh_per_second=12)
        self._live.start()

    def stop(self):
        if self._live:
            self._live.stop()
            self._live = None

    def stop_requested(self) -> bool:
        # Hook for future keyboard interrupt handling
        return False

    def on_host_started(self, host: str):
        self.current_host = host
        self._refresh()

    def on_port_result(self, host: str, port: int, is_open: bool):
        self.ports_done += 1
        if is_open:
            self.last_open_ports.setdefault(host, []).append(port)
        self._refresh()

    def on_host_finished(self, host: str, open_ports: List[int]):
        self.hosts_done += 1
        self._refresh()

    def on_check(self, host: str, stage: str):
        # stage: "tls" or "web" etc.
        self._refresh()

    def on_finding(self, host: str, f: Dict[str, Any]):
        self.last_findings.append({"host": host, **f})
        self._refresh()

    def _refresh(self):
        if self._live:
            self._live.update(self._render())

    def _render(self):
        header = Panel(Text("Cyberscanner UI", style="bold cyan"))
        stats = Panel(
            Text(
                f"Hosts: {self.hosts_done}/{self.total_hosts} | "
                f"Ports tested: {self.ports_done}/{self.total_ports} | "
                f"Current: {self.current_host or '-'}",
                style="white",
            ),
            title="Progress",
        )

        table = Table(title="Latest Findings (last 10)")
        table.add_column("Severity", style="bold")
        table.add_column("Host:Port")
        table.add_column("Category")
        table.add_column("Issue")
        last10 = self.last_findings[-10:]
        for f in last10:
            sev = str(f.get("severity", "Info"))
            host = str(f.get("host", "?"))
            port = str(f.get("port", "?"))
            cat = str(f.get("category", "general"))
            issue = str(f.get("issue", ""))
            table.add_row(sev, f"{host}:{port}", cat, issue)

        opens = Table(title="Open Ports (latest hosts)")
        opens.add_column("Host")
        opens.add_column("Ports")
        for host, ports in list(self.last_open_ports.items())[-5:]:
            opens.add_row(host, ", ".join(map(str, sorted(set(ports)))))

        return Group(header, stats, opens, table)