# ui.py
import threading
import time
from collections import deque, defaultdict
from typing import Dict, List, Optional

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    MofNCompleteColumn,
    SpinnerColumn,
)
from rich.table import Table


def _read_key_nonblocking() -> Optional[str]:
    # Windows fast path
    try:
        import msvcrt  # type: ignore
        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            return ch
        return None
    except Exception:
        # POSIX fallback (no-op to keep this dependency-light)
        return None


class ProgressUI:
    def __init__(self, total_hosts: int, total_ports: int) -> None:
        self.console = Console()
        self.progress = Progress(
            SpinnerColumn(style="bold cyan"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            expand=True,
        )

        self.hosts_task = self.progress.add_task("Hosts", total=max(1, total_hosts))
        self.ports_task = self.progress.add_task("Ports", total=max(1, total_ports))

        self.logs = deque(maxlen=300)
        self.finding_counts = defaultdict(int)  # severity -> count
        self.total_open_ports = 0
        self.total_ports_scanned = 0
        self.total_hosts = total_hosts
        self.current_host: Optional[str] = None
        self._lock = threading.Lock()
        self._stop_requested = False
        self._live: Optional[Live] = None
        self._keyboard_thread: Optional[threading.Thread] = None

    # ---------- Public controls ----------
    def start(self):
        self._live = Live(self.render_layout(), refresh_per_second=10, console=self.console)
        self._live.start()
        self._keyboard_thread = threading.Thread(target=self._keyboard_loop, daemon=True)
        self._keyboard_thread.start()

    def stop(self):
        # drain keyboard thread naturally
        if self._live:
            self._live.stop()

    def stop_requested(self) -> bool:
        with self._lock:
            return self._stop_requested

    # ---------- Event sinks ----------
    def log(self, message: str):
        with self._lock:
            self.logs.append(f"{time.strftime('%H:%M:%S')}  {message}")
            self._refresh()

    def on_host_started(self, host: str):
        with self._lock:
            self.current_host = host
            self.logs.append(f"{time.strftime('%H:%M:%S')}  ▶ Scanning {host}")
            self._refresh()

    def on_port_result(self, host: str, port: int, is_open: bool):
        with self._lock:
            self.total_ports_scanned += 1
            try:
                self.progress.advance(self.ports_task, 1)
            except Exception:
                pass
            if is_open:
                self.total_open_ports += 1
                self.logs.append(f"{time.strftime('%H:%M:%S')}  + {host}:{port} open")
            self._refresh()

    def on_host_finished(self, host: str, open_ports: List[int]):
        with self._lock:
            try:
                self.progress.advance(self.hosts_task, 1)
            except Exception:
                pass
            if open_ports:
                ports = ", ".join(str(p) for p in open_ports)
                self.logs.append(f"{time.strftime('%H:%M:%S')}  ✓ {host} open ports -> {ports}")
            else:
                self.logs.append(f"{time.strftime('%H:%M:%S')}  ✓ {host} no open ports found")
            self.current_host = None
            self._refresh()

    def on_check(self, host: str, stage: str):
        with self._lock:
            self.logs.append(f"{time.strftime('%H:%M:%S')}  • {host} check: {stage}")
            self._refresh()

    def on_finding(self, host: str, finding: Dict):
        sev = (finding.get("severity") or "INFO").upper()
        typ = finding.get("type") or "finding"
        msg = finding.get("message") or ""
        with self._lock:
            self.finding_counts[sev] += 1
            self.logs.append(f"{time.strftime('%H:%M:%S')}  ! [{sev}] {host} - {typ}: {msg[:100]}")
            self._refresh()

    def save_snapshot(self, path: str = "ui_snapshot.txt"):
        snap = self._build_text_snapshot()
        with open(path, "w", encoding="utf-8") as f:
            f.write(snap)
        self.log(f"Snapshot saved -> {path}")

    # ---------- Rendering ----------
    def _build_text_snapshot(self) -> str:
        lines = []
        lines.append("=== Scan Snapshot ===")
        lines.append(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Hosts progress: {self.progress.tasks[self.hosts_task].completed}/{self.progress.tasks[self.hosts_task].total}")
        lines.append(f"Ports progress: {self.progress.tasks[self.ports_task].completed}/{self.progress.tasks[self.ports_task].total}")
        lines.append(f"Open ports found: {self.total_open_ports}")
        lines.append("Findings by severity:")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            lines.append(f"  {sev}: {self.finding_counts.get(sev, 0)}")
        lines.append("")
        lines.append("Recent logs:")
        for ln in list(self.logs)[-100:]:
            lines.append(f"  {ln}")
        lines.append("")
        lines.append("Hotkeys: [q] quit after current host, [s] save snapshot")
        return "\n".join(lines)

    def render_layout(self):
        # Left: progress group; Right: findings table; Bottom: logs
        metrics = Table.grid(expand=True)
        metrics.add_column()
        metrics.add_column(justify="right")
        metrics.add_row(
            f"[bold]Current host:[/bold] {self.current_host or '-'}",
            f"[bold]Open ports:[/bold] {self.total_open_ports}   [bold]Ports scanned:[/bold] {self.total_ports_scanned}",
        )

        findings_tbl = Table(title="Findings", expand=True, show_edge=False, box=None)
        findings_tbl.add_column("Severity", style="bold")
        findings_tbl.add_column("Count", justify="right")
        for sev, color in [("CRITICAL", "red"), ("HIGH", "red"), ("MEDIUM", "yellow"), ("LOW", "green"), ("INFO", "cyan")]:
            findings_tbl.add_row(f"[{color}]{sev}[/{color}]", str(self.finding_counts.get(sev, 0)))

        progress_panel = Panel(
            Group(metrics, self.progress),
            title="Progress",
            border_style="cyan",
        )
        findings_panel = Panel(findings_tbl, title="Summary", border_style="magenta")

        logs_tbl = Table(title="Logs (latest 50)", expand=True, show_header=False, box=None)
        for ln in list(self.logs)[-50:]:
            logs_tbl.add_row(ln)
        logs_panel = Panel(logs_tbl, border_style="blue")

        top = Table.grid(expand=True)
        top.add_column(ratio=2)
        top.add_column(ratio=1)
        top.add_row(progress_panel, findings_panel)

        return Group(top, logs_panel, Panel("[dim]Hotkeys: [q] quit after current host   [s] save snapshot[/dim]", border_style="dim"))

    def _refresh(self):
        if self._live:
            try:
                self._live.update(self.render_layout())
            except Exception:
                pass

    def _keyboard_loop(self):
        while self._live and self._live.is_started:
            key = _read_key_nonblocking()
            if key:
                k = key.lower()
                if k == "q":
                    with self._lock:
                        self._stop_requested = True
                        self.logs.append(f"{time.strftime('%H:%M:%S')}  ⚠ Stop requested (will exit after current host)")
                        self._refresh()
                elif k == "s":
                    self.save_snapshot()
            time.sleep(0.05)