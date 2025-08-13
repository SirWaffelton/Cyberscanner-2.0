# main.py
# CLI entrypoint: scanning, vuln checks, reporting

from __future__ import annotations
import argparse
import os
import re
import socket
import subprocess
import sys
import time
from typing import List

from config import ScanConfig, PROFILES
from reporter import Reporter
from scanner import parse_targets, scan_host_ports
from vuln_tester import run_vuln_checks

# Optional UI
try:
    from ui import ProgressUI
except Exception:
    ProgressUI = None  # type: ignore


def ensure_parent_dir(path: str):
    if not path:
        return
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def get_local_ipv4s() -> set[str]:
    """Best-effort local IPv4 discovery for --skip-self (Windows-friendly)."""
    ips = set()
    # Windows ipconfig parse
    try:
        out = subprocess.run(["ipconfig"], capture_output=True, text=True, check=False).stdout
        for m in re.finditer(r"IPv4 Address[^\d]+(\d+\.\d+\.\d+\.\d+)", out):
            ips.add(m.group(1))
    except Exception:
        pass
    # Fallback via hostname resolution
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    return ips


def expand_web_ports_if_requested(ports: List[int], enabled: bool) -> List[int]:
    if not enabled:
        return ports
    s = set(ports)
    if 80 in s:
        s.add(8080)
    if 443 in s:
        s.add(8443)
    return sorted(s)


def apply_exclusions(targets: List[str], exclude_spec: str) -> List[str]:
    """Exclude IPs/ranges/CIDRs using same parser for consistency."""
    excluded = set()
    for token in exclude_spec.split(","):
        token = token.strip()
        if not token:
            continue
        for ip in parse_targets(token):
            excluded.add(ip)
    return [t for t in targets if t not in excluded]


def main():
    parser = argparse.ArgumentParser(description="Network scanner + vulnerability checks")

    # Positional
    parser.add_argument(
        "targets",
        nargs="?",
        help="IP, CIDR, range (e.g., 192.168.1.10-20), or file:targets.txt",
        default=None,
    )

    # Common flags
    parser.add_argument("--ports", help="Comma-separated ports (default uses config)", default=None)
    parser.add_argument("--timeout", type=float, help="Connect/service/HTTP/TLS timeout (seconds)", default=None)
    parser.add_argument("--ui", action="store_true", help="Enable interactive terminal UI")
    parser.add_argument("--no-color", action="store_true", help="Disable colorized output")
    parser.add_argument("--html", help="Also save an HTML report to this path", default=None)

    # New capabilities
    parser.add_argument("--profile", choices=list(PROFILES.keys()), help="Use a preset port profile", default=None)
    parser.add_argument("--exclude", help="Comma-separated IPs/ranges/CIDRs to skip", default=None)
    parser.add_argument("--skip-self", action="store_true", help="Skip local IPv4 address(es)")
    parser.add_argument("--rate", choices=["slow", "normal", "fast"], default=None, help="Adjust concurrency via max_workers")
    parser.add_argument("--expand-web-ports", action="store_true", help="Auto-add 8080 if 80 and 8443 if 443 are selected")

    args = parser.parse_args()

    # Prompt if no targets provided
    if not args.targets:
        print("No targets provided. Examples: 192.168.1.254 | 192.168.1.0/24 | 192.168.1.10-20 | file:targets.txt")
        args.targets = input("Enter targets: ").strip()
        if not args.targets:
            parser.error("targets are required (e.g., 192.168.1.10 or 192.168.1.0/24)")

    cfg = ScanConfig()

    # Timeouts
    if args.timeout is not None:
        cfg.connect_timeout = float(args.timeout)
        cfg.service_timeout = float(args.timeout)
        cfg.http_timeout = float(args.timeout)
        cfg.tls_timeout = float(args.timeout)

    # HTML path override
    if args.html:
        cfg.save_html_path = args.html

    # Rate -> max_workers tuning
    if args.rate:
        if args.rate == "slow":
            cfg.max_workers = max(10, cfg.max_workers // 2)
        elif args.rate == "fast":
            cfg.max_workers = max(100, cfg.max_workers * 2)
        # "normal" leaves as-is

    # Ports: profile > explicit list > config default
    if args.profile:
        ports = sorted(set(PROFILES[args.profile]))
    elif args.ports:
        try:
            ports = sorted({int(p.strip()) for p in args.ports.split(",") if p.strip()})
        except Exception:
            print("Invalid ports list.")
            sys.exit(1)
    else:
        ports = list(cfg.default_ports)

    # Optional expansion for web alt ports
    ports = expand_web_ports_if_requested(ports, args.expand_web_ports)

    reporter = Reporter(colorize=not args.no_color)

    # Parse and refine targets
    try:
        targets = parse_targets(args.targets)
    except Exception as e:
        print(f"Invalid targets: {e}")
        sys.exit(1)

    if args.exclude:
        targets = apply_exclusions(targets, args.exclude)

    if args.skip_self:
        self_ips = get_local_ipv4s()
        if self_ips:
            targets = [t for t in targets if t not in self_ips]

    if not targets:
        print("No targets to scan after applying filters.")
        sys.exit(0)

    # UI setup
    use_ui = bool(args.ui and ProgressUI is not None)
    ui = None
    if args.ui and ProgressUI is None:
        print("UI requested but 'rich' or ui module unavailable. Install with: pip install rich")

    if use_ui:
        ui = ProgressUI(total_hosts=len(targets), total_ports=len(ports) * len(targets)) # type: ignore
        ui.start()

    # Scan + vuln checks
    for host in targets:
        if use_ui and ui and ui.stop_requested():
            break

        if use_ui and ui:
            ui.on_host_started(host)
        else:
            print(f"Scanning {host}...")

        open_ports = scan_host_ports(
            host,
            ports,
            timeout=cfg.connect_timeout,
            max_workers=cfg.max_workers,
            on_result=(lambda p, is_open: ui.on_port_result(host, p, is_open)) if use_ui and ui else None,
        )

        reporter.add_open_ports(host, open_ports)

        if use_ui and ui:
            ui.on_host_finished(host, open_ports)
        else:
            if open_ports:
                print(f"{host}: Open ports -> {', '.join(map(str, open_ports))}")
            else:
                print(f"{host}: No open ports found on selected set")

        # Vuln checks with callbacks
        def _stage_cb(stage: str):
            if use_ui and ui:
                ui.on_check(host, stage)

        def _finding_cb(f):
            if use_ui and ui:
                ui.on_finding(host, f)

        findings = run_vuln_checks(
            host,
            open_ports,
            cfg,
            on_progress=_stage_cb,
            on_finding=_finding_cb
        )
        for f in findings:
            reporter.add_finding(**f)

    # Stop UI and output + save reports
    if use_ui and ui:
        ui.stop()

    text_out = reporter.to_text()
    print(text_out)

    if cfg.save_text_path:
        ensure_parent_dir(cfg.save_text_path)
        reporter.save_text(cfg.save_text_path)
    if cfg.save_json_path:
        ensure_parent_dir(cfg.save_json_path)
        reporter.save_json(cfg.save_json_path)
    if cfg.save_html_path:
        ensure_parent_dir(cfg.save_html_path)
        reporter.save_html(cfg.save_html_path)

    saved = []
    if cfg.save_text_path: saved.append(cfg.save_text_path)
    if cfg.save_json_path: saved.append(cfg.save_json_path)
    if cfg.save_html_path: saved.append(cfg.save_html_path)
    if saved:
        print("Reports saved as " + " and ".join(saved))
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Network scan and vulnerability test performed on {args.targets}")


if __name__ == "__main__":
    main()