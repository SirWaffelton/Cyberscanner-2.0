import argparse
import sys
import time

from config import ScanConfig
from reporter import Reporter
from scanner import parse_targets, scan_host_ports
from vuln_tester import run_vuln_checks

# Optional UI
try:
    from ui import ProgressUI
except Exception:
    ProgressUI = None  # type: ignore


def main():
    parser = argparse.ArgumentParser(description="Network scanner + vulnerability checks")
    parser.add_argument("targets", nargs="?", help="Target spec (IP, CIDR, range like 192.168.1.10-20, or file:targets.txt)", default=None)
    parser.add_argument("--ports", help="Comma-separated ports (default uses config)", default=None)
    parser.add_argument("--no-color", action="store_true", help="Disable colorized console output")
    parser.add_argument("--html", help="Also save HTML report to this path", default=None)
    parser.add_argument("--timeout", type=float, help="Connect timeout (seconds)", default=None)
    parser.add_argument("--ui", action="store_true", help="Show interactive terminal UI (progress + logs)")
    args = parser.parse_args()

    if not args.targets:
        print("No targets provided. Examples: 192.168.1.254 | 192.168.1.0/24 | 192.168.1.10-20 | file:targets.txt")
        args.targets = input("Enter targets: ").strip()
        if not args.targets:
            parser.error("targets are required (e.g., 192.168.1.10 or 192.168.1.0/24)")

    cfg = ScanConfig()
    if args.timeout is not None:
        cfg.connect_timeout = cfg.service_timeout = cfg.http_timeout = float(args.timeout)
    if args.html:
        cfg.save_html_path = args.html

    # Ports selection
    if args.ports:
        try:
            ports = sorted({int(p.strip()) for p in args.ports.split(",") if p.strip()})
        except Exception:
            print("Invalid ports list.")
            sys.exit(1)
    else:
        ports = cfg.default_ports

    reporter = Reporter(colorize=not args.no_color)

    try:
        targets = parse_targets(args.targets)
    except Exception as e:
        print(f"Invalid targets: {e}")
        sys.exit(1)

    use_ui = bool(args.ui and ProgressUI is not None)
    ui = None
    if args.ui and ProgressUI is None:
        print("UI requested but 'rich' or ui module unavailable. Install with: pip install rich")
    if use_ui:
        ui = ProgressUI(total_hosts=len(targets), total_ports=len(ports) * len(targets))
        ui.start()

    for host in targets:
        if use_ui and ui and ui.stop_requested():
            break

        if use_ui and ui:
            ui.on_host_started(host)
        else:
            print(f"Scanning {host}...")

        # Scan ports with progress callback
        open_ports = scan_host_ports(
            host,
            ports,
            timeout=cfg.connect_timeout,
            max_workers=cfg.max_workers,
            on_result=(lambda p, is_open: ui.on_port_result(host, p, is_open)) if use_ui and ui else None,
        )

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

        findings = run_vuln_checks(host, open_ports, cfg, on_progress=_stage_cb, on_finding=_finding_cb)
        for f in findings:
            reporter.add_finding(**f)

    # Stop UI before printing the final report text
    if use_ui and ui:
        ui.stop()

    # Output report to console (text)
    print(reporter.to_text())

    # Save reports
    if cfg.save_text_path:
        reporter.save_text(cfg.save_text_path)
    if cfg.save_json_path:
        reporter.save_json(cfg.save_json_path)
    if cfg.save_html_path:
        reporter.save_html(cfg.save_html_path)

    print(f"Reports saved as {cfg.save_text_path} and {cfg.save_json_path}" + (f" and {cfg.save_html_path}" if cfg.save_html_path else ""))
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Network scan and vulnerability test performed on {args.targets}")


if __name__ == "__main__":
    main()