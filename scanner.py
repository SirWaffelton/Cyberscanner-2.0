# scanner.py
# Target parsing and TCP connect port scanning

from __future__ import annotations
import concurrent.futures
import ipaddress
import os
import socket
from typing import Callable, Iterable, List, Optional


def _expand_range_token(token: str) -> List[str]:
    # Supports a.b.c.start-end (e.g., 192.168.1.10-20)
    try:
        head, tail = token.rsplit(".", 1)
        start_s, end_s = tail.split("-", 1)
        start = int(start_s)
        end = int(end_s)
        if not (0 <= start <= 255 and 0 <= end <= 255) or end < start:
            return []
        base = head + "."
        return [f"{base}{i}" for i in range(start, end + 1)]
    except Exception:
        return []


def _expand_token(token: str) -> List[str]:
    token = token.strip()
    if not token:
        return []
    # CIDR
    try:
        net = ipaddress.ip_network(token, strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception:
        pass
    # Range a.b.c.start-end
    rng = _expand_range_token(token)
    if rng:
        return rng
    # Single IP
    try:
        ipaddress.ip_address(token)
        return [token]
    except Exception:
        pass
    return []


def parse_targets(spec: str) -> List[str]:
    """
    Parse:
      - single IP, CIDR, a.b.c.start-end
      - file:targets.txt (each line can itself be any of the above)
    """
    spec = spec.strip()
    targets: List[str] = []
    if spec.lower().startswith("file:"):
        path = spec.split(":", 1)[1]
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise ValueError(f"Targets file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.extend(_expand_token(line))
    else:
        targets.extend(_expand_token(spec))

    # Deduplicate preserving order
    seen = set()
    deduped = []
    for ip in targets:
        if ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    if not deduped:
        raise ValueError(f"Unable to parse targets from: {spec}")
    return deduped


def _probe_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_host_ports(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.5,
    max_workers: int = 100,
    on_result: Optional[Callable[[int, bool], None]] = None,
) -> List[int]:
    """
    TCP connect-scan. Calls on_result(port, is_open) for each port if provided.
    Returns sorted list of open ports.
    """
    ports_list = sorted(set(int(p) for p in ports if int(p) > 0))
    open_ports: List[int] = []

    def task(p: int) -> None:
        is_open = _probe_port(host, p, timeout)
        if is_open:
            open_ports.append(p)
        if on_result:
            try:
                on_result(p, is_open)
            except Exception:
                pass

    # Limit concurrency per host
    workers = max(1, min(max_workers, len(ports_list)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(task, ports_list))

    return sorted(open_ports)