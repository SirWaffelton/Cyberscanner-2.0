# discovery.py
# Simple host discovery via ping sweep and/or ARP table

from __future__ import annotations
import concurrent.futures
import re
import subprocess
from typing import Iterable, List, Set

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def _ping_once(ip: str, timeout_ms: int = 400) -> bool:
    # Windows: ping -n 1 -w 400 <ip>; returncode 0 -> success
    try:
        res = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True,
            text=True
        )
        return res.returncode == 0
    except Exception:
        return False

def ping_sweep(ips: Iterable[str], timeout_ms: int = 400, workers: int = 64) -> List[str]:
    ips_list = list(ips)
    live: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_ping_once, ip, timeout_ms): ip for ip in ips_list}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            ok = False
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                live.append(ip)
    return sorted(live)

def read_arp_ips() -> Set[str]:
    ips: Set[str] = set()
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        out = res.stdout
        for line in out.splitlines():
            m = IP_RE.search(line)
            if m:
                ips.add(m.group(0))
    except Exception:
        pass
    return ips

def discover_live_hosts(targets: Iterable[str], mode: str = "none", timeout_ms: int = 400) -> List[str]:
    """
    mode: "none" | "ping" | "arp" | "auto"
    - ping: return only IPs that responded to one ping
    - arp: return IPs that appear in the ARP table
    - auto: union of ping-responding IPs and ARP entries intersected with targets
    """
    ips = list(targets)
    if mode == "none":
        return ips
    if mode == "ping":
        return ping_sweep(ips, timeout_ms=timeout_ms)
    if mode == "arp":
        arp_ips = read_arp_ips()
        return sorted([ip for ip in ips if ip in arp_ips])
    if mode == "auto":
        live = set(ping_sweep(ips, timeout_ms=timeout_ms))
        arp_ips = read_arp_ips()
        for ip in ips:
            if ip in arp_ips:
                live.add(ip)
        return sorted(live)
    # Fallback
    return ips