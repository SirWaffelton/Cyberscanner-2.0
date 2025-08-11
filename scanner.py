import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Optional, Set


def parse_targets(spec: str) -> List[str]:
    """
    Accepts:
      - Single IP: 192.168.1.10
      - CIDR: 192.168.1.0/24
      - Range: 192.168.1.10-20
      - File: file:targets.txt (one IP/CIDR/range per line)
    """
    targets: Set[str] = set()

    def add_range(base: str, start: int, end: int):
        for last in range(start, end + 1):
            targets.add(".".join(base.split(".")[:3] + [str(last)]))

    if spec.startswith("file:"):
        path = spec[5:]
        with open(path, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        for line in lines:
            targets.update(parse_targets(line))
        return sorted(targets)

    if "-" in spec and "/" not in spec:
        base, rng = spec.rsplit(".", 1)
        start, end = rng.split("-")
        add_range(base + ".", int(start), int(end))
    elif "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        for ip in net.hosts():
            targets.add(str(ip))
    else:
        ipaddress.ip_address(spec)  # validate
        targets.add(spec)

    return sorted(targets)


def probe_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan_host_ports(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    max_workers: int = 200,
    on_result: Optional[Callable[[int, bool], None]] = None,
) -> List[int]:
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(probe_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                result = fut.result()
                if on_result:
                    try:
                        on_result(p, result)
                    except Exception:
                        pass
                if result:
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)