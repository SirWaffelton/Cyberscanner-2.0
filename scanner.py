import subprocess
import ipaddress
import platform
import socket
from typing import List, Dict

def parse_ip_input(ip_input: str) -> List[str]:
    """
    Parses an IP input string and returns a list of IP addresses.
    Supports:
    - Single IP (e.g. 192.168.1.5)
    - IP range (e.g. 192.168.1.1-192.168.1.20)
    - CIDR notation (e.g. 192.168.1.0/24)
    """
    ip_list = []
    ip_input = ip_input.strip()
    
    if '-' in ip_input:
        # IP range
        start_ip_str, end_ip_str = ip_input.split('-')
        start_ip = ipaddress.IPv4Address(start_ip_str.strip())
        end_ip = ipaddress.IPv4Address(end_ip_str.strip())
        if start_ip > end_ip:
            raise ValueError("Start IP must be less than or equal to End IP")
        ip_list = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]
    elif '/' in ip_input:
        # CIDR notation
        network = ipaddress.IPv4Network(ip_input, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]  # hosts() excludes network and broadcast addresses
    else:
        # Single IP
        ip = ipaddress.IPv4Address(ip_input)
        ip_list = [str(ip)]
    
    return ip_list

def ping(ip: str) -> bool:
    """
    Ping an IP address to check if it is active.
    Returns True if host responds, False otherwise.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    try:
        output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return output.returncode == 0
    except Exception:
        return False

def scan_ports(ip: str, ports: List[int]) -> List[int]:
    """
    Scan specified ports on the given IP.
    Return list of open ports.
    """
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.7)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

def scan_network(ip_list: List[str], ports: List[int]) -> Dict[str, List[int]]:
    """
    Scan a list of IPs, ping sweep + port scan.
    Return dict: {ip: [open_ports]} for active hosts.
    """
    scanned_results = {}
    for ip in ip_list:
        if ping(ip):
            open_ports = scan_ports(ip, ports)
            scanned_results[ip] = open_ports
    return scanned_results

def run_scan(ip_input: str, ports: List[int]):
    """
    Parses IP input, scans network, and prints results.
    """
    try:
        ip_list = parse_ip_input(ip_input)
    except ValueError as e:
        print(f"Invalid IP input: {e}")
        return

    results = scan_network(ip_list, ports)

    if not results:
        print("No active hosts found.")
    else:
        for ip, open_ports in results.items():
            ports_str = ", ".join(str(p) for p in open_ports) if open_ports else "None"
            print(f"{ip} is active. Open ports: {ports_str}")
