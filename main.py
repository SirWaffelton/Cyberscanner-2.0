import scanner
import vuln_tester
from utils import log_event

def main():
    print("=== Network Scanner and Vulnerability Tester ===")
    print("1. Scan Network")
    print("2. Exit")
    
    choice = input("Enter Choice: ").strip()
    
    if choice == "1":
        ip_input = input("Enter IP (single, range, or CIDR): ").strip()
        # Common ports to scan
        common_ports = [22, 80, 443, 8080]

        print(f"Scanning IPs {ip_input} on ports {common_ports} ...")
        ip_list = scanner.parse_ip_input(ip_input)
        results = scanner.scan_network(ip_list, common_ports)
        
        if results:
            print("\nScan Results:")
            for ip, ports in results.items():
                if ports:
                    ports_str = ", ".join(str(p) for p in ports)
                    print(f"- {ip}: Open ports -> {ports_str}")
                else:
                    print(f"- {ip}: No open ports found")
            # Run vulnerability tests on discovered hosts with open ports
            for ip, ports in results.items():
                vuln_tester.check_vulnerabilities(ip, ports)
        else:
            print("No active hosts found in the specified range.")
        
        log_event(f"Network scan and vulnerability test performed on {ip_input}")
    
    elif choice == "2":
        print("Exiting...")
    else:
        print("Invalid Choice")

if __name__ == "__main__":
    main()
