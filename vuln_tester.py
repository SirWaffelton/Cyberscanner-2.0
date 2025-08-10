import ssl
import socket
from datetime import datetime
import requests
from urllib.parse import urlparse

def get_ssl_certificate(hostname, port=443):
    """
    Fetch SSL certificate details for a given hostname and port.
    """
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=3) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            tls_version = ssock.version()
    return cert, tls_version

def check_certificate(cert):
    """
    Check if SSL certificate is valid, expired, or self-signed.
    Returns messages about certificate status.
    """
    messages = []
    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    now = datetime.utcnow()

    if now < not_before:
        messages.append(f"Certificate is not valid before {not_before}")
    if now > not_after:
        messages.append(f"Certificate expired on {not_after}")
    # Self-signed detection is tricky without third-party libs,
    # but we can check if issuer == subject as a heuristic:
    if cert.get('issuer') == cert.get('subject'):
        messages.append("Certificate appears to be self-signed")
    if not messages:
        messages.append("Certificate is valid and not self-signed")
    return messages

def check_ssh_banner(ip):
    port = 22
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        if banner:
            print(f"- Port {port} (SSH): Banner found - {banner}")
        else:
            print(f"- Port {port} (SSH): No banner received")
    except Exception as e:
        print(f"- Port {port} (SSH): Connection failed ({e})")

def check_security_headers(url):
    """
    Check common security headers in HTTP(S) response.
    Returns messages about missing or present headers.
    """
    try:
        response = requests.get(url, timeout=3, verify=False)
        headers = response.headers
    except Exception as e:
        return [f"Failed to fetch headers: {e}"]

    results = []

    # Check for HSTS
    if 'strict-transport-security' in headers:
        results.append("HSTS header is present")
    else:
        results.append("HSTS header is missing")

    # Check for Content Security Policy
    if 'content-security-policy' in headers:
        results.append("Content-Security-Policy header is present")
    else:
        results.append("Content-Security-Policy header is missing")

    # Check for X-Content-Type-Options
    if 'x-content-type-options' in headers:
        results.append("X-Content-Type-Options header is present")
    else:
        results.append("X-Content-Type-Options header is missing")

    # Check for X-Frame-Options
    if 'x-frame-options' in headers:
        results.append("X-Frame-Options header is present")
    else:
        results.append("X-Frame-Options header is missing")

    # Check for Server header (outdated server disclosure)
    server = headers.get('server')
    if server:
        results.append(f"Server header found: {server}")
    else:
        results.append("No Server header found")

    return results

def check_http_dir_listing(ip, port):
    url = f"http://{ip}:{port}/"
    try:
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200 and ("Index of" in resp.text or "<title>Directory listing for" in resp.text):
            print(f"- Port {port} (HTTP): Directory listing enabled at {url}")
        else:
            print(f"- Port {port} (HTTP): No directory listing detected")
    except Exception as e:
        print(f"- Port {port} (HTTP): Request failed ({e})")

def check_vulnerabilities(ip, open_ports):
    print(f"Checking vulnerabilities on {ip}:")
    for port in open_ports:
        if port == 80:
            url = f"http://{ip}"
            # Your existing directory listing check here (keep it)

            # Add HTTP security headers check
            headers_results = check_security_headers(url)
            for msg in headers_results:
                print(f"- Port 80 (HTTP): {msg}")

        elif port == 443:
            url = f"https://{ip}"
            try:
                cert, tls_version = get_ssl_certificate(ip, 443)
                cert_messages = check_certificate(cert)
                print(f"- Port 443 (HTTPS): TLS version {tls_version}")
                for msg in cert_messages:
                    print(f"  * {msg}")

                headers_results = check_security_headers(url)
                for msg in headers_results:
                    print(f"  * {msg}")

            except Exception as e:
                print(f"- Port 443 (HTTPS): Failed to get SSL info: {e}")

        else:
            print(f"- Port {port}: No vulnerability checks implemented for this port.")
