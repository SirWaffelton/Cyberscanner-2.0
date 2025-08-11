import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Optional deep cert parsing if cryptography is available
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
except Exception:  # pragma: no cover
    x509 = None
    default_backend = None
    rsa = dsa = ec = None


def _is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def inspect_tls(
    host: str,
    port: int = 443,
    server_hostname: Optional[str] = None,
    timeout: float = 4.0
) -> List[Dict]:
    findings: List[Dict] = []

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # manual checks

    sni_host: Optional[str] = server_hostname if server_hostname else (None if _is_ip_literal(host) else host)

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni_host) as ssock:
                proto = ssock.version()  # 'TLSv1.3' / 'TLSv1.2' / 'TLSv1.1' / 'TLSv1' / None
                cert = ssock.getpeercert()  # parsed dict
                now = datetime.now(timezone.utc)

                # Protocol level
                if proto in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "severity": "HIGH",
                        "type": "tls.weak_protocol",
                        "target": f"{host}:{port}",
                        "message": f"Weak protocol negotiated: {proto}",
                        "recommendation": "Disable TLS 1.0/1.1 and enforce TLS 1.2+ (prefer 1.3)."
                    })
                elif proto == "TLSv1.2":
                    findings.append({
                        "severity": "INFO",
                        "type": "tls.protocol",
                        "target": f"{host}:{port}",
                        "message": "Negotiated TLS 1.2",
                        "recommendation": "Enable TLS 1.3 if supported."
                    })
                elif proto == "TLSv1.3":
                    findings.append({
                        "severity": "INFO",
                        "type": "tls.protocol",
                        "target": f"{host}:{port}",
                        "message": "Negotiated TLS 1.3",
                        "recommendation": "Good protocol level."
                    })
                else:
                    findings.append({
                        "severity": "INFO",
                        "type": "tls.protocol_unknown",
                        "target": f"{host}:{port}",
                        "message": "Could not determine negotiated TLS protocol",
                        "recommendation": "Verify TLS configuration; ensure modern protocols are enabled."
                    })

                # Cipher suite advisory
                try:
                    cipher_name, _, bits = ssock.cipher()
                    cn = cipher_name.upper() if cipher_name else "UNKNOWN"
                    if bits and bits < 128:
                        findings.append({
                            "severity": "HIGH",
                            "type": "tls.weak_cipher_bits",
                            "target": f"{host}:{port}",
                            "message": f"Negotiated cipher {cn} with {bits} bits",
                            "recommendation": "Require 128-bit+ ciphers; prefer AES-GCM/CHACHA20-POLY1305."
                        })
                    if any(w in cn for w in ("RC4", "3DES", "DES", "NULL", "EXPORT")):
                        findings.append({
                            "severity": "HIGH",
                            "type": "tls.weak_cipher",
                            "target": f"{host}:{port}",
                            "message": f"Weak/obsolete cipher negotiated: {cn}",
                            "recommendation": "Disable RC4/3DES/DES/NULL/EXPORT ciphers."
                        })
                    elif "RSA_WITH_" in cn and "GCM" not in cn and "CHACHA20" not in cn and proto == "TLSv1.2":
                        findings.append({
                            "severity": "MEDIUM",
                            "type": "tls.rsa_kex_no_pfs",
                            "target": f"{host}:{port}",
                            "message": f"Non-PFS RSA key exchange cipher negotiated: {cn}",
                            "recommendation": "Prefer ECDHE/DHE key exchange (PFS) and AEAD ciphers."
                        })
                    elif "CBC" in cn and proto == "TLSv1.2":
                        findings.append({
                            "severity": "LOW",
                            "type": "tls.cbc_cipher",
                            "target": f"{host}:{port}",
                            "message": f"CBC-mode cipher negotiated: {cn}",
                            "recommendation": "Prefer AEAD ciphers (GCM/CHACHA20) where possible."
                        })
                except Exception:
                    pass

                # If no certificate dict returned, early exit after cipher/proto
                if not cert:
                    findings.append({
                        "severity": "INFO",
                        "type": "tls.no_certificate",
                        "target": f"{host}:{port}",
                        "message": "Peer did not present a certificate (or it could not be parsed)",
                        "recommendation": "Ensure the server presents a valid certificate chain."
                    })
                    return findings

                # Subject/Issuer
                try:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                except Exception:
                    subject = {}
                try:
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                except Exception:
                    issuer = {}

                cn = subject.get("commonName")
                issuer_cn = issuer.get("commonName")

                # SANs
                san = []
                try:
                    san = [v for (typ, v) in cert.get("subjectAltName", ()) if typ in ("DNS", "IP Address")]
                except Exception:
                    pass

                # Expiry
                days_left = None
                not_after = cert.get("notAfter")
                if not_after:
                    parsed = None
                    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %e %H:%M:%S %Y %Z"):
                        try:
                            parsed = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
                            break
                        except ValueError:
                            continue
                    if parsed:
                        days_left = (parsed - now).days

                # Hostname match (use the host if no explicit SNI)
                hostname_ok = True
                try:
                    ssl.match_hostname(cert, server_hostname or host)
                except Exception:
                    hostname_ok = False

                # Self-signed heuristic
                self_signed = False
                if subject and issuer:
                    self_signed = (subject == issuer) or (issuer_cn == cn)

                if self_signed:
                    sev = "MEDIUM" if _is_private_ip(host) else "HIGH"
                    findings.append({
                        "severity": sev,
                        "type": "tls.self_signed",
                        "target": f"{host}:{port}",
                        "message": "Certificate appears self-signed",
                        "recommendation": "Use a CA-signed certificate (public) or an internal PKI (private). Include proper SANs."
                    })

                if days_left is not None:
                    if days_left < 0:
                        findings.append({
                            "severity": "HIGH",
                            "type": "tls.expired",
                            "target": f"{host}:{port}",
                            "message": f"Certificate expired {abs(days_left)} days ago",
                            "recommendation": "Renew the certificate immediately."
                        })
                    elif days_left <= 30:
                        findings.append({
                            "severity": "MEDIUM",
                            "type": "tls.expiring",
                            "target": f"{host}:{port}",
                            "message": f"Certificate expires in {days_left} days",
                            "recommendation": "Plan renewal and set up automated certificate management."
                        })

                if not hostname_ok:
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "tls.hostname_mismatch",
                        "target": f"{host}:{port}",
                        "message": "Certificate does not match the requested hostname",
                        "recommendation": "Include correct DNS names in SAN; avoid CN-only certificates."
                    })

                if not san:
                    findings.append({
                        "severity": "LOW",
                        "type": "tls.missing_san",
                        "target": f"{host}:{port}",
                        "message": "Certificate missing Subject Alternative Names (SAN)",
                        "recommendation": "Issue certificates with SAN entries. CN-only is deprecated."
                    })

                # Deep certificate checks (optional)
                try:
                    if x509 is not None:
                        der = ssock.getpeercert(binary_form=True)
                        cert_obj = x509.load_der_x509_certificate(der, default_backend())
                        pub = cert_obj.public_key()
                        # Key size
                        if rsa is not None and isinstance(pub, rsa.RSAPublicKey):
                            sz = pub.key_size
                            if sz < 2048:
                                findings.append({
                                    "severity": "HIGH",
                                    "type": "tls.rsa_key_too_small",
                                    "target": f"{host}:{port}",
                                    "message": f"RSA key size is {sz} bits",
                                    "recommendation": "Use 2048-bit+ RSA (or ECDSA with P-256+)."
                                })
                            elif sz == 2048:
                                findings.append({
                                    "severity": "INFO",
                                    "type": "tls.rsa_key_size",
                                    "target": f"{host}:{port}",
                                    "message": f"RSA key size: {sz} bits",
                                    "recommendation": "Consider 3072/4096 for long-lived roots; 2048 is acceptable for leaf certs."
                                })
                        # Signature algorithm
                        try:
                            sig_hash = getattr(cert_obj.signature_hash_algorithm, "name", None)
                            if sig_hash in ("md5", "sha1"):
                                findings.append({
                                    "severity": "HIGH",
                                    "type": "tls.weak_signature",
                                    "target": f"{host}:{port}",
                                    "message": f"Certificate signed with weak hash: {sig_hash}",
                                    "recommendation": "Reissue certificates with SHA-256 or stronger."
                                })
                            elif sig_hash:
                                findings.append({
                                    "severity": "INFO",
                                    "type": "tls.signature_hash",
                                    "target": f"{host}:{port}",
                                    "message": f"Certificate signature hash: {sig_hash}",
                                    "recommendation": "Ensure modern signature algorithms are used across the chain."
                                })
                        except Exception:
                            pass
                except Exception:
                    # cryptography not available or parsing failed; ignore
                    pass

    except (ssl.SSLError, socket.error, socket.timeout) as e:
        findings.append({
            "severity": "INFO",
            "type": "tls.connect_error",
            "target": f"{host}:{port}",
            "message": f"TLS connect/get cert failed: {e}",
            "recommendation": "Verify service availability and TLS configuration; increase timeout if needed."
        })

    return findings