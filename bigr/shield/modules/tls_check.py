"""TLS validation module using Python stdlib ssl and socket."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.request import urlopen, Request

from bigr.shield.models import FindingSeverity, ShieldFinding
from bigr.shield.modules.base import ScanModule

# Weak cipher suites that should be flagged
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED", "MD5",
}

# Days before expiry to warn
EXPIRY_WARNING_DAYS = 30

# Connection timeout in seconds
DEFAULT_TIMEOUT = 5


def _is_weak_cipher(cipher_name: str) -> bool:
    """Check if a cipher suite name contains weak algorithm indicators."""
    upper = cipher_name.upper()
    for weak in WEAK_CIPHERS:
        if weak.upper() in upper:
            return True
    return False


def _check_san_match(cert: dict, target: str) -> bool:
    """Check if target matches any Subject Alternative Name or Common Name."""
    # Check SANs first
    san_entries = cert.get("subjectAltName", ())
    for san_type, san_value in san_entries:
        if san_type.lower() == "dns":
            if _hostname_matches(san_value, target):
                return True
        elif san_type.lower() == "ip address":
            if san_value == target:
                return True

    # Fall back to CN
    subject = cert.get("subject", ())
    for rdn in subject:
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                if _hostname_matches(attr_value, target):
                    return True

    return False


def _hostname_matches(pattern: str, hostname: str) -> bool:
    """Check if a hostname matches a certificate pattern (supports wildcards)."""
    pattern = pattern.lower()
    hostname = hostname.lower()

    if pattern == hostname:
        return True

    # Wildcard match: *.example.com matches foo.example.com but not foo.bar.example.com
    if pattern.startswith("*."):
        pattern_suffix = pattern[2:]
        # hostname must have exactly one more label
        if hostname.endswith("." + pattern_suffix):
            prefix = hostname[: -(len(pattern_suffix) + 1)]
            if "." not in prefix:
                return True

    return False


class TLSCheckModule(ScanModule):
    """TLS/SSL certificate and configuration validation module."""

    name: str = "tls"
    weight: int = 20

    def check_available(self) -> bool:
        """SSL stdlib is always available."""
        return True

    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Run TLS checks against the target.

        Checks performed:
        1. Certificate validity (expired / expiring soon)
        2. Certificate chain verification
        3. Protocol version (TLS 1.0/1.1 = critical)
        4. Key size (< 2048 = high)
        5. Self-signed detection
        6. HSTS header check
        7. Cipher suite strength
        8. CN/SAN match with target
        """
        findings: list[ShieldFinding] = []
        actual_port = port or 443

        # Step 1: Connect and retrieve certificate info
        cert_info: dict | None = None
        cipher_info: tuple | None = None
        protocol_version: str | None = None
        peer_cert_der: bytes | None = None

        try:
            ctx = ssl.create_default_context()
            # We want to inspect even problematic certs, so disable verification
            # for info gathering, then check separately
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, actual_port), timeout=DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_info = ssock.getpeercert(binary_form=False)
                    peer_cert_der = ssock.getpeercert(binary_form=True)
                    cipher_info = ssock.cipher()
                    protocol_version = ssock.version()

        except socket.timeout:
            findings.append(ShieldFinding(
                module="tls",
                severity=FindingSeverity.MEDIUM,
                title="TLS Connection Timeout",
                description=f"Connection to {target}:{actual_port} timed out after {DEFAULT_TIMEOUT}s.",
                remediation="Verify the target is reachable and the port is open.",
                target_ip=target,
                target_port=actual_port,
                evidence={"error": "timeout"},
            ))
            return findings
        except ConnectionRefusedError:
            findings.append(ShieldFinding(
                module="tls",
                severity=FindingSeverity.MEDIUM,
                title="TLS Connection Refused",
                description=f"Connection to {target}:{actual_port} was refused.",
                remediation="Verify TLS service is running on the target port.",
                target_ip=target,
                target_port=actual_port,
                evidence={"error": "connection_refused"},
            ))
            return findings
        except socket.gaierror:
            findings.append(ShieldFinding(
                module="tls",
                severity=FindingSeverity.HIGH,
                title="DNS Resolution Failure",
                description=f"Could not resolve hostname: {target}",
                remediation="Verify the domain name is correct and DNS is reachable.",
                target_ip=target,
                target_port=actual_port,
                evidence={"error": "dns_resolution_failed"},
            ))
            return findings
        except ssl.SSLError as exc:
            findings.append(ShieldFinding(
                module="tls",
                severity=FindingSeverity.HIGH,
                title="SSL/TLS Error",
                description=f"SSL error connecting to {target}:{actual_port}: {exc}",
                remediation="Check the TLS configuration of the target service.",
                target_ip=target,
                target_port=actual_port,
                evidence={"error": str(exc)},
            ))
            return findings
        except OSError as exc:
            findings.append(ShieldFinding(
                module="tls",
                severity=FindingSeverity.MEDIUM,
                title="Connection Error",
                description=f"Could not connect to {target}:{actual_port}: {exc}",
                remediation="Verify network connectivity to the target.",
                target_ip=target,
                target_port=actual_port,
                evidence={"error": str(exc)},
            ))
            return findings

        # If we got no cert info at all (CERT_NONE can return empty dict), record it
        if not cert_info and not peer_cert_der:
            findings.append(ShieldFinding(
                module="tls",
                severity=FindingSeverity.HIGH,
                title="No Certificate Presented",
                description=f"The server at {target}:{actual_port} did not present a certificate.",
                remediation="Configure a valid TLS certificate on the server.",
                target_ip=target,
                target_port=actual_port,
            ))
            return findings

        # If getpeercert(False) returned empty but DER is available, we have a
        # cert that couldn't be parsed in non-binary mode (e.g. self-signed with
        # CERT_NONE). We still attempt the checks we can.

        # Step 2: Certificate verification (separate pass with full verification)
        chain_valid = True
        chain_error: str | None = None
        try:
            verify_ctx = ssl.create_default_context()
            with socket.create_connection((target, actual_port), timeout=DEFAULT_TIMEOUT) as sock:
                with verify_ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    # If we get here, chain is valid and hostname matches
                    # Also grab the cert with verification enabled
                    verified_cert = ssock.getpeercert(binary_form=False)
                    if verified_cert and not cert_info:
                        cert_info = verified_cert
        except ssl.SSLCertVerificationError as exc:
            chain_valid = False
            chain_error = str(exc)
        except (OSError, ssl.SSLError):
            # Can't verify chain (network issue on second connection)
            chain_valid = False
            chain_error = "Unable to verify certificate chain (connection failed on verification pass)"

        if not chain_valid:
            # Determine if self-signed
            is_self_signed = False
            if cert_info:
                issuer = cert_info.get("issuer", ())
                subject = cert_info.get("subject", ())
                if issuer == subject:
                    is_self_signed = True

            if is_self_signed:
                findings.append(ShieldFinding(
                    module="tls",
                    severity=FindingSeverity.HIGH,
                    title="Self-Signed Certificate",
                    description=(
                        f"The certificate for {target} is self-signed. "
                        "Clients will not trust this certificate by default."
                    ),
                    remediation="Replace with a certificate signed by a trusted Certificate Authority.",
                    target_ip=target,
                    target_port=actual_port,
                    evidence={"self_signed": True, "chain_error": chain_error},
                    attack_technique="T1557",
                    attack_tactic="Credential Access",
                ))
            else:
                findings.append(ShieldFinding(
                    module="tls",
                    severity=FindingSeverity.HIGH,
                    title="Certificate Chain Verification Failed",
                    description=f"Certificate chain verification failed for {target}: {chain_error}",
                    remediation=(
                        "Ensure the server sends the full certificate chain including intermediate CAs."
                    ),
                    target_ip=target,
                    target_port=actual_port,
                    evidence={"chain_error": chain_error},
                ))

        # Step 3: Certificate expiry check
        if cert_info:
            not_after_str = cert_info.get("notAfter")
            if not_after_str:
                try:
                    # Python ssl module returns dates like 'Jan  5 00:00:00 2025 GMT'
                    not_after = _parse_ssl_date(not_after_str)
                    now = datetime.now(timezone.utc)
                    days_remaining = (not_after - now).days

                    if days_remaining < 0:
                        findings.append(ShieldFinding(
                            module="tls",
                            severity=FindingSeverity.CRITICAL,
                            title="Certificate Expired",
                            description=(
                                f"The certificate for {target} expired {abs(days_remaining)} days ago "
                                f"(expiry: {not_after.isoformat()})."
                            ),
                            remediation="Renew the TLS certificate immediately.",
                            target_ip=target,
                            target_port=actual_port,
                            evidence={
                                "not_after": not_after.isoformat(),
                                "days_remaining": days_remaining,
                            },
                        ))
                    elif days_remaining <= EXPIRY_WARNING_DAYS:
                        findings.append(ShieldFinding(
                            module="tls",
                            severity=FindingSeverity.MEDIUM,
                            title="Certificate Expiring Soon",
                            description=(
                                f"The certificate for {target} expires in {days_remaining} days "
                                f"(expiry: {not_after.isoformat()})."
                            ),
                            remediation=f"Renew the TLS certificate before {not_after.date().isoformat()}.",
                            target_ip=target,
                            target_port=actual_port,
                            evidence={
                                "not_after": not_after.isoformat(),
                                "days_remaining": days_remaining,
                            },
                        ))
                except (ValueError, TypeError):
                    pass

        # Step 4: Protocol version check
        if protocol_version:
            if protocol_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                findings.append(ShieldFinding(
                    module="tls",
                    severity=FindingSeverity.CRITICAL,
                    title="Deprecated TLS Protocol Version",
                    description=(
                        f"The server negotiated {protocol_version}, which is deprecated and insecure."
                    ),
                    remediation="Disable TLS 1.0, TLS 1.1, and all SSL versions. Use TLS 1.2 or TLS 1.3.",
                    target_ip=target,
                    target_port=actual_port,
                    evidence={"protocol_version": protocol_version},
                    attack_technique="T1040",
                    attack_tactic="Credential Access",
                ))

        # Step 5: Key size check
        if cert_info:
            # The key size is not directly in getpeercert() dict, but we can
            # try to extract from the DER cert if cryptography is available,
            # otherwise skip this check.
            key_bits = _extract_key_bits(peer_cert_der)
            if key_bits is not None and key_bits < 2048:
                findings.append(ShieldFinding(
                    module="tls",
                    severity=FindingSeverity.HIGH,
                    title="Weak Certificate Key Size",
                    description=f"The certificate uses a {key_bits}-bit key, which is below the recommended 2048-bit minimum.",
                    remediation="Generate a new certificate with at least a 2048-bit RSA key or 256-bit ECDSA key.",
                    target_ip=target,
                    target_port=actual_port,
                    evidence={"key_bits": key_bits},
                ))

        # Step 6: Cipher suite check
        if cipher_info:
            cipher_name = cipher_info[0]
            if _is_weak_cipher(cipher_name):
                findings.append(ShieldFinding(
                    module="tls",
                    severity=FindingSeverity.HIGH,
                    title="Weak Cipher Suite",
                    description=f"The negotiated cipher suite '{cipher_name}' uses weak cryptographic algorithms.",
                    remediation="Disable weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, anonymous).",
                    target_ip=target,
                    target_port=actual_port,
                    evidence={
                        "cipher_name": cipher_name,
                        "protocol": cipher_info[1] if len(cipher_info) > 1 else None,
                        "bits": cipher_info[2] if len(cipher_info) > 2 else None,
                    },
                    attack_technique="T1557",
                    attack_tactic="Credential Access",
                ))

        # Step 7: CN/SAN match check
        if cert_info:
            if not _check_san_match(cert_info, target):
                findings.append(ShieldFinding(
                    module="tls",
                    severity=FindingSeverity.MEDIUM,
                    title="Certificate Name Mismatch",
                    description=f"The certificate does not match the target hostname '{target}'.",
                    remediation="Obtain a certificate that includes the correct hostname in the SAN field.",
                    target_ip=target,
                    target_port=actual_port,
                    evidence={
                        "target": target,
                        "san": [
                            f"{t}:{v}" for t, v in cert_info.get("subjectAltName", ())
                        ],
                    },
                ))

        # Step 8: HSTS header check
        hsts_finding = _check_hsts(target, actual_port)
        if hsts_finding is not None:
            findings.append(hsts_finding)

        return findings


def _parse_ssl_date(date_str: str) -> datetime:
    """Parse ssl module date string like 'Jan  5 00:00:00 2025 GMT'."""
    import email.utils
    # Try the standard ssl format
    # ssl module uses: '%b %d %H:%M:%S %Y GMT'
    try:
        parsed = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # Try with double-space day (e.g., 'Jan  5')
    try:
        parsed = datetime.strptime(date_str.replace("  ", " "), "%b %d %H:%M:%S %Y %Z")
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # Last resort: email.utils
    ts = email.utils.parsedate_to_datetime(date_str)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def _extract_key_bits(cert_der: bytes | None) -> int | None:
    """Try to extract key bit length from DER-encoded certificate.

    Uses the cryptography library if available, otherwise returns None.
    This is a best-effort check -- we don't add external dependencies.
    """
    if cert_der is None:
        return None
    try:
        from cryptography.x509 import load_der_x509_certificate
        cert = load_der_x509_certificate(cert_der)
        return cert.public_key().key_size
    except Exception:
        return None


def _check_hsts(target: str, port: int) -> ShieldFinding | None:
    """Check for HTTP Strict Transport Security header."""
    try:
        url = f"https://{target}:{port}/" if port != 443 else f"https://{target}/"
        req = Request(url, method="HEAD")
        # We need to ignore cert errors for the HSTS check since the target
        # may have a self-signed cert
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urlopen(req, timeout=DEFAULT_TIMEOUT, context=ctx) as resp:
            hsts = resp.headers.get("Strict-Transport-Security")
            if not hsts:
                return ShieldFinding(
                    module="tls",
                    severity=FindingSeverity.LOW,
                    title="HSTS Header Missing",
                    description=(
                        f"The server at {target} does not send the "
                        "Strict-Transport-Security header."
                    ),
                    remediation=(
                        "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                    ),
                    target_ip=target,
                    target_port=port,
                    evidence={"hsts_present": False},
                )
    except Exception:
        # HSTS check is best-effort; don't fail the scan for it
        pass
    return None
