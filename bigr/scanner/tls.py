"""TLS certificate discovery and monitoring."""

from __future__ import annotations

import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class CertificateInfo:
    """Parsed TLS certificate information."""

    ip: str
    port: int
    cn: str | None = None  # Common Name
    san: list[str] = field(default_factory=list)  # Subject Alt Names
    issuer: str | None = None
    issuer_org: str | None = None
    valid_from: str | None = None  # ISO datetime
    valid_to: str | None = None  # ISO datetime
    serial: str | None = None
    key_size: int | None = None  # e.g., 2048, 4096
    key_algorithm: str | None = None  # "RSA", "ECDSA", "Ed25519"
    signature_algorithm: str | None = None
    is_self_signed: bool = False
    is_expired: bool = False
    days_until_expiry: int | None = None

    @property
    def expiry_status(self) -> str:
        """Return expiry status: 'expired', 'critical', 'warning', 'ok'."""
        if self.is_expired:
            return "expired"
        if self.days_until_expiry is not None:
            if self.days_until_expiry <= 7:
                return "critical"
            if self.days_until_expiry <= 30:
                return "warning"
        return "ok"

    @property
    def security_issues(self) -> list[str]:
        """List security concerns with this certificate."""
        issues: list[str] = []
        if self.is_expired:
            issues.append("Certificate is expired")
        if self.is_self_signed:
            issues.append("Self-signed certificate")
        if self.key_size is not None and self.key_size < 2048:
            issues.append(f"Weak key size ({self.key_size} bits)")
        if (
            self.days_until_expiry is not None
            and self.days_until_expiry <= 30
            and not self.is_expired
        ):
            issues.append(f"Expiring in {self.days_until_expiry} days")
        if self.key_algorithm and self.key_algorithm.upper() in ("SHA1", "MD5"):
            issues.append(f"Weak signature algorithm: {self.key_algorithm}")
        return issues

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "ip": self.ip,
            "port": self.port,
            "cn": self.cn,
            "san": self.san,
            "issuer": self.issuer,
            "issuer_org": self.issuer_org,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "serial": self.serial,
            "key_size": self.key_size,
            "key_algorithm": self.key_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "is_self_signed": self.is_self_signed,
            "is_expired": self.is_expired,
            "days_until_expiry": self.days_until_expiry,
            "expiry_status": self.expiry_status,
            "security_issues": self.security_issues,
        }


@dataclass
class CertScanResult:
    """Result of scanning multiple assets for TLS certificates."""

    certificates: list[CertificateInfo] = field(default_factory=list)
    total_scanned: int = 0
    total_certs_found: int = 0
    expired_count: int = 0
    expiring_soon_count: int = 0  # within 30 days
    self_signed_count: int = 0
    weak_key_count: int = 0

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "certificates": [c.to_dict() for c in self.certificates],
            "total_scanned": self.total_scanned,
            "total_certs_found": self.total_certs_found,
            "expired_count": self.expired_count,
            "expiring_soon_count": self.expiring_soon_count,
            "self_signed_count": self.self_signed_count,
            "weak_key_count": self.weak_key_count,
        }


# Common TLS ports to scan
TLS_PORTS = [443, 8443, 993, 995, 636, 8883, 9443]


# SSL date format: 'Mon DD HH:MM:SS YYYY GMT'
_SSL_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_ssl_date(date_str: str) -> datetime | None:
    """Parse an SSL date string to a timezone-aware datetime."""
    if not date_str:
        return None
    try:
        # Handle extra spaces in single-digit days (e.g., 'Jan  1' vs 'Jan 01')
        normalized = " ".join(date_str.split())
        dt = datetime.strptime(normalized, _SSL_DATE_FMT)
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _extract_field_from_dn(dn_tuple: tuple | None, field: str) -> str | None:
    """Extract a field value from an SSL subject/issuer distinguished name tuple.

    The format from getpeercert() is: ((('fieldName', 'value'),), ...)
    """
    if not dn_tuple:
        return None
    for rdn in dn_tuple:
        for attr_type, attr_value in rdn:
            if attr_type == field:
                return attr_value
    return None


def parse_certificate(cert_dict: dict, ip: str, port: int) -> CertificateInfo:
    """Parse a certificate dict (from ssl.getpeercert()) into CertificateInfo.

    The cert_dict format matches Python's ssl.SSLSocket.getpeercert() output:
    {
        'subject': ((('commonName', 'example.com'),),),
        'issuer': ((('organizationName', 'Let\\'s Encrypt'),), (('commonName', 'R3'),)),
        'notBefore': 'Jan  1 00:00:00 2026 GMT',
        'notAfter': 'Apr  1 00:00:00 2026 GMT',
        'serialNumber': 'ABCDEF123456',
        'subjectAltName': (('DNS', 'example.com'), ('DNS', '*.example.com')),
    }
    """
    subject = cert_dict.get("subject")
    issuer = cert_dict.get("issuer")

    cn = _extract_field_from_dn(subject, "commonName")
    issuer_cn = _extract_field_from_dn(issuer, "commonName")
    issuer_org = _extract_field_from_dn(issuer, "organizationName")

    # Parse dates
    not_before_str = cert_dict.get("notBefore", "")
    not_after_str = cert_dict.get("notAfter", "")
    not_before = _parse_ssl_date(not_before_str)
    not_after = _parse_ssl_date(not_after_str)

    valid_from = not_before.isoformat() if not_before else None
    valid_to = not_after.isoformat() if not_after else None

    # Calculate expiry
    days_until = None
    is_expired = False
    if not_after:
        days_until = calculate_days_until_expiry(not_after_str)
        is_expired = days_until < 0

    # SAN extraction
    san: list[str] = []
    san_data = cert_dict.get("subjectAltName", ())
    for san_type, san_value in san_data:
        if san_type == "DNS":
            san.append(san_value)

    # Self-signed detection
    self_signed = is_cert_self_signed(cn, issuer_cn)

    serial = cert_dict.get("serialNumber")

    return CertificateInfo(
        ip=ip,
        port=port,
        cn=cn,
        san=san,
        issuer=issuer_cn,
        issuer_org=issuer_org,
        valid_from=valid_from,
        valid_to=valid_to,
        serial=serial,
        is_self_signed=self_signed,
        is_expired=is_expired,
        days_until_expiry=days_until,
    )


def calculate_days_until_expiry(not_after: str) -> int:
    """Calculate days until certificate expiry from 'notAfter' string.

    Format: 'Apr  1 00:00:00 2026 GMT'
    """
    expiry = _parse_ssl_date(not_after)
    if expiry is None:
        return 0
    now = datetime.now(timezone.utc)
    delta = expiry - now
    return delta.days


def is_cert_self_signed(subject_cn: str | None, issuer_cn: str | None) -> bool:
    """Determine if a certificate is self-signed (subject CN == issuer CN)."""
    if subject_cn is None or issuer_cn is None:
        return False
    return subject_cn.lower() == issuer_cn.lower()


def scan_host_certificates(
    ip: str, ports: list[int] | None = None, timeout: float = 3.0
) -> list[CertificateInfo]:
    """Scan a single host for TLS certificates on given ports.

    Uses ssl.create_default_context() with check_hostname disabled.
    """
    if ports is None:
        ports = TLS_PORTS

    results: list[CertificateInfo] = []

    for port in ports:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert_dict = ssock.getpeercert(binary_form=False)
                    if cert_dict:
                        info = parse_certificate(cert_dict, ip, port)
                        results.append(info)
        except (OSError, ssl.SSLError, socket.timeout, ConnectionRefusedError):
            continue

    return results


def scan_all_certificates(
    assets: list[dict], ports: list[int] | None = None
) -> CertScanResult:
    """Scan all assets for TLS certificates.

    For each asset, check TLS_PORTS plus any HTTPS ports from open_ports.
    """
    all_certs: list[CertificateInfo] = []
    total_scanned = 0

    for asset in assets:
        ip = asset.get("ip", "")
        if not ip:
            continue

        # Build port list: default TLS ports + any open HTTPS-like ports
        scan_ports = set(ports or TLS_PORTS)
        for p in asset.get("open_ports", []):
            if p in (443, 8443, 993, 995, 636, 8883, 9443):
                scan_ports.add(p)

        total_scanned += 1
        certs = scan_host_certificates(ip, ports=sorted(scan_ports))
        all_certs.extend(certs)

    # Calculate summary counts
    expired_count = sum(1 for c in all_certs if c.is_expired)
    expiring_soon_count = sum(
        1
        for c in all_certs
        if c.days_until_expiry is not None
        and 0 <= c.days_until_expiry <= 30
        and not c.is_expired
    )
    self_signed_count = sum(1 for c in all_certs if c.is_self_signed)
    weak_key_count = sum(
        1 for c in all_certs if c.key_size is not None and c.key_size < 2048
    )

    return CertScanResult(
        certificates=all_certs,
        total_scanned=total_scanned,
        total_certs_found=len(all_certs),
        expired_count=expired_count,
        expiring_soon_count=expiring_soon_count,
        self_signed_count=self_signed_count,
        weak_key_count=weak_key_count,
    )


def get_expiring_certs(
    certificates: list[CertificateInfo], days: int = 30
) -> list[CertificateInfo]:
    """Filter certificates expiring within N days (includes already expired)."""
    return [
        c
        for c in certificates
        if c.days_until_expiry is not None and c.days_until_expiry <= days
    ]
