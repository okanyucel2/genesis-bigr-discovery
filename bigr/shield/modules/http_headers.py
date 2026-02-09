"""HTTP security headers check module using Python stdlib."""

from __future__ import annotations

import logging
import ssl
import urllib.error
import urllib.request

from bigr.shield.models import FindingSeverity, ShieldFinding
from bigr.shield.modules.base import ScanModule

logger = logging.getLogger(__name__)

# Connection timeout in seconds
DEFAULT_TIMEOUT = 10

# Required security headers and their absence severity
REQUIRED_HEADERS: list[dict] = [
    {
        "header": "Strict-Transport-Security",
        "severity": FindingSeverity.HIGH,
        "title": "HSTS Header Missing",
        "description": (
            "The Strict-Transport-Security (HSTS) header is not set. "
            "Without HSTS, browsers may allow insecure HTTP connections, "
            "exposing users to downgrade attacks and cookie hijacking."
        ),
        "remediation": (
            "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
    },
    {
        "header": "Content-Security-Policy",
        "severity": FindingSeverity.MEDIUM,
        "title": "Content-Security-Policy Header Missing",
        "description": (
            "The Content-Security-Policy (CSP) header is not set. "
            "CSP helps prevent cross-site scripting (XSS), clickjacking, "
            "and other code injection attacks."
        ),
        "remediation": (
            "Add a Content-Security-Policy header. Start with a report-only policy "
            "and tighten as needed: Content-Security-Policy: default-src 'self'"
        ),
    },
    {
        "header": "X-Frame-Options",
        "severity": FindingSeverity.MEDIUM,
        "title": "X-Frame-Options Header Missing",
        "description": (
            "The X-Frame-Options header is not set. "
            "This makes the site vulnerable to clickjacking attacks."
        ),
        "remediation": "Add the header: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).",
    },
    {
        "header": "X-Content-Type-Options",
        "severity": FindingSeverity.LOW,
        "title": "X-Content-Type-Options Header Missing",
        "description": (
            "The X-Content-Type-Options header is not set. "
            "Browsers may MIME-sniff responses, which can lead to XSS attacks."
        ),
        "remediation": "Add the header: X-Content-Type-Options: nosniff",
    },
    {
        "header": "Referrer-Policy",
        "severity": FindingSeverity.LOW,
        "title": "Referrer-Policy Header Missing",
        "description": (
            "The Referrer-Policy header is not set. "
            "Without it, the full URL may be sent in the Referer header to third-party sites, "
            "potentially leaking sensitive information."
        ),
        "remediation": "Add the header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "Permissions-Policy",
        "severity": FindingSeverity.LOW,
        "title": "Permissions-Policy Header Missing",
        "description": (
            "The Permissions-Policy header is not set. "
            "This header controls which browser features (camera, microphone, geolocation, etc.) "
            "the page is allowed to use."
        ),
        "remediation": (
            "Add the header: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
    },
]

# Headers that leak information when present
INFO_LEAK_HEADERS: list[dict] = [
    {
        "header": "Server",
        "title": "Server Header Information Disclosure",
        "description": (
            "The Server header reveals server software and version information. "
            "Attackers can use this to target known vulnerabilities."
        ),
        "remediation": "Remove or obfuscate the Server header to avoid disclosing version information.",
        "check_value": True,  # Only flag if contains version-like info
    },
    {
        "header": "X-Powered-By",
        "title": "X-Powered-By Header Information Disclosure",
        "description": (
            "The X-Powered-By header reveals the technology stack in use. "
            "Attackers can use this to target framework-specific vulnerabilities."
        ),
        "remediation": "Remove the X-Powered-By header from server responses.",
        "check_value": False,  # Flag whenever present
    },
]


def _has_version_info(value: str) -> bool:
    """Check if a header value appears to contain version information."""
    # Look for patterns like: nginx/1.19.0, Apache/2.4.41, etc.
    if "/" in value:
        return True
    # Look for version numbers like 1.2.3
    import re
    if re.search(r"\d+\.\d+", value):
        return True
    return False


def _fetch_headers(target: str) -> tuple[dict[str, str], str]:
    """Fetch HTTP headers from target, trying HTTPS first then HTTP.

    Returns a tuple of (headers_dict, url_used).
    Headers dict has lowercase keys.
    """
    urls_to_try = [
        f"https://{target}",
        f"http://{target}",
    ]

    last_error: Exception | None = None

    for url in urls_to_try:
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "BiGR-Shield/1.0 (Security Scanner)")

            # Create SSL context that doesn't verify for scanning purposes
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT, context=ctx) as resp:
                headers: dict[str, str] = {}
                for key in resp.headers:
                    headers[key.lower()] = resp.headers[key]
                return headers, url

        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            last_error = exc
            logger.debug("Failed to fetch %s: %s", url, exc)
            continue

    raise last_error or OSError(f"Failed to connect to {target}")


class HttpHeadersModule(ScanModule):
    """HTTP security headers check module."""

    name: str = "headers"
    weight: int = 10

    def check_available(self) -> bool:
        """Always available -- uses stdlib urllib."""
        return True

    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Fetch HTTP headers and check for security header presence.

        Checks performed:
        1. Required security headers (HSTS, CSP, X-Frame-Options, etc.)
        2. Information-leaking headers (Server, X-Powered-By)
        """
        findings: list[ShieldFinding] = []
        actual_port = port or 443

        try:
            headers, url_used = _fetch_headers(target)
        except urllib.error.HTTPError as exc:
            # HTTP errors still have headers we can check
            try:
                headers_obj = exc.headers
                headers = {}
                for key in headers_obj:
                    headers[key.lower()] = headers_obj[key]
                url_used = exc.url or f"https://{target}"
            except Exception:
                findings.append(ShieldFinding(
                    module="headers",
                    severity=FindingSeverity.MEDIUM,
                    title="HTTP Headers Check Failed",
                    description=f"HTTP error {exc.code} fetching headers from {target}: {exc.reason}",
                    remediation="Verify the target is reachable and serving HTTP responses.",
                    target_ip=target,
                    target_port=actual_port,
                    evidence={"error": str(exc), "http_code": exc.code},
                ))
                return findings
        except (urllib.error.URLError, OSError) as exc:
            findings.append(ShieldFinding(
                module="headers",
                severity=FindingSeverity.MEDIUM,
                title="HTTP Connection Failed",
                description=f"Could not connect to {target} to check HTTP headers: {exc}",
                remediation="Verify the target is reachable and serving HTTP/HTTPS.",
                target_ip=target,
                target_port=actual_port,
                evidence={"error": str(exc)},
            ))
            return findings
        except Exception as exc:
            findings.append(ShieldFinding(
                module="headers",
                severity=FindingSeverity.INFO,
                title="HTTP Headers Check Error",
                description=f"Unexpected error checking headers for {target}: {exc}",
                remediation="Check the target address and try again.",
                target_ip=target,
                target_port=actual_port,
                evidence={"error": str(exc)},
            ))
            return findings

        # Check required security headers
        for req in REQUIRED_HEADERS:
            header_name = req["header"].lower()
            if header_name not in headers:
                findings.append(ShieldFinding(
                    module="headers",
                    severity=req["severity"],
                    title=req["title"],
                    description=req["description"],
                    remediation=req["remediation"],
                    target_ip=target,
                    target_port=actual_port,
                    evidence={
                        "missing_header": req["header"],
                        "url_checked": url_used,
                    },
                    attack_technique="T1190",
                    attack_tactic="Initial Access",
                ))

        # Check info-leaking headers
        for leak in INFO_LEAK_HEADERS:
            header_name = leak["header"].lower()
            header_value = headers.get(header_name)
            if header_value is not None:
                # For Server header, only flag if it contains version info
                if leak.get("check_value") and not _has_version_info(header_value):
                    continue

                findings.append(ShieldFinding(
                    module="headers",
                    severity=FindingSeverity.MEDIUM,
                    title=leak["title"],
                    description=leak["description"],
                    remediation=leak["remediation"],
                    target_ip=target,
                    target_port=actual_port,
                    evidence={
                        "header": leak["header"],
                        "value": header_value,
                        "url_checked": url_used,
                    },
                    attack_technique="T1592",
                    attack_tactic="Reconnaissance",
                ))

        return findings
