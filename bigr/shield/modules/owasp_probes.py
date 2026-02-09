"""OWASP basic probes module - non-destructive detection only."""

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

# SQL error patterns indicating potential SQL injection vulnerability
SQL_ERROR_PATTERNS: list[str] = [
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or near",
    "ORA-",
    "mysql_fetch",
    "pg_query",
    "sqlite3.OperationalError",
]

# XSS test payload
XSS_PAYLOAD = "<script>alert(1)</script>"

# Directory traversal test patterns
TRAVERSAL_PAYLOADS: list[str] = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
]

# Indicator that directory traversal succeeded
TRAVERSAL_SUCCESS_INDICATOR = "/root:"

# Information disclosure paths to check
DISCLOSURE_PATHS: list[tuple[str, str]] = [
    ("/.env", "Environment File Exposed"),
    ("/phpinfo.php", "PHPInfo Page Exposed"),
    ("/server-status", "Apache Server Status Exposed"),
    ("/debug", "Debug Page Exposed"),
    ("/.git/HEAD", "Git Repository Exposed"),
    ("/wp-config.php.bak", "WordPress Config Backup Exposed"),
    ("/actuator/health", "Spring Actuator Exposed"),
]

# Open redirect test
REDIRECT_TEST_URL = "https://evil.example.com"


def _build_base_url(target: str, port: int | None = None) -> str | None:
    """Build a base URL for the target, trying HTTPS then HTTP.

    Returns the first URL that responds, or None if neither works.
    """
    if port is not None:
        if port in (443, 8443):
            urls = [f"https://{target}:{port}" if port != 443 else f"https://{target}"]
        elif port in (80,):
            urls = [f"http://{target}"]
        else:
            urls = [f"https://{target}:{port}", f"http://{target}:{port}"]
    else:
        urls = [f"https://{target}", f"http://{target}"]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for url in urls:
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "BiGR-Shield/1.0 (Security Scanner)")
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT, context=ctx):
                return url
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            continue

    return None


def _http_get(url: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, str]:
    """Perform an HTTP GET request and return (status_code, response_body).

    Returns (-1, "") on connection error.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "BiGR-Shield/1.0 (Security Scanner)")

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            return resp.status, body

    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body

    except (urllib.error.URLError, OSError) as exc:
        logger.debug("HTTP GET %s failed: %s", url, exc)
        return -1, ""


def _check_sql_injection(base_url: str, target: str, port: int | None) -> list[ShieldFinding]:
    """Test for error-based SQL injection by injecting SQL payload in query params."""
    findings: list[ShieldFinding] = []
    test_url = f"{base_url}/?id=' OR 1=1--"

    status, body = _http_get(test_url)
    if status == -1:
        return findings

    body_lower = body.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if pattern.lower() in body_lower:
            findings.append(ShieldFinding(
                module="owasp",
                severity=FindingSeverity.CRITICAL,
                title="Potential SQL Injection Detected",
                description=(
                    f"SQL error pattern detected in response from {test_url}. "
                    f"The application may be vulnerable to SQL injection attacks. "
                    f"Matched pattern: '{pattern}'"
                ),
                remediation=(
                    "Use parameterized queries or prepared statements. "
                    "Never concatenate user input into SQL queries. "
                    "Implement input validation and use an ORM where possible."
                ),
                target_ip=target,
                target_port=port,
                evidence={
                    "url": test_url,
                    "matched_pattern": pattern,
                    "status_code": status,
                    "response_snippet": body[:500],
                },
                attack_technique="T1190",
                attack_tactic="Initial Access",
            ))
            break  # One finding per test is sufficient

    return findings


def _check_xss(base_url: str, target: str, port: int | None) -> list[ShieldFinding]:
    """Test for reflected XSS by checking if payload is reflected in response."""
    findings: list[ShieldFinding] = []
    test_url = f"{base_url}/?q={XSS_PAYLOAD}"

    status, body = _http_get(test_url)
    if status == -1:
        return findings

    if XSS_PAYLOAD in body:
        findings.append(ShieldFinding(
            module="owasp",
            severity=FindingSeverity.HIGH,
            title="Potential Reflected XSS Detected",
            description=(
                f"The XSS payload was reflected in the response from {test_url}. "
                f"The application may be vulnerable to cross-site scripting attacks."
            ),
            remediation=(
                "Implement proper output encoding/escaping for all user-controlled data. "
                "Use Content-Security-Policy headers. "
                "Consider using a template engine with auto-escaping enabled."
            ),
            target_ip=target,
            target_port=port,
            evidence={
                "url": test_url,
                "payload": XSS_PAYLOAD,
                "reflected": True,
                "status_code": status,
            },
            attack_technique="T1059.007",
            attack_tactic="Execution",
        ))

    return findings


def _check_directory_traversal(
    base_url: str, target: str, port: int | None
) -> list[ShieldFinding]:
    """Test for directory traversal vulnerabilities."""
    findings: list[ShieldFinding] = []

    for payload in TRAVERSAL_PAYLOADS:
        test_url = f"{base_url}/?file={payload}"
        status, body = _http_get(test_url)
        if status == -1:
            continue

        if TRAVERSAL_SUCCESS_INDICATOR in body:
            findings.append(ShieldFinding(
                module="owasp",
                severity=FindingSeverity.CRITICAL,
                title="Directory Traversal Vulnerability Detected",
                description=(
                    f"Directory traversal payload '{payload}' returned sensitive file contents "
                    f"from {test_url}. An attacker can read arbitrary files from the server."
                ),
                remediation=(
                    "Validate and sanitize all file path inputs. "
                    "Use a whitelist of allowed file paths. "
                    "Run the application with minimal file system permissions."
                ),
                target_ip=target,
                target_port=port,
                evidence={
                    "url": test_url,
                    "payload": payload,
                    "indicator_found": TRAVERSAL_SUCCESS_INDICATOR,
                    "status_code": status,
                    "response_snippet": body[:500],
                },
                attack_technique="T1190",
                attack_tactic="Initial Access",
            ))
            break  # One finding is sufficient

    return findings


def _check_info_disclosure(
    base_url: str, target: str, port: int | None
) -> list[ShieldFinding]:
    """Check for information disclosure via exposed paths."""
    findings: list[ShieldFinding] = []

    for path, title in DISCLOSURE_PATHS:
        test_url = f"{base_url}{path}"
        status, body = _http_get(test_url)

        if status == 200 and len(body) > 0:
            findings.append(ShieldFinding(
                module="owasp",
                severity=FindingSeverity.HIGH,
                title=title,
                description=(
                    f"The path {path} is accessible on {target} and returned content. "
                    f"This may expose sensitive configuration, source code, or debugging information."
                ),
                remediation=(
                    f"Remove or restrict access to {path}. "
                    f"Configure the web server to deny access to sensitive paths. "
                    f"Ensure debug/development features are disabled in production."
                ),
                target_ip=target,
                target_port=port,
                evidence={
                    "url": test_url,
                    "path": path,
                    "status_code": status,
                    "response_length": len(body),
                    "response_snippet": body[:200],
                },
                attack_technique="T1190",
                attack_tactic="Initial Access",
            ))

    return findings


def _check_open_redirect(
    base_url: str, target: str, port: int | None
) -> list[ShieldFinding]:
    """Check for open redirect vulnerabilities."""
    findings: list[ShieldFinding] = []
    test_url = f"{base_url}/?url={REDIRECT_TEST_URL}"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(test_url, method="GET")
        req.add_header("User-Agent", "BiGR-Shield/1.0 (Security Scanner)")

        # Use a custom opener that doesn't follow redirects
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
                raise urllib.error.HTTPError(
                    newurl, code, msg, headers, fp
                )

        opener = urllib.request.build_opener(
            NoRedirectHandler,
            urllib.request.HTTPSHandler(context=ctx),
        )

        try:
            with opener.open(req, timeout=DEFAULT_TIMEOUT) as resp:
                # No redirect happened -- check if body contains redirect URL
                body = resp.read(65536).decode("utf-8", errors="replace")
                if REDIRECT_TEST_URL in body:
                    findings.append(ShieldFinding(
                        module="owasp",
                        severity=FindingSeverity.MEDIUM,
                        title="Potential Open Redirect Detected",
                        description=(
                            f"The external URL '{REDIRECT_TEST_URL}' appears in the response "
                            f"from {test_url}, suggesting a possible open redirect vulnerability."
                        ),
                        remediation=(
                            "Validate redirect URLs against a whitelist of allowed domains. "
                            "Never use user-supplied URLs directly for redirects."
                        ),
                        target_ip=target,
                        target_port=port,
                        evidence={
                            "url": test_url,
                            "redirect_target": REDIRECT_TEST_URL,
                            "status_code": resp.status,
                        },
                        attack_technique="T1190",
                        attack_tactic="Initial Access",
                    ))
        except urllib.error.HTTPError as exc:
            # Check if redirect location points to external URL
            location = exc.headers.get("Location", "") if exc.headers else ""
            if REDIRECT_TEST_URL in location:
                findings.append(ShieldFinding(
                    module="owasp",
                    severity=FindingSeverity.MEDIUM,
                    title="Open Redirect Detected",
                    description=(
                        f"The server at {test_url} redirects to external URL '{location}'. "
                        f"An attacker can use this to redirect users to malicious sites."
                    ),
                    remediation=(
                        "Validate redirect URLs against a whitelist of allowed domains. "
                        "Never use user-supplied URLs directly for redirects."
                    ),
                    target_ip=target,
                    target_port=port,
                    evidence={
                        "url": test_url,
                        "redirect_location": location,
                        "status_code": exc.code,
                    },
                    attack_technique="T1190",
                    attack_tactic="Initial Access",
                ))

    except (urllib.error.URLError, OSError) as exc:
        logger.debug("Open redirect check failed for %s: %s", test_url, exc)

    return findings


class OwaspProbesModule(ScanModule):
    """OWASP basic probes module -- non-destructive detection only.

    Probes:
    1. SQL Injection (error-based detection)
    2. Reflected XSS
    3. Directory traversal
    4. Information disclosure (exposed paths)
    5. Open redirect
    """

    name: str = "owasp"
    weight: int = 5

    def check_available(self) -> bool:
        """Always available -- uses stdlib urllib."""
        return True

    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Run OWASP probes against the target.

        1. Determine if HTTP service is available (try HTTPS then HTTP)
        2. Run each probe category
        3. Return findings for detected issues
        """
        findings: list[ShieldFinding] = []

        # Try to find a reachable HTTP service
        base_url = _build_base_url(target, port)
        if base_url is None:
            findings.append(ShieldFinding(
                module="owasp",
                severity=FindingSeverity.INFO,
                title="HTTP Service Not Available",
                description=(
                    f"Could not connect to {target} over HTTP/HTTPS. "
                    f"OWASP probes require an HTTP service to test."
                ),
                remediation="No action needed if the target is not a web application.",
                target_ip=target,
                target_port=port,
                evidence={"error": "no_http_service"},
            ))
            return findings

        actual_port = port

        # Run each probe
        findings.extend(_check_sql_injection(base_url, target, actual_port))
        findings.extend(_check_xss(base_url, target, actual_port))
        findings.extend(_check_directory_traversal(base_url, target, actual_port))
        findings.extend(_check_info_disclosure(base_url, target, actual_port))
        findings.extend(_check_open_redirect(base_url, target, actual_port))

        return findings
