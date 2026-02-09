"""Remediation recommendation engine for Shield findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from bigr.shield.models import FindingSeverity, ShieldFinding


@dataclass
class Remediation:
    """A remediation recommendation for a specific finding."""

    finding_id: str = ""
    summary: str = ""
    steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    effort: str = "medium"  # "low" | "medium" | "high"
    impact: str = "medium"  # "low" | "medium" | "high"
    priority_label: str = "Important"  # "Quick Win" | "Important" | "Major Project" | "Deprioritize"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "summary": self.summary,
            "steps": self.steps,
            "references": self.references,
            "effort": self.effort,
            "impact": self.impact,
            "priority_label": self.priority_label,
        }


# Priority label ordering for sorting
PRIORITY_ORDER: dict[str, int] = {
    "Quick Win": 0,
    "Important": 1,
    "Major Project": 2,
    "Deprioritize": 3,
}


def _compute_priority_label(effort: str, impact: str) -> str:
    """Compute priority label from effort/impact matrix.

    | | Low Effort | High Effort |
    |---|---|---|
    | High Impact | Quick Win | Major Project |
    | Low Impact | Deprioritize | Deprioritize |

    Medium values map to "Important".
    """
    if impact == "high" and effort == "low":
        return "Quick Win"
    if impact == "high" and effort == "high":
        return "Major Project"
    if impact == "low" and effort == "low":
        return "Deprioritize"
    if impact == "low" and effort == "high":
        return "Deprioritize"
    # Medium impact or medium effort -> Important
    return "Important"


# ---- Module-specific remediation mappings ----

_TLS_REMEDIATIONS: dict[str, dict] = {
    "TLS Certificate Expired": {
        "summary": "Renew the expired TLS certificate",
        "steps": [
            "Generate a new Certificate Signing Request (CSR)",
            "Submit CSR to your Certificate Authority (CA) or use Let's Encrypt",
            "Install the renewed certificate on your web server",
            "Verify with: openssl s_client -connect <host>:443 -servername <host>",
            "Set up automatic renewal (certbot renew --dry-run)",
        ],
        "references": [
            "https://letsencrypt.org/docs/",
            "https://www.ssl.com/guide/renew-ssl-certificate/",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Weak TLS Version": {
        "summary": "Disable legacy TLS versions (TLSv1.0, TLSv1.1)",
        "steps": [
            "Nginx: set 'ssl_protocols TLSv1.2 TLSv1.3;' in server block",
            "Apache: set 'SSLProtocol -all +TLSv1.2 +TLSv1.3' in ssl.conf",
            "IIS: Disable TLS 1.0/1.1 via Registry or IIS Crypto tool",
            "Test with: nmap --script ssl-enum-ciphers -p 443 <host>",
        ],
        "references": [
            "https://wiki.mozilla.org/Security/Server_Side_TLS",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Self-Signed Certificate": {
        "summary": "Replace self-signed certificate with a trusted CA-signed certificate",
        "steps": [
            "Generate a CSR with your organization details",
            "Obtain a certificate from a trusted CA (Let's Encrypt is free)",
            "Install the CA-signed certificate and intermediate chain",
            "Verify the certificate chain: openssl verify -CAfile chain.pem cert.pem",
        ],
        "references": [
            "https://letsencrypt.org/getting-started/",
        ],
        "effort": "low",
        "impact": "high",
    },
}

_PORT_REMEDIATIONS: dict[str, dict] = {
    "Dangerous Port Open": {
        "summary": "Close or restrict access to dangerous service ports",
        "steps": [
            "Identify if the service is required for business operations",
            "If not needed: stop the service and disable auto-start",
            "If needed: restrict access with firewall rules (iptables/ufw/security groups)",
            "Linux: sudo ufw deny <port>/tcp (or allow from specific IPs only)",
            "AWS: Update Security Group to remove public access to the port",
            "Verify: nmap -p <port> <host> (should show filtered/closed)",
        ],
        "references": [
            "https://www.cisecurity.org/benchmark",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Excessive Open Ports": {
        "summary": "Reduce attack surface by closing unnecessary ports",
        "steps": [
            "Audit all open ports: ss -tlnp (Linux) or netstat -an (cross-platform)",
            "Document required services and their ports",
            "Disable all unnecessary services",
            "Implement default-deny firewall policy",
            "Allow only required ports from specific source IPs/ranges",
        ],
        "references": [
            "https://www.cisecurity.org/benchmark",
        ],
        "effort": "medium",
        "impact": "high",
    },
}

_HEADER_REMEDIATIONS: dict[str, dict] = {
    "HSTS Header Missing": {
        "summary": "Enable HTTP Strict Transport Security (HSTS)",
        "steps": [
            "Nginx: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';",
            "Apache: Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'",
            "IIS: Add custom header in HTTP Response Headers",
            "Verify all HTTP URLs redirect to HTTPS before enabling HSTS",
            "Consider submitting to HSTS preload list: https://hstspreload.org/",
        ],
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://hstspreload.org/",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Content-Security-Policy Header Missing": {
        "summary": "Implement Content Security Policy to prevent XSS",
        "steps": [
            "Start with report-only mode: Content-Security-Policy-Report-Only: default-src 'self'",
            "Monitor violations and adjust policy",
            "Switch to enforcement mode once policy is stable",
            "Nginx: add_header Content-Security-Policy \"default-src 'self'\";",
            "Apache: Header set Content-Security-Policy \"default-src 'self'\"",
        ],
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://csp-evaluator.withgoogle.com/",
        ],
        "effort": "medium",
        "impact": "medium",
    },
    "Server Header Information Disclosure": {
        "summary": "Remove or obfuscate server version information",
        "steps": [
            "Nginx: add 'server_tokens off;' to nginx.conf",
            "Apache: set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf",
            "IIS: Install URL Rewrite module and remove Server header",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        "effort": "low",
        "impact": "low",
    },
}

_DNS_REMEDIATIONS: dict[str, dict] = {
    "DNSSEC Not Enabled": {
        "summary": "Enable DNSSEC to protect DNS responses from tampering",
        "steps": [
            "Contact your DNS provider about DNSSEC support",
            "Generate DNSSEC keys (KSK and ZSK)",
            "Sign your DNS zone",
            "Publish DS record with your domain registrar",
            "Verify: dig +dnssec <domain> (should show RRSIG records)",
        ],
        "references": [
            "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en",
        ],
        "effort": "medium",
        "impact": "medium",
    },
    "SPF Record Missing": {
        "summary": "Add SPF record to prevent email spoofing",
        "steps": [
            "Identify all authorized mail servers",
            "Create a TXT record: v=spf1 include:_spf.google.com ~all",
            "Adjust the include: directives for your mail provider",
            "Verify: dig TXT <domain> | grep spf",
        ],
        "references": [
            "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
        ],
        "effort": "low",
        "impact": "medium",
    },
}

_CVE_REMEDIATIONS: dict[str, dict] = {
    "Known CVE Detected": {
        "summary": "Patch or upgrade affected software to fix known vulnerability",
        "steps": [
            "Check the CVE details for affected versions and patches",
            "Update the affected software to the latest patched version",
            "If no patch available, apply recommended workaround/mitigation",
            "Verify the fix: rescan or check version after update",
            "Monitor for new CVEs affecting your software stack",
        ],
        "references": [
            "https://nvd.nist.gov/",
            "https://cve.mitre.org/",
        ],
        "effort": "medium",
        "impact": "high",
    },
}

_CREDS_REMEDIATIONS: dict[str, dict] = {
    "Redis Accessible Without Authentication": {
        "summary": "Enable Redis authentication and restrict network access",
        "steps": [
            "Edit redis.conf: set 'requirepass <strong-password>'",
            "Bind to localhost: set 'bind 127.0.0.1' in redis.conf",
            "Disable dangerous commands: rename-command FLUSHALL ''",
            "Restart Redis: sudo systemctl restart redis",
            "Verify: redis-cli ping (should require AUTH)",
            "Update all application connection strings with the password",
        ],
        "references": [
            "https://redis.io/docs/management/security/",
        ],
        "effort": "low",
        "impact": "high",
    },
    "MongoDB Accessible Without Authentication": {
        "summary": "Enable MongoDB authentication and restrict access",
        "steps": [
            "Create admin user: db.createUser({user:'admin', pwd:'<strong>', roles:['root']})",
            "Edit mongod.conf: set 'security.authorization: enabled'",
            "Bind to localhost: set 'net.bindIp: 127.0.0.1'",
            "Restart MongoDB: sudo systemctl restart mongod",
            "Update application connection strings with credentials",
        ],
        "references": [
            "https://www.mongodb.com/docs/manual/administration/security-checklist/",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Default Admin Panel Accessible": {
        "summary": "Restrict access to admin panels",
        "steps": [
            "Add authentication to the admin panel",
            "Restrict access by IP: allow only trusted networks",
            "Change default admin credentials immediately",
            "Consider moving admin panel to a non-standard path",
            "Implement rate limiting on login attempts",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Service Detected - Default Credential Check Recommended": {
        "summary": "Verify and change default credentials on detected services",
        "steps": [
            "Test all default credentials for the detected service",
            "Change any default passwords to strong, unique passwords",
            "Disable default accounts where possible",
            "Implement account lockout after failed login attempts",
            "Enable key-based authentication for SSH",
        ],
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
        ],
        "effort": "low",
        "impact": "medium",
    },
}

_OWASP_REMEDIATIONS: dict[str, dict] = {
    "Potential SQL Injection Detected": {
        "summary": "Fix SQL injection vulnerability by using parameterized queries",
        "steps": [
            "Identify all SQL queries using string concatenation with user input",
            "Replace with parameterized queries or prepared statements",
            "Python: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "Use an ORM (SQLAlchemy, Django ORM) for safer database access",
            "Implement input validation and sanitization as defense in depth",
            "Deploy a Web Application Firewall (WAF) as additional protection",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "effort": "medium",
        "impact": "high",
    },
    "Potential Reflected XSS Detected": {
        "summary": "Fix XSS vulnerability by implementing output encoding",
        "steps": [
            "Identify all locations where user input is reflected in HTML output",
            "Implement context-appropriate output encoding (HTML, JS, URL, CSS)",
            "Use a template engine with auto-escaping (Jinja2, React, Vue)",
            "Add Content-Security-Policy header to prevent inline script execution",
            "Implement input validation as defense in depth",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "effort": "medium",
        "impact": "high",
    },
    "Directory Traversal Vulnerability Detected": {
        "summary": "Fix directory traversal by validating file path inputs",
        "steps": [
            "Validate all file path inputs against a whitelist of allowed paths",
            "Use os.path.realpath() to resolve symlinks and normalize paths",
            "Verify the resolved path starts with the expected base directory",
            "Remove or sanitize '../' sequences from user input",
            "Run the application with minimal file system permissions",
        ],
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Environment File Exposed": {
        "summary": "Remove exposed environment file from web root",
        "steps": [
            "Remove .env file from the web-accessible directory",
            "Configure web server to deny access to dotfiles",
            "Nginx: location ~ /\\. { deny all; }",
            "Rotate all secrets/credentials exposed in the file",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Git Repository Exposed": {
        "summary": "Remove exposed .git directory from web root",
        "steps": [
            "Remove the .git directory from the web-accessible path",
            "Configure web server to deny access to .git: location ~ /\\.git { deny all; }",
            "Rotate all secrets that may have been in git history",
            "Review git history for any committed credentials",
        ],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        "effort": "low",
        "impact": "high",
    },
    "Open Redirect Detected": {
        "summary": "Fix open redirect by validating redirect URLs",
        "steps": [
            "Validate all redirect URLs against a whitelist of allowed domains",
            "Use relative paths for internal redirects instead of full URLs",
            "If external redirects are needed, use an allowlist of trusted domains",
            "Never pass user-supplied URLs directly to redirect functions",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
        "effort": "low",
        "impact": "medium",
    },
}

# Combine all module-specific mappings into a single lookup
_ALL_REMEDIATIONS: dict[str, dict] = {
    **_TLS_REMEDIATIONS,
    **_PORT_REMEDIATIONS,
    **_HEADER_REMEDIATIONS,
    **_DNS_REMEDIATIONS,
    **_CVE_REMEDIATIONS,
    **_CREDS_REMEDIATIONS,
    **_OWASP_REMEDIATIONS,
}


def _effort_from_severity(severity: FindingSeverity) -> str:
    """Estimate effort based on finding severity (fallback heuristic)."""
    if severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        return "medium"
    return "low"


def _impact_from_severity(severity: FindingSeverity) -> str:
    """Estimate impact based on finding severity (fallback heuristic)."""
    if severity == FindingSeverity.CRITICAL:
        return "high"
    if severity == FindingSeverity.HIGH:
        return "high"
    if severity == FindingSeverity.MEDIUM:
        return "medium"
    return "low"


class RemediationEngine:
    """Generates remediation plans from Shield findings.

    Uses a lookup table of known finding types mapped to specific
    remediation steps, effort/impact estimates, and reference URLs.
    Falls back to the finding's built-in remediation text for unknown types.
    """

    def get_remediation(self, finding: ShieldFinding) -> Remediation:
        """Get a remediation recommendation for a specific finding.

        Attempts to match the finding title against known remediation mappings.
        Falls back to a generic remediation based on the finding's own fields.
        """
        # Try exact title match first
        matched = _ALL_REMEDIATIONS.get(finding.title)

        # Try partial title match if exact fails
        if matched is None:
            for key, value in _ALL_REMEDIATIONS.items():
                if key in finding.title:
                    matched = value
                    break

        if matched is not None:
            effort = matched.get("effort", _effort_from_severity(finding.severity))
            impact = matched.get("impact", _impact_from_severity(finding.severity))
            priority = _compute_priority_label(effort, impact)

            return Remediation(
                finding_id=finding.id,
                summary=matched["summary"],
                steps=matched["steps"],
                references=matched.get("references", []),
                effort=effort,
                impact=impact,
                priority_label=priority,
            )

        # Fallback: use the finding's built-in remediation text
        effort = _effort_from_severity(finding.severity)
        impact = _impact_from_severity(finding.severity)
        priority = _compute_priority_label(effort, impact)

        return Remediation(
            finding_id=finding.id,
            summary=finding.remediation or f"Address: {finding.title}",
            steps=[finding.remediation] if finding.remediation else ["Review and address the finding."],
            references=[],
            effort=effort,
            impact=impact,
            priority_label=priority,
        )

    def generate_plan(self, findings: list[ShieldFinding]) -> list[Remediation]:
        """Generate a prioritized remediation plan from a list of findings.

        Returns remediations sorted by priority:
        Quick Win first, then Important, then Major Project, then Deprioritize.
        """
        if not findings:
            return []

        remediations = [self.get_remediation(f) for f in findings]

        # Sort by priority order
        remediations.sort(key=lambda r: PRIORITY_ORDER.get(r.priority_label, 99))

        return remediations
