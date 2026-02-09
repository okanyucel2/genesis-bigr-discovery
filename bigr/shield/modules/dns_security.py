"""DNS security records check module using subprocess dig/nslookup."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil

from bigr.shield.models import FindingSeverity, ShieldFinding
from bigr.shield.modules.base import ScanModule

logger = logging.getLogger(__name__)

# DNS query timeout in seconds
DNS_TIMEOUT = 15

# Common DKIM selector to check
DEFAULT_DKIM_SELECTOR = "default"


def _is_ip_address(target: str) -> bool:
    """Check if the target looks like an IP address (v4 or v6)."""
    # IPv4
    parts = target.split(".")
    if len(parts) == 4:
        try:
            for p in parts:
                val = int(p)
                if not 0 <= val <= 255:
                    return False
            return True
        except ValueError:
            pass
    # IPv6 (contains colons)
    if ":" in target:
        return True
    return False


def _strip_domain(target: str) -> str:
    """Strip protocol prefix and path from domain, if any."""
    domain = target.strip()
    for prefix in ("https://", "http://", "//"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    # Handle IPv6 addresses in brackets [::1]:port
    if domain.startswith("["):
        bracket_end = domain.find("]")
        if bracket_end != -1:
            return domain[1:bracket_end]
    # If it looks like an IPv6 address (contains multiple colons), return as-is
    if domain.count(":") > 1:
        return domain
    # Remove port if present (single colon, not IPv6)
    if ":" in domain:
        domain = domain.split(":")[0]
    # Remove trailing path
    if "/" in domain:
        domain = domain.split("/")[0]
    return domain


async def _query_dns_txt(domain: str) -> tuple[list[str], str | None]:
    """Query TXT records for domain using dig or nslookup.

    Returns a tuple of (txt_records_list, error_message_or_none).
    Uses create_subprocess_exec (argument-list style, no shell) for safety.
    """
    # Try dig first (more common on Linux/macOS)
    if shutil.which("dig"):
        return await _query_with_dig(domain, "TXT")

    # Fall back to nslookup
    if shutil.which("nslookup"):
        return await _query_with_nslookup(domain, "TXT")

    return [], "Neither dig nor nslookup found on system"


async def _query_dns_caa(domain: str) -> tuple[list[str], str | None]:
    """Query CAA records for domain using dig or nslookup.

    Returns a tuple of (caa_records_list, error_message_or_none).
    """
    if shutil.which("dig"):
        return await _query_with_dig(domain, "CAA")

    if shutil.which("nslookup"):
        return await _query_with_nslookup(domain, "CAA")

    return [], "Neither dig nor nslookup found on system"


async def _query_dns_mx(domain: str) -> tuple[list[str], str | None]:
    """Query MX records for domain.

    Returns a tuple of (mx_records_list, error_message_or_none).
    """
    if shutil.which("dig"):
        return await _query_with_dig(domain, "MX")

    if shutil.which("nslookup"):
        return await _query_with_nslookup(domain, "MX")

    return [], "Neither dig nor nslookup found on system"


async def _query_with_dig(domain: str, record_type: str) -> tuple[list[str], str | None]:
    """Run dig command and parse output.

    Uses create_subprocess_exec with explicit argument list (no shell injection).
    """
    cmd = ["dig", "+short", record_type, domain]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=DNS_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return [], f"DNS query timed out after {DNS_TIMEOUT}s"
    except OSError as exc:
        return [], f"Failed to run dig: {exc}"

    if proc.returncode != 0:
        stderr_text = stderr.decode("utf-8", errors="replace").strip() if stderr else ""
        return [], f"dig exited with code {proc.returncode}: {stderr_text}"

    output = stdout.decode("utf-8", errors="replace").strip()
    if not output:
        return [], None  # No records found (not an error)

    records = [line.strip().strip('"') for line in output.splitlines() if line.strip()]
    return records, None


async def _query_with_nslookup(domain: str, record_type: str) -> tuple[list[str], str | None]:
    """Run nslookup command and parse output.

    Uses create_subprocess_exec with explicit argument list (no shell injection).
    """
    cmd = ["nslookup", f"-type={record_type}", domain]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=DNS_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return [], f"DNS query timed out after {DNS_TIMEOUT}s"
    except OSError as exc:
        return [], f"Failed to run nslookup: {exc}"

    output = stdout.decode("utf-8", errors="replace")

    # Parse nslookup output for text= or TXT lines
    records: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        # nslookup TXT format: text = "v=spf1 ..."
        if "text =" in line.lower() or "txt" in line.lower():
            # Extract quoted content
            match = re.search(r'"([^"]*)"', line)
            if match:
                records.append(match.group(1))
        # CAA format: issue "letsencrypt.org"
        elif record_type == "CAA" and ("issue" in line.lower() or "iodef" in line.lower()):
            records.append(line)
        # MX format: mail exchanger = 10 mx.example.com
        elif record_type == "MX" and "mail exchanger" in line.lower():
            records.append(line)

    return records, None


def _parse_spf(txt_records: list[str]) -> dict:
    """Parse SPF record from TXT records.

    Returns dict with: found, record, valid, mechanisms.
    """
    for record in txt_records:
        if "v=spf1" in record.lower():
            # Basic validation
            mechanisms = record.split()
            has_all = any(m.lower() in ("-all", "~all", "+all", "?all") for m in mechanisms)
            return {
                "found": True,
                "record": record,
                "valid": has_all,  # SPF should end with an 'all' mechanism
                "mechanisms": mechanisms,
                "policy_strict": any(m.lower() == "-all" for m in mechanisms),
            }
    return {"found": False, "record": None, "valid": False, "mechanisms": []}


def _parse_dmarc(txt_records: list[str]) -> dict:
    """Parse DMARC record from TXT records.

    Returns dict with: found, record, policy.
    """
    for record in txt_records:
        if "v=dmarc1" in record.lower():
            # Extract policy
            policy = "none"
            match = re.search(r"p\s*=\s*(\w+)", record, re.IGNORECASE)
            if match:
                policy = match.group(1).lower()
            return {
                "found": True,
                "record": record,
                "policy": policy,
            }
    return {"found": False, "record": None, "policy": None}


class DnsSecurityModule(ScanModule):
    """DNS security records check module."""

    name: str = "dns"
    weight: int = 10

    def check_available(self) -> bool:
        """Always available -- uses subprocess for DNS queries."""
        return True

    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Check DNS security records for the target domain.

        Checks performed:
        1. SPF record presence and validity
        2. DKIM record check (common selector)
        3. DMARC record and policy level
        4. CAA record presence
        5. MX record presence (for email-capable domains)
        """
        findings: list[ShieldFinding] = []
        domain = _strip_domain(target)

        # Skip DNS checks for IP addresses
        if _is_ip_address(domain):
            findings.append(ShieldFinding(
                module="dns",
                severity=FindingSeverity.INFO,
                title="DNS Checks Skipped for IP Address",
                description=f"Target {domain} is an IP address. DNS security record checks are not applicable.",
                remediation="No action needed. DNS security records apply to domain names only.",
                target_ip=domain,
                target_port=None,
                evidence={"target_type": "ip_address"},
            ))
            return findings

        # Check if DNS tools are available
        has_dig = shutil.which("dig") is not None
        has_nslookup = shutil.which("nslookup") is not None
        if not has_dig and not has_nslookup:
            findings.append(ShieldFinding(
                module="dns",
                severity=FindingSeverity.INFO,
                title="DNS Query Tools Not Available",
                description="Neither dig nor nslookup were found on the system.",
                remediation="Install dnsutils (apt-get install dnsutils) or equivalent for your OS.",
                target_ip=domain,
                target_port=None,
                evidence={"error": "no_dns_tools"},
            ))
            return findings

        # Step 1: Check SPF record
        txt_records, txt_error = await _query_dns_txt(domain)
        if txt_error:
            findings.append(ShieldFinding(
                module="dns",
                severity=FindingSeverity.INFO,
                title="DNS TXT Query Failed",
                description=f"Failed to query TXT records for {domain}: {txt_error}",
                remediation="Verify the domain exists and DNS is reachable.",
                target_ip=domain,
                target_port=None,
                evidence={"error": txt_error},
            ))
        else:
            spf = _parse_spf(txt_records)
            if not spf["found"]:
                findings.append(ShieldFinding(
                    module="dns",
                    severity=FindingSeverity.HIGH,
                    title="SPF Record Missing",
                    description=(
                        f"No SPF (Sender Policy Framework) record found for {domain}. "
                        "Without SPF, attackers can send emails that appear to originate from this domain."
                    ),
                    remediation=(
                        "Add an SPF TXT record to your DNS. Example: "
                        'v=spf1 include:_spf.google.com -all'
                    ),
                    target_ip=domain,
                    target_port=None,
                    evidence={"spf_found": False, "txt_records_checked": len(txt_records)},
                    attack_technique="T1566",
                    attack_tactic="Initial Access",
                ))
            elif not spf["valid"]:
                findings.append(ShieldFinding(
                    module="dns",
                    severity=FindingSeverity.MEDIUM,
                    title="SPF Record Invalid or Incomplete",
                    description=(
                        f"SPF record found for {domain} but may be incomplete: {spf['record']}. "
                        "An SPF record should end with an 'all' mechanism (-all, ~all, etc.)."
                    ),
                    remediation="Ensure your SPF record ends with -all (hard fail) or ~all (soft fail).",
                    target_ip=domain,
                    target_port=None,
                    evidence={"spf_record": spf["record"], "mechanisms": spf["mechanisms"]},
                    attack_technique="T1566",
                    attack_tactic="Initial Access",
                ))
            elif not spf["policy_strict"]:
                findings.append(ShieldFinding(
                    module="dns",
                    severity=FindingSeverity.LOW,
                    title="SPF Policy Not Strict",
                    description=(
                        f"SPF record for {domain} does not use -all (hard fail): {spf['record']}. "
                        "A soft fail (~all) is less protective than a hard fail (-all)."
                    ),
                    remediation="Consider changing ~all to -all for stricter email authentication.",
                    target_ip=domain,
                    target_port=None,
                    evidence={"spf_record": spf["record"]},
                ))

        # Step 2: Check DKIM record
        dkim_domain = f"{DEFAULT_DKIM_SELECTOR}._domainkey.{domain}"
        dkim_records, dkim_error = await _query_dns_txt(dkim_domain)
        if dkim_error:
            logger.debug("DKIM query error for %s: %s", dkim_domain, dkim_error)
        if not dkim_records and not dkim_error:
            findings.append(ShieldFinding(
                module="dns",
                severity=FindingSeverity.MEDIUM,
                title="DKIM Record Not Found",
                description=(
                    f"No DKIM record found at {dkim_domain}. "
                    "DKIM (DomainKeys Identified Mail) helps verify that emails were not "
                    "tampered with in transit. Note: DKIM selector may differ from 'default'."
                ),
                remediation=(
                    "Configure DKIM signing for your email service and publish the DKIM public key "
                    f"as a TXT record at <selector>._domainkey.{domain}."
                ),
                target_ip=domain,
                target_port=None,
                evidence={"dkim_selector": DEFAULT_DKIM_SELECTOR, "dkim_domain": dkim_domain},
                attack_technique="T1566",
                attack_tactic="Initial Access",
            ))

        # Step 3: Check DMARC record
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_records, dmarc_error = await _query_dns_txt(dmarc_domain)
        if dmarc_error:
            logger.debug("DMARC query error for %s: %s", dmarc_domain, dmarc_error)
        if not dmarc_records and not dmarc_error:
            findings.append(ShieldFinding(
                module="dns",
                severity=FindingSeverity.HIGH,
                title="DMARC Record Missing",
                description=(
                    f"No DMARC record found at {dmarc_domain}. "
                    "Without DMARC, there is no policy to handle emails failing SPF/DKIM checks."
                ),
                remediation=(
                    "Add a DMARC TXT record at _dmarc.{domain}. Example: "
                    'v=DMARC1; p=reject; rua=mailto:dmarc@{domain}'
                ),
                target_ip=domain,
                target_port=None,
                evidence={"dmarc_found": False},
                attack_technique="T1566",
                attack_tactic="Initial Access",
            ))
        elif dmarc_records:
            dmarc = _parse_dmarc(dmarc_records)
            if dmarc["found"]:
                if dmarc["policy"] == "none":
                    findings.append(ShieldFinding(
                        module="dns",
                        severity=FindingSeverity.HIGH,
                        title="DMARC Policy Set to None",
                        description=(
                            f"DMARC record for {domain} has policy=none: {dmarc['record']}. "
                            "This means no action is taken on emails that fail authentication, "
                            "effectively providing no protection."
                        ),
                        remediation=(
                            "Change the DMARC policy from p=none to p=quarantine or p=reject. "
                            "Start with p=quarantine and monitor reports before moving to p=reject."
                        ),
                        target_ip=domain,
                        target_port=None,
                        evidence={
                            "dmarc_record": dmarc["record"],
                            "policy": dmarc["policy"],
                        },
                        attack_technique="T1566",
                        attack_tactic="Initial Access",
                    ))
                elif dmarc["policy"] == "quarantine":
                    findings.append(ShieldFinding(
                        module="dns",
                        severity=FindingSeverity.LOW,
                        title="DMARC Policy Set to Quarantine",
                        description=(
                            f"DMARC record for {domain} has policy=quarantine: {dmarc['record']}. "
                            "This is good, but p=reject provides stronger protection."
                        ),
                        remediation=(
                            "Consider upgrading to p=reject after confirming legitimate email "
                            "is not being quarantined."
                        ),
                        target_ip=domain,
                        target_port=None,
                        evidence={
                            "dmarc_record": dmarc["record"],
                            "policy": dmarc["policy"],
                        },
                    ))
                # policy == "reject" is the ideal state -- no finding generated

        # Step 4: Check CAA record
        caa_records, caa_error = await _query_dns_caa(domain)
        if caa_error:
            logger.debug("CAA query error for %s: %s", domain, caa_error)
        if not caa_records and not caa_error:
            findings.append(ShieldFinding(
                module="dns",
                severity=FindingSeverity.LOW,
                title="CAA Record Missing",
                description=(
                    f"No CAA (Certificate Authority Authorization) record found for {domain}. "
                    "CAA records specify which CAs are allowed to issue certificates for the domain."
                ),
                remediation=(
                    "Add a CAA record to restrict certificate issuance. Example: "
                    '0 issue "letsencrypt.org"'
                ),
                target_ip=domain,
                target_port=None,
                evidence={"caa_found": False},
            ))

        # Step 5: Check MX record (for context on email security findings)
        mx_records, mx_error = await _query_dns_mx(domain)
        if mx_error:
            logger.debug("MX query error for %s: %s", domain, mx_error)
        if mx_records:
            findings.append(ShieldFinding(
                module="dns",
                severity=FindingSeverity.INFO,
                title="MX Records Present",
                description=(
                    f"Domain {domain} has MX records configured, indicating email capability. "
                    "Email security records (SPF, DKIM, DMARC) are especially important."
                ),
                remediation="Ensure SPF, DKIM, and DMARC are all configured for email-capable domains.",
                target_ip=domain,
                target_port=None,
                evidence={"mx_records": mx_records[:5]},  # Cap at 5 for evidence
            ))

        return findings
