"""CVE intelligence module -- matches services to known CVEs with EPSS/KEV enrichment."""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from bigr.shield.models import FindingSeverity, ShieldFinding
from bigr.shield.modules.base import ScanModule

logger = logging.getLogger(__name__)

# Connection timeout for banner grabs
BANNER_TIMEOUT = 5

# NVD API rate limit (seconds between requests)
NVD_RATE_LIMIT = 6.0  # without API key

# NVD API rate limit with API key
NVD_RATE_LIMIT_KEYED = 0.6

# HTTP request timeout for external APIs
API_TIMEOUT = 15

# KEV cache TTL in seconds (24 hours)
KEV_CACHE_TTL = 86400

# Common ports to probe for service banners
DEFAULT_PROBE_PORTS = [22, 80, 443, 8080, 8443, 3306, 5432]

# ---- CPE Mapping ----

# Maps lowercase service name prefixes to CPE vendor:product strings.
# Version is substituted at runtime via _banner_to_cpe().
CPE_MAP: dict[str, tuple[str, str]] = {
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "iis": ("microsoft", "internet_information_services"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "tomcat": ("apache", "tomcat"),
    "postfix": ("postfix", "postfix"),
    "exim": ("exim", "exim"),
    "dovecot": ("dovecot", "dovecot"),
    "proftpd": ("proftpd_project", "proftpd"),
    "vsftpd": ("beasts", "vsftpd"),
    "haproxy": ("haproxy", "haproxy"),
    "envoy": ("envoyproxy", "envoy"),
    "traefik": ("traefik", "traefik"),
    "caddy": ("caddyserver", "caddy"),
    "node.js": ("nodejs", "node.js"),
    "express": ("expressjs", "express"),
    "php": ("php", "php"),
    "python": ("python", "python"),
}

# Version extraction regex: matches patterns like /1.24.0, _8.9p1, etc.
VERSION_RE = re.compile(r"[/_\s-]?(\d+(?:\.\d+)+(?:p\d+)?)")


def _extract_version(banner: str) -> str | None:
    """Extract a version string from a service banner.

    Examples:
        "nginx/1.24.0" -> "1.24.0"
        "OpenSSH_8.9p1" -> "8.9"
        "Apache/2.4.57 (Ubuntu)" -> "2.4.57"
    """
    match = VERSION_RE.search(banner)
    if match:
        version = match.group(1)
        # Strip trailing 'p' suffix variants (e.g. "8.9p1" -> "8.9")
        clean = re.sub(r"p\d+$", "", version)
        return clean
    return None


def _banner_to_cpe(service_name: str, version: str | None = None) -> str | None:
    """Map a service banner/name to a CPE 2.3 string.

    Args:
        service_name: Service name (e.g. "nginx", "OpenSSH_8.9p1").
        version: Explicit version string. If None, extracted from service_name.

    Returns:
        CPE 2.3 string or None if unmapped.
    """
    lower = service_name.lower().strip()

    # Try to match service name against known CPE prefixes
    vendor_product: tuple[str, str] | None = None
    for prefix, mapping in CPE_MAP.items():
        if prefix in lower:
            vendor_product = mapping
            break

    if vendor_product is None:
        return None

    vendor, product = vendor_product

    # Extract version if not explicitly provided
    if version is None:
        version = _extract_version(service_name)

    ver_str = version if version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{ver_str}:*:*:*:*:*:*:*"


# ---- NVD CVE Lookup ----

def _get_nvd_headers() -> dict[str, str]:
    """Build request headers for NVD API, including API key if available."""
    headers: dict[str, str] = {
        "User-Agent": "BiGR-Shield/1.0 (CVE Intelligence Module)",
    }
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _get_nvd_rate_limit() -> float:
    """Return appropriate rate limit based on API key presence."""
    if os.environ.get("NVD_API_KEY"):
        return NVD_RATE_LIMIT_KEYED
    return NVD_RATE_LIMIT


def _fetch_cves_for_cpe(cpe: str) -> list[dict]:
    """Fetch CVEs from NVD API 2.0 for a given CPE string.

    Returns a list of dicts with keys: cve_id, cvss, description, cwe.
    """
    encoded_cpe = urllib.request.quote(cpe, safe="")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={encoded_cpe}"

    req = urllib.request.Request(url, headers=_get_nvd_headers())

    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=API_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            logger.warning("NVD API rate limited (403) for CPE %s", cpe)
        else:
            logger.warning("NVD API HTTP error %d for CPE %s", exc.code, cpe)
        return []
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        logger.warning("NVD API request failed for CPE %s: %s", cpe, exc)
        return []
    except Exception as exc:
        logger.warning("Unexpected error fetching CVEs for CPE %s: %s", cpe, exc)
        return []

    return _parse_nvd_response(data)


def _parse_nvd_response(data: dict) -> list[dict]:
    """Parse NVD API 2.0 JSON response into a list of CVE dicts.

    Each dict has keys: cve_id, cvss, description, cwe.
    """
    results: list[dict] = []
    vulnerabilities = data.get("vulnerabilities", [])

    for vuln_wrapper in vulnerabilities:
        cve = vuln_wrapper.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # Extract CVSS v3.1 score
        cvss: float | None = None
        metrics = cve.get("metrics", {})
        # Try cvssMetricV31 first, then cvssMetricV30
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss = cvss_data.get("baseScore")
                if cvss is not None:
                    break

        # Extract description (English preferred)
        description = ""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # Extract CWE
        cwe = ""
        weaknesses = cve.get("weaknesses", [])
        for weakness in weaknesses:
            for w_desc in weakness.get("description", []):
                val = w_desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe = val
                    break
            if cwe:
                break

        results.append({
            "cve_id": cve_id,
            "cvss": cvss,
            "description": description,
            "cwe": cwe,
        })

    return results


# ---- EPSS Enrichment ----

def _fetch_epss(cve_id: str) -> float | None:
    """Fetch EPSS exploitation probability score for a CVE ID.

    Returns float 0-1 or None if not found / error.
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "BiGR-Shield/1.0 (CVE Intelligence Module)",
    })

    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=API_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            json.JSONDecodeError) as exc:
        logger.debug("EPSS lookup failed for %s: %s", cve_id, exc)
        return None
    except Exception as exc:
        logger.debug("Unexpected EPSS error for %s: %s", cve_id, exc)
        return None

    epss_data = data.get("data", [])
    if epss_data:
        try:
            return float(epss_data[0].get("epss", 0))
        except (ValueError, TypeError, IndexError):
            pass
    return None


# ---- CISA KEV Check ----

# Module-level KEV cache
_kev_cache: dict[str, object] = {
    "data": None,
    "fetched_at": 0.0,
}

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _fetch_kev_catalog() -> set[str]:
    """Fetch or return cached CISA KEV catalog.

    Returns a set of CVE IDs known to be actively exploited.
    """
    now = time.time()
    if _kev_cache["data"] is not None and (now - _kev_cache["fetched_at"]) < KEV_CACHE_TTL:
        return _kev_cache["data"]  # type: ignore[return-value]

    req = urllib.request.Request(KEV_FEED_URL, headers={
        "User-Agent": "BiGR-Shield/1.0 (CVE Intelligence Module)",
    })

    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=API_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("Failed to fetch CISA KEV catalog: %s", exc)
        # Return existing cache if available, else empty set
        if _kev_cache["data"] is not None:
            return _kev_cache["data"]  # type: ignore[return-value]
        return set()

    cve_ids: set[str] = set()
    for vuln in data.get("vulnerabilities", []):
        cid = vuln.get("cveID", "")
        if cid:
            cve_ids.add(cid)

    _kev_cache["data"] = cve_ids  # type: ignore[assignment]
    _kev_cache["fetched_at"] = now
    return cve_ids


def _check_kev(cve_id: str) -> bool:
    """Check whether a CVE is in the CISA Known Exploited Vulnerabilities catalog."""
    kev_set = _fetch_kev_catalog()
    return cve_id in kev_set


# ---- Priority Scoring ----

def _calculate_priority(
    cvss: float | None,
    epss: float | None,
    kev: bool,
) -> FindingSeverity:
    """Calculate finding severity from CVSS, EPSS and KEV status.

    Priority rules:
    - CRITICAL: CVSS >= 9.0 AND (EPSS >= 0.5 OR KEV)
    - HIGH:     CVSS >= 7.0 OR (EPSS >= 0.3 AND CVSS >= 4.0) OR KEV
    - MEDIUM:   CVSS >= 4.0
    - LOW:      CVSS < 4.0
    - INFO:     No CVSS available
    """
    if cvss is None:
        return FindingSeverity.INFO

    epss_val = epss if epss is not None else 0.0

    # CRITICAL
    if cvss >= 9.0 and (epss_val >= 0.5 or kev):
        return FindingSeverity.CRITICAL

    # HIGH
    if cvss >= 7.0:
        return FindingSeverity.HIGH
    if epss_val >= 0.3 and cvss >= 4.0:
        return FindingSeverity.HIGH
    if kev:
        return FindingSeverity.HIGH

    # MEDIUM
    if cvss >= 4.0:
        return FindingSeverity.MEDIUM

    # LOW
    return FindingSeverity.LOW


# ---- Banner Grabbing ----

def _grab_banner(target: str, port: int) -> str | None:
    """Attempt to grab a service banner from target:port.

    For HTTP/HTTPS ports, sends a HEAD request and reads the Server header.
    For other ports, reads raw bytes from the socket.
    """
    try:
        if port in (443, 8443):
            return _grab_https_banner(target, port)
        if port in (80, 8080):
            return _grab_http_banner(target, port)
        return _grab_raw_banner(target, port)
    except Exception as exc:
        logger.debug("Banner grab failed for %s:%d: %s", target, port, exc)
        return None


def _grab_https_banner(target: str, port: int) -> str | None:
    """Grab Server header from HTTPS service."""
    url = f"https://{target}:{port}/" if port != 443 else f"https://{target}/"
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "BiGR-Shield/1.0")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=BANNER_TIMEOUT, context=ctx) as resp:
        server = resp.headers.get("Server", "")
        if server:
            return server
    return None


def _grab_http_banner(target: str, port: int) -> str | None:
    """Grab Server header from HTTP service."""
    url = f"http://{target}:{port}/" if port != 80 else f"http://{target}/"
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "BiGR-Shield/1.0")
    try:
        with urllib.request.urlopen(req, timeout=BANNER_TIMEOUT) as resp:
            server = resp.headers.get("Server", "")
            if server:
                return server
    except urllib.error.HTTPError as exc:
        # Even error responses may have Server header
        server = exc.headers.get("Server", "") if exc.headers else ""
        if server:
            return server
    return None


def _grab_raw_banner(target: str, port: int) -> str | None:
    """Grab banner from a raw TCP socket connection."""
    try:
        with socket.create_connection((target, port), timeout=BANNER_TIMEOUT) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            data = sock.recv(1024)
            if data:
                return data.decode("utf-8", errors="replace").strip()
    except (OSError, UnicodeDecodeError):
        pass
    return None


def _detect_services(target: str, ports: list[int] | None = None) -> list[dict]:
    """Detect services on target by grabbing banners from common ports.

    Returns list of dicts with keys: port, banner, service, version.
    """
    probe_ports = ports if ports else DEFAULT_PROBE_PORTS
    services: list[dict] = []

    for port in probe_ports:
        banner = _grab_banner(target, port)
        if banner:
            # Try to identify the service from the banner
            service_name = _identify_service(banner, port)
            version = _extract_version(banner)
            services.append({
                "port": port,
                "banner": banner,
                "service": service_name,
                "version": version,
            })

    return services


def _identify_service(banner: str, port: int) -> str:
    """Identify the service name from a banner string and port number."""
    lower = banner.lower()

    # Check known service identifiers in banner
    for prefix in CPE_MAP:
        if prefix in lower:
            return prefix

    # Fall back to port-based identification
    port_service_map = {
        22: "ssh",
        80: "http",
        443: "https",
        8080: "http-proxy",
        8443: "https-alt",
        3306: "mysql",
        5432: "postgresql",
    }
    return port_service_map.get(port, "unknown")


# ---- ATT&CK Mapping ----

# Service categories for ATT&CK mapping
WEB_SERVICES = {"nginx", "apache", "lighttpd", "iis", "tomcat", "http", "https",
                "http-proxy", "https-alt", "haproxy", "envoy", "traefik", "caddy",
                "node.js", "express", "php", "python"}
REMOTE_SERVICES = {"openssh", "ssh", "rdp", "vnc"}


def _get_attack_mapping(service: str) -> tuple[str, str]:
    """Map a service name to MITRE ATT&CK technique and tactic.

    Returns (technique_id, tactic_name).
    """
    lower = service.lower()
    if lower in WEB_SERVICES or any(ws in lower for ws in WEB_SERVICES):
        return "T1190", "Initial Access"
    if lower in REMOTE_SERVICES or any(rs in lower for rs in REMOTE_SERVICES):
        return "T1133", "Persistence"
    # Default for database / other services
    return "T1190", "Initial Access"


# ---- Main Module ----

class CveMatcherModule(ScanModule):
    """CVE intelligence module using NVD API, EPSS, and CISA KEV."""

    name: str = "cve"
    weight: int = 25

    def __init__(self) -> None:
        self._last_nvd_call: float = 0.0

    def check_available(self) -> bool:
        """Always available -- uses HTTP APIs."""
        return True

    def _rate_limit_nvd(self) -> None:
        """Enforce NVD API rate limiting."""
        now = time.time()
        delay = _get_nvd_rate_limit()
        elapsed = now - self._last_nvd_call
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_nvd_call = time.time()

    async def scan(self, target: str, port: int | None = None) -> list[ShieldFinding]:
        """Run CVE intelligence scan against the target.

        Steps:
        1. Detect services via banner grabbing on common ports
        2. Map each service to CPE
        3. Lookup CVEs via NVD API
        4. Enrich each CVE with EPSS and KEV data
        5. Create ShieldFinding for each CVE

        Args:
            target: Target host (domain or IP).
            port: Optional specific port to scan.
        """
        findings: list[ShieldFinding] = []

        # Step 1: Detect services
        probe_ports = [port] if port else None
        try:
            services = _detect_services(target, probe_ports)
        except Exception as exc:
            logger.warning("Service detection failed for %s: %s", target, exc)
            findings.append(ShieldFinding(
                module="cve",
                severity=FindingSeverity.INFO,
                title="Service Detection Failed",
                description=f"Could not detect services on {target}: {exc}",
                remediation="Verify network connectivity to the target.",
                target_ip=target,
                evidence={"error": str(exc)},
            ))
            return findings

        if not services:
            findings.append(ShieldFinding(
                module="cve",
                severity=FindingSeverity.INFO,
                title="No Services Detected",
                description=f"No service banners were detected on {target}.",
                remediation="No action needed. The target may not expose detectable service banners.",
                target_ip=target,
                evidence={"probed_ports": probe_ports or DEFAULT_PROBE_PORTS},
            ))
            return findings

        # Step 2-5: For each service, map to CPE, lookup CVEs, enrich
        api_failed = False
        for svc in services:
            cpe = _banner_to_cpe(svc["banner"], svc.get("version"))
            if cpe is None:
                continue

            # Rate limit NVD calls
            self._rate_limit_nvd()

            # Lookup CVEs
            try:
                cves = _fetch_cves_for_cpe(cpe)
            except Exception as exc:
                logger.warning("NVD lookup failed for CPE %s: %s", cpe, exc)
                api_failed = True
                continue

            if not cves:
                continue

            # Enrich each CVE
            for cve_info in cves:
                cve_id = cve_info["cve_id"]
                cvss = cve_info.get("cvss")

                # EPSS enrichment
                epss = _fetch_epss(cve_id)

                # KEV check
                kev = _check_kev(cve_id)

                # Calculate priority
                severity = _calculate_priority(cvss, epss, kev)

                # ATT&CK mapping
                technique, tactic = _get_attack_mapping(svc["service"])

                # Build remediation
                remediation = f"Update {svc['service']} to the latest version."
                if kev:
                    remediation += " This CVE is in CISA's Known Exploited Vulnerabilities catalog -- patch immediately."
                if cvss is not None and cvss >= 9.0:
                    remediation += " This is a critical-severity vulnerability."

                findings.append(ShieldFinding(
                    module="cve",
                    severity=severity,
                    title=f"{cve_id}: {svc['service']} vulnerability",
                    description=cve_info.get("description", f"CVE {cve_id} affects {cpe}"),
                    remediation=remediation,
                    target_ip=target,
                    target_port=svc["port"],
                    evidence={
                        "cpe": cpe,
                        "banner": svc["banner"],
                        "cwe": cve_info.get("cwe", ""),
                        "service": svc["service"],
                        "version": svc.get("version", ""),
                    },
                    cve_id=cve_id,
                    cvss_score=cvss,
                    epss_score=epss,
                    cisa_kev=kev,
                    attack_technique=technique,
                    attack_tactic=tactic,
                ))

        # If all API calls failed, add an info finding
        if api_failed and not findings:
            findings.append(ShieldFinding(
                module="cve",
                severity=FindingSeverity.INFO,
                title="CVE API Unavailable",
                description="Could not reach NVD API to check for known vulnerabilities.",
                remediation="Check network connectivity or set NVD_API_KEY environment variable.",
                target_ip=target,
                evidence={"error": "api_unavailable"},
            ))

        return findings
