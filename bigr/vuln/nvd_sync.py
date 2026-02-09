"""NVD data seeding for offline use. Ships common CVEs for known device vendors."""

from __future__ import annotations

from pathlib import Path

from bigr.vuln.cve_db import bulk_upsert_cves, init_cve_db
from bigr.vuln.models import CveEntry

# Pre-built CVE data for common network device vendors
# This provides baseline matching without requiring NVD API access
SEED_CVES: list[CveEntry] = [
    # --- Cisco ---
    CveEntry(
        cve_id="CVE-2023-20198",
        cvss_score=10.0,
        severity="critical",
        description="Cisco IOS XE Web UI privilege escalation allows unauthenticated remote attacker to create an account with privilege level 15 access",
        affected_vendor="cisco",
        affected_product="ios_xe",
        cpe="cpe:2.3:o:cisco:ios_xe:*",
        published="2023-10-16",
        cisa_kev=True,
    ),
    CveEntry(
        cve_id="CVE-2023-20269",
        cvss_score=9.1,
        severity="critical",
        description="Cisco ASA and FTD Software Remote Access VPN unauthorized access vulnerability",
        affected_vendor="cisco",
        affected_product="asa",
        cpe="cpe:2.3:o:cisco:asa:*",
        published="2023-09-06",
        cisa_kev=True,
    ),
    CveEntry(
        cve_id="CVE-2024-20353",
        cvss_score=8.6,
        severity="high",
        description="Cisco ASA and FTD Software Web Services Denial-of-Service vulnerability",
        affected_vendor="cisco",
        affected_product="asa",
        cpe="cpe:2.3:o:cisco:asa:*",
        published="2024-04-24",
        cisa_kev=True,
    ),
    # --- Hikvision ---
    CveEntry(
        cve_id="CVE-2021-36260",
        cvss_score=9.8,
        severity="critical",
        description="Hikvision IP camera/NVR command injection vulnerability via crafted messages",
        affected_vendor="hikvision",
        affected_product="ip_camera",
        cpe="cpe:2.3:h:hikvision:*:*",
        published="2021-09-18",
        cisa_kev=True,
    ),
    CveEntry(
        cve_id="CVE-2023-28808",
        cvss_score=9.8,
        severity="critical",
        description="Hikvision Hybrid SAN/cluster storage access control bypass",
        affected_vendor="hikvision",
        affected_product="storage",
        cpe="cpe:2.3:h:hikvision:hybrid_san:*",
        published="2023-04-11",
    ),
    # --- HP Printers ---
    CveEntry(
        cve_id="CVE-2022-3942",
        cvss_score=8.4,
        severity="high",
        description="HP LaserJet Pro printers buffer overflow via link-local multicast name resolution",
        affected_vendor="hp",
        affected_product="laserjet",
        cpe="cpe:2.3:h:hp:laserjet:*",
        published="2022-03-21",
    ),
    CveEntry(
        cve_id="CVE-2023-26271",
        cvss_score=7.5,
        severity="high",
        description="HP LaserJet printers information disclosure vulnerability",
        affected_vendor="hp",
        affected_product="laserjet",
        cpe="cpe:2.3:h:hp:laserjet:*",
        published="2023-04-04",
    ),
    # --- TP-Link ---
    CveEntry(
        cve_id="CVE-2023-1389",
        cvss_score=8.8,
        severity="high",
        description="TP-Link Archer AX21 unauthenticated command injection via web management interface",
        affected_vendor="tp-link",
        affected_product="archer",
        cpe="cpe:2.3:h:tp-link:archer_ax21:*",
        published="2023-03-15",
        cisa_kev=True,
    ),
    CveEntry(
        cve_id="CVE-2024-21833",
        cvss_score=8.8,
        severity="high",
        description="TP-Link routers OS command injection vulnerability",
        affected_vendor="tp-link",
        affected_product="router",
        cpe="cpe:2.3:h:tp-link:router:*",
        published="2024-01-11",
    ),
    # --- ZTE ---
    CveEntry(
        cve_id="CVE-2022-39063",
        cvss_score=7.5,
        severity="high",
        description="ZTE MF286R LTE router command injection via network diagnostics",
        affected_vendor="zte",
        affected_product="mf286r",
        cpe="cpe:2.3:h:zte:mf286r:*",
        published="2022-10-11",
    ),
    # --- MikroTik ---
    CveEntry(
        cve_id="CVE-2023-30799",
        cvss_score=9.1,
        severity="critical",
        description="MikroTik RouterOS privilege escalation from admin to super-admin",
        affected_vendor="mikrotik",
        affected_product="routeros",
        cpe="cpe:2.3:o:mikrotik:routeros:*",
        published="2023-07-19",
    ),
    CveEntry(
        cve_id="CVE-2018-14847",
        cvss_score=9.1,
        severity="critical",
        description="MikroTik RouterOS directory traversal vulnerability allowing credential theft",
        affected_vendor="mikrotik",
        affected_product="routeros",
        cpe="cpe:2.3:o:mikrotik:routeros:*",
        published="2018-08-02",
        cisa_kev=True,
    ),
    # --- Ubiquiti ---
    CveEntry(
        cve_id="CVE-2021-22205",
        cvss_score=10.0,
        severity="critical",
        description="Ubiquiti UniFi Network Application remote code execution via ExifTool DjVu file parsing",
        affected_vendor="ubiquiti",
        affected_product="unifi",
        cpe="cpe:2.3:a:ubiquiti:unifi_network:*",
        published="2021-04-23",
        cisa_kev=True,
    ),
    # --- Synology ---
    CveEntry(
        cve_id="CVE-2024-10443",
        cvss_score=9.8,
        severity="critical",
        description="Synology DiskStation Manager (DSM) zero-click remote code execution",
        affected_vendor="synology",
        affected_product="dsm",
        cpe="cpe:2.3:a:synology:dsm:*",
        published="2024-11-01",
    ),
    CveEntry(
        cve_id="CVE-2023-2729",
        cvss_score=7.5,
        severity="high",
        description="Synology DiskStation Manager insufficient random values for admin password reset",
        affected_vendor="synology",
        affected_product="dsm",
        cpe="cpe:2.3:a:synology:dsm:*",
        published="2023-06-13",
    ),
    # --- Generic Web Servers ---
    CveEntry(
        cve_id="CVE-2024-47176",
        cvss_score=9.9,
        severity="critical",
        description="CUPS (Common Unix Printing System) remote code execution via IPP protocol",
        affected_vendor="cups",
        affected_product="cups",
        cpe="cpe:2.3:a:cups:cups:*",
        published="2024-09-26",
    ),
    CveEntry(
        cve_id="CVE-2023-44487",
        cvss_score=7.5,
        severity="high",
        description="HTTP/2 Rapid Reset Attack affecting nginx, Apache, and other web servers",
        affected_vendor="generic",
        affected_product="http2",
        cpe="cpe:2.3:a:generic:http2:*",
        published="2023-10-10",
        cisa_kev=True,
    ),
    # --- Dahua ---
    CveEntry(
        cve_id="CVE-2021-33044",
        cvss_score=9.8,
        severity="critical",
        description="Dahua IP camera authentication bypass via crafted login request",
        affected_vendor="dahua",
        affected_product="ip_camera",
        cpe="cpe:2.3:h:dahua:*:*",
        published="2021-09-15",
        cisa_kev=True,
    ),
]


def seed_cve_database(db_path: Path | None = None) -> int:
    """Populate CVE database with built-in seed data. Returns count."""
    init_cve_db(db_path)
    count = bulk_upsert_cves(SEED_CVES, db_path=db_path)
    return count


def get_seed_cve_count() -> int:
    """Return count of built-in seed CVEs."""
    return len(SEED_CVES)
