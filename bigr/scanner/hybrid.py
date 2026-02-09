"""Hybrid scanner - orchestrates passive and active scanning."""

from __future__ import annotations

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from bigr.models import Asset, ScanMethod, ScanResult
from bigr.scanner.active import is_root, run_active_scan, scan_ports
from bigr.scanner.mdns import discover_mdns_services, enrich_assets_with_mdns
from bigr.scanner.passive import run_passive_scan

logger = logging.getLogger(__name__)


def expand_cidr(target: str) -> list[str]:
    """Expand CIDR notation to list of host IPs."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # Single IP
        return [target]


def merge_assets(passive: list[Asset], active: list[Asset]) -> list[Asset]:
    """Merge passive and active scan results. Active data wins conflicts."""
    merged: dict[str, Asset] = {}

    # Add passive first
    for asset in passive:
        key = asset.mac or asset.ip
        merged[key] = asset

    # Active overwrites/enriches
    for asset in active:
        key = asset.mac or asset.ip
        if key in merged:
            existing = merged[key]
            # Keep passive hostname if active doesn't have one
            if asset.hostname is None and existing.hostname is not None:
                asset.hostname = existing.hostname
            # Merge ports
            all_ports = set(existing.open_ports) | set(asset.open_ports)
            asset.open_ports = sorted(all_ports)
            asset.scan_method = ScanMethod.HYBRID
            # Merge evidence
            asset.raw_evidence = {**existing.raw_evidence, **asset.raw_evidence}
        merged[key] = asset

    return list(merged.values())


def run_hybrid_scan(
    target: str,
    mode: str = "hybrid",
    ports: list[int] | None = None,
    timeout: float = 2.0,
    mdns_timeout: float = 8.0,
) -> ScanResult:
    """Run hybrid scan: passive first, then active if root.

    mDNS discovery runs in parallel with the passive scan phase
    (both are non-root operations). After merging passive and active
    results, assets are enriched with mDNS hostnames and services.

    Args:
        target: CIDR notation (e.g., "192.168.1.0/24")
        mode: "passive", "active", or "hybrid"
        ports: Custom port list. Defaults to critical ports.
        timeout: Per-port scan timeout.
        mdns_timeout: How long to listen for mDNS services.
    """
    started_at = datetime.now(timezone.utc)
    root = is_root()

    target_ips = expand_cidr(target)
    passive_assets: list[Asset] = []
    active_assets: list[Asset] = []

    # Phase 1: Passive scan + mDNS discovery (parallel, both non-root)
    mdns_future = None
    if mode in ("passive", "hybrid"):
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Start mDNS discovery in background
            mdns_future = executor.submit(discover_mdns_services, mdns_timeout)

            # Run passive scan in main thread
            passive_assets = run_passive_scan(target_ips=target_ips)

            # Port scan passive-discovered hosts (doesn't need root)
            for asset in passive_assets:
                if not asset.open_ports:
                    asset.open_ports = scan_ports(asset.ip, ports=ports, timeout=timeout)

    # Phase 2: Active scan (only if root and mode allows)
    if mode in ("active", "hybrid") and root:
        active_assets = run_active_scan(target, ports=ports, timeout=timeout)

    # Merge results
    if mode == "hybrid":
        assets = merge_assets(passive_assets, active_assets)
    elif mode == "active":
        assets = active_assets
    else:
        assets = passive_assets

    # Phase 3: Enrich with mDNS data
    if mdns_future is not None:
        try:
            mdns_services = mdns_future.result(timeout=mdns_timeout + 5)
            if mdns_services:
                logger.info("Enriching %d assets with %d mDNS services", len(assets), len(mdns_services))
                enrich_assets_with_mdns(assets, mdns_services)
        except Exception as exc:
            logger.warning("mDNS discovery failed: %s", exc)

    scan_method = ScanMethod.HYBRID if mode == "hybrid" else ScanMethod(mode)

    return ScanResult(
        target=target,
        scan_method=scan_method,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
        assets=assets,
        is_root=root,
    )
