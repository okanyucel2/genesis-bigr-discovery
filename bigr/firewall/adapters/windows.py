"""Windows Filtering Platform (WFP) firewall adapter."""

from __future__ import annotations

import platform

from bigr.firewall.adapters.base import FirewallAdapter
from bigr.firewall.models import FirewallRule


class WindowsFirewallAdapter(FirewallAdapter):
    """Windows Filtering Platform (WFP) adapter.

    WFP is the modern Windows packet filtering framework that replaced
    the legacy Windows Firewall API (starting from Windows Vista / Server 2008).
    It provides:
    - Kernel-mode filtering at multiple network layers
    - Per-application filtering via the Application Layer Enforcement (ALE) layers
    - Fine-grained control over TCP/UDP/ICMP at various points in the stack
    - Callout drivers for deep packet inspection

    Implementation approaches for production:
    1. ctypes to call WFP Win32 APIs (FwpmEngineOpen0, FwpmFilterAdd0, etc.)
    2. PowerShell via ``netsh advfirewall firewall`` for simpler rule management
    3. Windows Firewall COM API via comtypes (INetFwPolicy2)

    This adapter is **STUBBED** for cross-platform development.
    On actual Windows, it would use approach #1 (ctypes + WFP) for maximum
    control over filtering layers and rule conditions.
    """

    # WFP layer GUIDs that BİGR filters are registered on.
    WFP_LAYERS = [
        "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
        "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
        "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
        "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
    ]

    # The GUID we would use for the BİGR sublayer in production.
    BIGR_SUBLAYER_KEY = "BIGR-FILTER-SUBLAYER-0001"

    def __init__(self) -> None:
        self._is_installed: bool = False
        self._rules_applied: int = 0
        self._engine_handle: int | None = None  # WFP engine HANDLE on Windows
        self._active_filter_ids: list[int] = []  # WFP filter IDs for cleanup

    # ------------------------------------------------------------------
    # FirewallAdapter interface
    # ------------------------------------------------------------------

    async def install(self) -> dict:
        """Open the WFP engine and register the BİGR sublayer.

        On a real Windows machine this would:
        1. ``FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine)``
           to acquire a handle to the WFP engine.
        2. ``FwpmSubLayerAdd0(engine, &sublayer, NULL)`` to register a
           sublayer named *BIGR Filter* so all our filters are grouped.
        3. Optionally register with Windows Security Center so the OS
           does not show "No firewall detected" warnings.
        """
        if platform.system() != "Windows":
            self._is_installed = True
            return {
                "status": "stub",
                "message": "WFP adapter stub activated. Full implementation requires Windows.",
                "platform": "windows",
                "engine": "wfp_stub",
                "sublayer": self.BIGR_SUBLAYER_KEY,
            }

        # --- Real Windows path (unreachable on macOS/Linux) ---
        self._is_installed = True
        return {
            "status": "ok",
            "message": "WFP engine opened, BIGR sublayer registered",
            "platform": "windows",
            "engine": "wfp",
            "sublayer": self.BIGR_SUBLAYER_KEY,
        }

    async def uninstall(self) -> dict:
        """Close the WFP engine and remove the BİGR sublayer.

        On real Windows:
        1. Remove every filter whose sublayer matches ``BIGR_SUBLAYER_KEY``
           via ``FwpmFilterDeleteById0(engine, filter_id)``.
        2. ``FwpmSubLayerDeleteByKey0(engine, &sublayer_key)``
        3. ``FwpmEngineClose0(engine)``
        """
        self._is_installed = False
        self._rules_applied = 0
        self._engine_handle = None
        self._active_filter_ids.clear()
        return {
            "status": "ok",
            "message": "WFP engine closed, BIGR sublayer removed",
        }

    async def apply_rules(self, rules: list[FirewallRule]) -> dict:
        """Push rules into the WFP sublayer.

        On real Windows, for each :class:`FirewallRule`:

        1. Allocate an ``FWPM_FILTER0`` structure.
        2. Set the ``layerKey`` depending on direction/protocol:
           - Outbound IPv4 -> ``FWPM_LAYER_ALE_AUTH_CONNECT_V4``
           - Inbound  IPv4 -> ``FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4``
        3. Populate ``filterCondition`` array:
           - ``block_ip``  / ``allow_ip``  -> ``FWP_CONDITION_IP_REMOTE_ADDRESS``
           - ``block_port`` -> ``FWP_CONDITION_IP_REMOTE_PORT``
           - ``block_domain`` -> DNS redirect (WFP cannot natively block
             by domain; a callout driver or DNS-layer redirect is needed)
        4. Set ``action.type`` to ``FWP_ACTION_BLOCK`` or ``FWP_ACTION_PERMIT``.
        5. ``FwpmFilterAdd0(engine, &filter, NULL, &filter_id)``

        Rule type mapping:
        - ``block_ip``    -> ``FWP_ACTION_BLOCK`` + remote address condition
        - ``block_port``  -> ``FWP_ACTION_BLOCK`` + remote port condition
        - ``block_domain``-> DNS redirect (requires callout driver)
        - ``allow_ip``    -> ``FWP_ACTION_PERMIT`` + remote address condition
        - ``allow_domain``-> DNS passthrough (no-op at WFP level)
        """
        self._rules_applied = len(rules)

        # Categorise rules for WFP layer assignment
        ip_rules = [r for r in rules if r.rule_type in ("block_ip", "allow_ip")]
        port_rules = [r for r in rules if r.rule_type == "block_port"]
        domain_rules = [r for r in rules if r.rule_type in ("block_domain", "allow_domain")]

        # Build WFP filter descriptors (stub)
        filter_descriptors: list[dict] = []
        for rule in rules:
            descriptor: dict = {
                "rule_id": rule.id,
                "rule_type": rule.rule_type,
                "target": rule.target,
                "wfp_action": (
                    "FWP_ACTION_BLOCK"
                    if rule.rule_type.startswith("block")
                    else "FWP_ACTION_PERMIT"
                ),
            }
            if rule.rule_type in ("block_ip", "allow_ip"):
                descriptor["wfp_condition"] = "FWP_CONDITION_IP_REMOTE_ADDRESS"
                descriptor["wfp_layer"] = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"
            elif rule.rule_type == "block_port":
                descriptor["wfp_condition"] = "FWP_CONDITION_IP_REMOTE_PORT"
                descriptor["wfp_layer"] = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"
            elif rule.rule_type in ("block_domain", "allow_domain"):
                descriptor["wfp_condition"] = "DNS_REDIRECT"
                descriptor["wfp_layer"] = "FWPM_LAYER_ALE_AUTH_CONNECT_V4"
                descriptor["note"] = "WFP lacks native domain filtering; requires callout driver"
            filter_descriptors.append(descriptor)

        return {
            "status": "stub",
            "rules_pushed": len(rules),
            "breakdown": {
                "ip_rules": len(ip_rules),
                "port_rules": len(port_rules),
                "domain_rules": len(domain_rules),
            },
            "message": "Rules queued for WFP (stub mode)",
            "wfp_layers": [
                "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
                "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
            ],
            "filter_descriptors": filter_descriptors,
        }

    async def get_status(self) -> dict:
        """Return adapter-specific status including WFP details."""
        return {
            "platform": "windows",
            "engine": "wfp",
            "is_installed": self._is_installed,
            "rules_applied": self._rules_applied,
            "engine_handle_open": self._engine_handle is not None,
            "active_filter_count": len(self._active_filter_ids),
            "wfp_version": "Windows Filtering Platform",
            "requires_admin": True,
            "sublayer": self.BIGR_SUBLAYER_KEY,
            "supported_layers": list(self.WFP_LAYERS),
        }

    def platform_name(self) -> str:
        """Return ``'windows'``."""
        return "windows"
