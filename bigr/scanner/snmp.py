"""SNMP switch integration for MAC table and port mapping."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SwitchConfig:
    """Configuration for an SNMP-managed switch."""
    host: str
    community: str = "public"
    version: str = "2c"  # "2c" or "3"
    label: str = ""


@dataclass
class SwitchPort:
    """Represents a switch port with connected MAC addresses."""
    port_index: int
    port_name: str  # e.g., "GigabitEthernet0/1"
    mac_addresses: list[str] = field(default_factory=list)
    vlan_id: int | None = None


@dataclass
class SwitchMacEntry:
    """Single MAC address -> switch port mapping."""
    mac: str
    switch_host: str
    switch_label: str
    port_index: int
    port_name: str
    vlan_id: int | None = None


def normalize_snmp_mac(raw_mac: str | bytes | None) -> str | None:
    """Normalize MAC from SNMP format to aa:bb:cc:dd:ee:ff.

    SNMP returns MACs in various formats:
    - Hex-String: 0x001EBDAABBCC
    - Dot notation: 001e.bdaa.bbcc
    - Dash notation: 00-1E-BD-AA-BB-CC
    - Colon notation: 00:1e:bd:aa:bb:cc
    - Octet bytes: b"\\x00\\x1e\\xbd\\xaa\\xbb\\xcc"
    """
    if raw_mac is None:
        return None

    # Handle raw bytes
    if isinstance(raw_mac, (bytes, bytearray)):
        if len(raw_mac) == 6:
            return ":".join(f"{b:02x}" for b in raw_mac)
        return None

    # Handle string formats
    raw_mac = raw_mac.strip()
    if not raw_mac:
        return None

    # 0x-prefixed hex string: "0x001EBDAABBCC"
    if raw_mac.lower().startswith("0x"):
        hex_str = raw_mac[2:]
        if len(hex_str) == 12:
            hex_str = hex_str.lower()
            return ":".join(hex_str[i:i+2] for i in range(0, 12, 2))
        return None

    # Dot notation: "001e.bdaa.bbcc"
    if "." in raw_mac and len(raw_mac.replace(".", "")) == 12:
        hex_str = raw_mac.replace(".", "").lower()
        return ":".join(hex_str[i:i+2] for i in range(0, 12, 2))

    # Dash notation: "00-1E-BD-AA-BB-CC"
    if "-" in raw_mac:
        raw_mac = raw_mac.replace("-", ":")

    # Colon notation (already or converted from dash): "00:1e:bd:aa:bb:cc"
    if ":" in raw_mac:
        parts = raw_mac.lower().split(":")
        if len(parts) == 6:
            return ":".join(p.zfill(2) for p in parts)

    return None


def _oid_suffix_to_mac(oid_suffix: str) -> str:
    """Convert OID suffix (decimal octets) to MAC string.

    Example: "0.30.189.170.187.204" -> "00:1e:bd:aa:bb:cc"
    """
    parts = oid_suffix.split(".")
    # Take the last 6 parts (MAC octets)
    if len(parts) >= 6:
        octets = parts[-6:]
    else:
        octets = parts
    return ":".join(f"{int(o):02x}" for o in octets)


class SnmpMacTableReader:
    """Reads MAC address tables from SNMP-managed switches."""

    def __init__(self, switch: SwitchConfig):
        self.switch = switch
        self._mac_table: list[SwitchMacEntry] = []

    def _snmp_walk_mac_to_bridge(self) -> dict[str, int]:
        """Walk dot1dTpFdbPort (1.3.6.1.2.1.17.4.3.1.2).

        Returns {full_oid: bridge_port_number}.
        Override or mock for testing.
        """
        return {}  # pragma: no cover

    def _snmp_walk_bridge_to_if(self) -> dict[int, int]:
        """Walk dot1dBasePortIfIndex (1.3.6.1.2.1.17.1.4.1.2).

        Returns {bridge_port: ifIndex}.
        Override or mock for testing.
        """
        return {}  # pragma: no cover

    def _snmp_walk_if_to_name(self) -> dict[int, str]:
        """Walk ifName (1.3.6.1.2.1.31.1.1.1.1).

        Returns {ifIndex: interface_name}.
        Override or mock for testing.
        """
        return {}  # pragma: no cover

    def read_mac_table(self) -> list[SwitchMacEntry]:
        """Read MAC address table via SNMP.

        Uses OIDs:
        - 1.3.6.1.2.1.17.4.3.1.2 (dot1dTpFdbPort) - MAC -> bridge port
        - 1.3.6.1.2.1.17.1.4.1.2 (dot1dBasePortIfIndex) - bridge port -> ifIndex
        - 1.3.6.1.2.1.31.1.1.1.1 (ifName) - ifIndex -> interface name
        """
        mac_to_bridge = self._snmp_walk_mac_to_bridge()
        bridge_to_if = self._snmp_walk_bridge_to_if()
        if_to_name = self._snmp_walk_if_to_name()

        entries: list[SwitchMacEntry] = []

        for oid, bridge_port in mac_to_bridge.items():
            # Extract MAC from OID suffix
            # OID format: 1.3.6.1.2.1.17.4.3.1.2.<mac_as_decimal_octets>
            base_oid = "1.3.6.1.2.1.17.4.3.1.2."
            if oid.startswith(base_oid):
                mac_suffix = oid[len(base_oid):]
            else:
                # Fallback: take last 6 dot-separated decimal values
                mac_suffix = oid

            mac = _oid_suffix_to_mac(mac_suffix)

            # Resolve bridge port -> ifIndex -> name
            if_index = bridge_to_if.get(bridge_port)
            port_name = if_to_name.get(if_index, f"port-{bridge_port}") if if_index else f"port-{bridge_port}"

            entries.append(SwitchMacEntry(
                mac=mac,
                switch_host=self.switch.host,
                switch_label=self.switch.label,
                port_index=bridge_port,
                port_name=port_name,
            ))

        self._mac_table = entries
        return entries

    @property
    def mac_table(self) -> list[SwitchMacEntry]:
        return self._mac_table


def enrich_assets_with_switch_info(
    assets: list[dict], mac_entries: list[SwitchMacEntry]
) -> list[dict]:
    """Enrich asset dicts with switch port information.

    For each asset, find matching MAC in mac_entries and add:
    - switch_host
    - switch_label
    - switch_port (port_name)
    - switch_port_index
    """
    # Build lookup: normalized MAC -> entry
    mac_lookup: dict[str, SwitchMacEntry] = {}
    for entry in mac_entries:
        if entry.mac:
            mac_lookup[entry.mac.lower()] = entry

    for asset in assets:
        asset_mac = asset.get("mac")
        if asset_mac:
            normalized = asset_mac.lower()
            entry = mac_lookup.get(normalized)
            if entry:
                asset["switch_host"] = entry.switch_host
                asset["switch_label"] = entry.switch_label
                asset["switch_port"] = entry.port_name
                asset["switch_port_index"] = entry.port_index

    return assets
