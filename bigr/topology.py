"""Network topology graph builder for D3.js visualization."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass
class TopologyNode:
    """A node in the network topology graph."""

    id: str  # Unique identifier (IP or MAC)
    label: str  # Display label
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    node_type: str = "device"  # "gateway", "switch", "device", "subnet"
    bigr_category: str = "unclassified"
    confidence: float = 0.0
    open_ports: list[int] = field(default_factory=list)
    size: int = 10  # Node size for visualization
    color: str = "#6b7280"  # Node color
    subnet: str | None = None
    switch_port: str | None = None

    def to_dict(self) -> dict:
        """Convert to D3.js-compatible dict."""
        return {
            "id": self.id,
            "label": self.label,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "type": self.node_type,
            "bigr_category": self.bigr_category,
            "confidence": self.confidence,
            "open_ports": self.open_ports,
            "size": self.size,
            "color": self.color,
            "subnet": self.subnet,
            "switch_port": self.switch_port,
        }


@dataclass
class TopologyEdge:
    """An edge (connection) in the topology graph."""

    source: str  # Source node ID
    target: str  # Target node ID
    edge_type: str = "connection"  # "gateway", "switch", "subnet", "connection"
    label: str | None = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type,
            "label": self.label,
        }


@dataclass
class TopologyGraph:
    """Complete network topology graph."""

    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "node_types": self._count_by_type(),
            },
        }

    def _count_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for node in self.nodes:
            counts[node.node_type] = counts.get(node.node_type, 0) + 1
        return counts


# BIGR category -> color mapping
CATEGORY_COLORS: dict[str, str] = {
    "ag_ve_sistemler": "#3b82f6",  # Blue
    "uygulamalar": "#8b5cf6",  # Purple
    "iot": "#10b981",  # Green
    "tasinabilir": "#f59e0b",  # Amber
    "unclassified": "#6b7280",  # Gray
}

# Node type -> size mapping
NODE_SIZES: dict[str, int] = {
    "gateway": 30,
    "switch": 25,
    "subnet": 20,
    "device": 10,
}


def detect_gateway(assets: list[dict]) -> str | None:
    """Detect the likely gateway IP from asset list.

    Heuristics (checked in order, first match wins):
    1. IP ending in .1 with category ag_ve_sistemler
    2. IP ending in .1 or .254 with open ports containing 53, 80, or 443
    3. Returns None if no candidate matches
    """
    if not assets:
        return None

    # Heuristic 1: .1 IP with ag_ve_sistemler category
    for asset in assets:
        ip = asset.get("ip", "")
        if ip.endswith(".1") and asset.get("bigr_category") == "ag_ve_sistemler":
            return ip

    # Heuristic 2: .1 or .254 with gateway-like open ports (53, 80, 443)
    gateway_ports = {53, 80, 443}
    for asset in assets:
        ip = asset.get("ip", "")
        if ip.endswith(".1") or ip.endswith(".254"):
            open_ports = set(asset.get("open_ports", []))
            if open_ports & gateway_ports:
                return ip

    return None


def detect_subnets(assets: list[dict]) -> list[str]:
    """Detect unique subnets from asset IPs.

    Groups by /24 network (e.g., 192.168.1.0/24).
    """
    seen: set[str] = set()
    result: list[str] = []
    for asset in assets:
        ip_str = asset.get("ip")
        if not ip_str:
            continue
        try:
            network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            cidr = str(network)
            if cidr not in seen:
                seen.add(cidr)
                result.append(cidr)
        except ValueError:
            continue
    return result


def _asset_subnet(ip: str) -> str | None:
    """Get /24 subnet CIDR for an IP address."""
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


def _make_device_node(asset: dict, gateway_ip: str | None) -> TopologyNode:
    """Create a TopologyNode from an asset dict."""
    ip = asset.get("ip", "")
    category = asset.get("bigr_category", "unclassified")
    is_gateway = ip == gateway_ip

    node_type = "gateway" if is_gateway else "device"
    size = NODE_SIZES.get(node_type, NODE_SIZES["device"])
    color = CATEGORY_COLORS.get(category, CATEGORY_COLORS["unclassified"])

    label = asset.get("hostname") or asset.get("vendor") or ip

    return TopologyNode(
        id=ip,
        label=label,
        ip=ip,
        mac=asset.get("mac"),
        hostname=asset.get("hostname"),
        vendor=asset.get("vendor"),
        node_type=node_type,
        bigr_category=category,
        confidence=asset.get("confidence_score", 0.0),
        open_ports=asset.get("open_ports", []),
        size=size,
        color=color,
        subnet=_asset_subnet(ip),
        switch_port=asset.get("switch_port"),
    )


def build_topology(
    assets: list[dict], subnets: list[dict] | None = None
) -> TopologyGraph:
    """Build a network topology graph from asset inventory.

    Algorithm:
    1. Detect gateway(s) and subnets
    2. Create subnet group nodes
    3. Create gateway nodes (larger, connected to subnet)
    4. Create device nodes (colored by BIGR category)
    5. Connect devices to their subnet
    6. If switch_port info available, create switch nodes and connect through them
    """
    if not assets:
        return TopologyGraph()

    graph = TopologyGraph()
    gateway_ip = detect_gateway(assets)
    detected_subnets = detect_subnets(assets)

    # 1. Create subnet group nodes
    for cidr in detected_subnets:
        subnet_node = TopologyNode(
            id=cidr,
            label=cidr,
            node_type="subnet",
            size=NODE_SIZES["subnet"],
            color="#334155",
        )
        graph.nodes.append(subnet_node)

    # 2. Track switch hosts for switch node creation
    switch_hosts: set[str] = set()

    # 3. Create device/gateway nodes and edges
    for asset in assets:
        ip = asset.get("ip")
        if not ip:
            continue

        node = _make_device_node(asset, gateway_ip)
        graph.nodes.append(node)

        # Determine which subnet this device belongs to
        subnet_cidr = _asset_subnet(ip)
        if not subnet_cidr:
            continue

        if node.node_type == "gateway":
            # Gateway connects to subnet with gateway edge type
            graph.edges.append(TopologyEdge(
                source=ip,
                target=subnet_cidr,
                edge_type="gateway",
                label="gateway",
            ))
        else:
            # Regular device connects to subnet
            graph.edges.append(TopologyEdge(
                source=ip,
                target=subnet_cidr,
                edge_type="subnet",
            ))

        # Track switch_host for switch node creation
        switch_host = asset.get("switch_host")
        if switch_host:
            switch_hosts.add(switch_host)

    # 4. Create switch nodes and re-route edges through switches
    for sw_host in switch_hosts:
        sw_node = TopologyNode(
            id=f"switch:{sw_host}",
            label=sw_host,
            node_type="switch",
            size=NODE_SIZES["switch"],
            color="#60a5fa",
        )
        graph.nodes.append(sw_node)

        # Connect switch to each subnet it participates in
        for cidr in detected_subnets:
            graph.edges.append(TopologyEdge(
                source=f"switch:{sw_host}",
                target=cidr,
                edge_type="switch",
                label="switch uplink",
            ))

    return graph


def build_subnet_topology(assets: list[dict], subnet_cidr: str) -> TopologyGraph:
    """Build topology for a specific subnet only."""
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
    except ValueError:
        return TopologyGraph()

    filtered = [
        a for a in assets
        if _ip_in_network(a.get("ip", ""), network)
    ]
    return build_topology(filtered)


def _ip_in_network(ip: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Check if an IP address belongs to a network."""
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False
