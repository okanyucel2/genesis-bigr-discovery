"""Tests for network topology graph builder (Phase 4C)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from bigr.topology import (
    CATEGORY_COLORS,
    NODE_SIZES,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
    build_subnet_topology,
    build_topology,
    detect_gateway,
    detect_subnets,
)


# ---------------------------------------------------------------------------
# TestTopologyNode
# ---------------------------------------------------------------------------


class TestTopologyNode:
    """Tests for TopologyNode dataclass."""

    def test_defaults(self):
        """Default values are correct."""
        node = TopologyNode(id="192.168.1.1", label="Device")
        assert node.ip is None
        assert node.mac is None
        assert node.hostname is None
        assert node.vendor is None
        assert node.node_type == "device"
        assert node.bigr_category == "unclassified"
        assert node.confidence == 0.0
        assert node.open_ports == []
        assert node.size == 10
        assert node.color == "#6b7280"
        assert node.subnet is None
        assert node.switch_port is None

    def test_to_dict(self):
        """All fields present in dict output."""
        node = TopologyNode(id="10.0.0.1", label="Gateway", ip="10.0.0.1")
        d = node.to_dict()
        expected_keys = {
            "id", "label", "ip", "mac", "hostname", "vendor",
            "type", "bigr_category", "confidence", "open_ports",
            "size", "color", "subnet", "switch_port",
        }
        assert set(d.keys()) == expected_keys
        assert d["id"] == "10.0.0.1"
        assert d["label"] == "Gateway"
        assert d["ip"] == "10.0.0.1"
        assert d["type"] == "device"  # node_type maps to "type" in dict

    def test_custom_node(self):
        """All custom fields set correctly."""
        node = TopologyNode(
            id="192.168.1.100",
            label="Camera",
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="cam-01",
            vendor="Hikvision",
            node_type="device",
            bigr_category="iot",
            confidence=0.85,
            open_ports=[80, 554],
            size=15,
            color="#10b981",
            subnet="192.168.1.0/24",
            switch_port="Gi0/1",
        )
        assert node.id == "192.168.1.100"
        assert node.mac == "aa:bb:cc:dd:ee:ff"
        assert node.hostname == "cam-01"
        assert node.vendor == "Hikvision"
        assert node.bigr_category == "iot"
        assert node.confidence == 0.85
        assert node.open_ports == [80, 554]
        assert node.size == 15
        assert node.color == "#10b981"
        assert node.subnet == "192.168.1.0/24"
        assert node.switch_port == "Gi0/1"
        d = node.to_dict()
        assert d["open_ports"] == [80, 554]
        assert d["switch_port"] == "Gi0/1"


# ---------------------------------------------------------------------------
# TestTopologyEdge
# ---------------------------------------------------------------------------


class TestTopologyEdge:
    """Tests for TopologyEdge dataclass."""

    def test_defaults(self):
        """Default edge_type is 'connection'."""
        edge = TopologyEdge(source="a", target="b")
        assert edge.edge_type == "connection"
        assert edge.label is None

    def test_to_dict(self):
        """Dict output is correct."""
        edge = TopologyEdge(source="gw", target="dev1", edge_type="gateway", label="uplink")
        d = edge.to_dict()
        assert d == {
            "source": "gw",
            "target": "dev1",
            "type": "gateway",
            "label": "uplink",
        }


# ---------------------------------------------------------------------------
# TestTopologyGraph
# ---------------------------------------------------------------------------


class TestTopologyGraph:
    """Tests for TopologyGraph dataclass."""

    def test_empty_graph(self):
        """No nodes/edges yields empty stats."""
        graph = TopologyGraph()
        assert graph.nodes == []
        assert graph.edges == []
        d = graph.to_dict()
        assert d["stats"]["total_nodes"] == 0
        assert d["stats"]["total_edges"] == 0
        assert d["stats"]["node_types"] == {}

    def test_to_dict(self):
        """Full graph serialization works."""
        graph = TopologyGraph(
            nodes=[TopologyNode(id="a", label="A"), TopologyNode(id="b", label="B")],
            edges=[TopologyEdge(source="a", target="b")],
        )
        d = graph.to_dict()
        assert len(d["nodes"]) == 2
        assert len(d["edges"]) == 1
        assert d["nodes"][0]["id"] == "a"
        assert d["edges"][0]["source"] == "a"

    def test_count_by_type(self):
        """Node type counting is correct."""
        graph = TopologyGraph(
            nodes=[
                TopologyNode(id="gw", label="GW", node_type="gateway"),
                TopologyNode(id="d1", label="D1", node_type="device"),
                TopologyNode(id="d2", label="D2", node_type="device"),
                TopologyNode(id="sw", label="SW", node_type="switch"),
            ],
        )
        counts = graph._count_by_type()
        assert counts == {"gateway": 1, "device": 2, "switch": 1}

    def test_stats_in_output(self):
        """Stats are included in to_dict output."""
        graph = TopologyGraph(
            nodes=[TopologyNode(id="x", label="X", node_type="device")],
            edges=[],
        )
        d = graph.to_dict()
        assert "stats" in d
        assert d["stats"]["total_nodes"] == 1
        assert d["stats"]["total_edges"] == 0
        assert d["stats"]["node_types"] == {"device": 1}


# ---------------------------------------------------------------------------
# TestDetectGateway
# ---------------------------------------------------------------------------


class TestDetectGateway:
    """Tests for detect_gateway function."""

    def test_gateway_at_dot_1(self):
        """192.168.1.1 with ag_ve_sistemler is detected as gateway."""
        assets = [
            {"ip": "192.168.1.1", "bigr_category": "ag_ve_sistemler", "open_ports": []},
            {"ip": "192.168.1.50", "bigr_category": "iot", "open_ports": []},
        ]
        assert detect_gateway(assets) == "192.168.1.1"

    def test_gateway_at_dot_254(self):
        """x.x.x.254 with open port 53 is detected as gateway."""
        assets = [
            {"ip": "10.0.0.254", "bigr_category": "unclassified", "open_ports": [53, 80]},
            {"ip": "10.0.0.10", "bigr_category": "iot", "open_ports": []},
        ]
        assert detect_gateway(assets) == "10.0.0.254"

    def test_no_gateway_found(self):
        """No matching IP returns None."""
        assets = [
            {"ip": "192.168.1.50", "bigr_category": "iot", "open_ports": []},
            {"ip": "192.168.1.51", "bigr_category": "uygulamalar", "open_ports": [80]},
        ]
        assert detect_gateway(assets) is None

    def test_gateway_by_ports(self):
        """.1 IP with ports 53,80,443 is detected as gateway."""
        assets = [
            {"ip": "172.16.0.1", "bigr_category": "unclassified", "open_ports": [53, 80, 443]},
            {"ip": "172.16.0.100", "bigr_category": "uygulamalar", "open_ports": [8080]},
        ]
        assert detect_gateway(assets) == "172.16.0.1"

    def test_multiple_subnets(self):
        """Picks the first matching .1 gateway found."""
        assets = [
            {"ip": "192.168.1.1", "bigr_category": "ag_ve_sistemler", "open_ports": []},
            {"ip": "192.168.2.1", "bigr_category": "ag_ve_sistemler", "open_ports": []},
            {"ip": "192.168.1.50", "bigr_category": "iot", "open_ports": []},
        ]
        # Returns the first match
        result = detect_gateway(assets)
        assert result in ("192.168.1.1", "192.168.2.1")


# ---------------------------------------------------------------------------
# TestDetectSubnets
# ---------------------------------------------------------------------------


class TestDetectSubnets:
    """Tests for detect_subnets function."""

    def test_single_subnet(self):
        """All 192.168.1.x gives single subnet."""
        assets = [
            {"ip": "192.168.1.1"},
            {"ip": "192.168.1.50"},
            {"ip": "192.168.1.100"},
        ]
        result = detect_subnets(assets)
        assert result == ["192.168.1.0/24"]

    def test_multiple_subnets(self):
        """Mixed IPs give multiple /24 subnets."""
        assets = [
            {"ip": "192.168.1.1"},
            {"ip": "192.168.2.50"},
            {"ip": "10.0.0.5"},
        ]
        result = detect_subnets(assets)
        assert len(result) == 3
        assert "192.168.1.0/24" in result
        assert "192.168.2.0/24" in result
        assert "10.0.0.0/24" in result

    def test_empty_assets(self):
        """No assets gives empty list."""
        assert detect_subnets([]) == []

    def test_deduplication(self):
        """Same subnet is not repeated."""
        assets = [
            {"ip": "192.168.1.1"},
            {"ip": "192.168.1.2"},
            {"ip": "192.168.1.3"},
        ]
        result = detect_subnets(assets)
        assert result == ["192.168.1.0/24"]


# ---------------------------------------------------------------------------
# TestBuildTopology
# ---------------------------------------------------------------------------


class TestBuildTopology:
    """Tests for build_topology function."""

    @pytest.fixture
    def sample_assets(self):
        return [
            {
                "ip": "192.168.1.1",
                "mac": "aa:bb:cc:dd:ee:01",
                "hostname": "router",
                "vendor": "TP-Link",
                "bigr_category": "ag_ve_sistemler",
                "confidence_score": 0.85,
                "open_ports": [53, 80, 443],
                "os_hint": "Network Equipment",
                "switch_host": None,
                "switch_port": None,
            },
            {
                "ip": "192.168.1.50",
                "mac": "aa:bb:cc:dd:ee:02",
                "hostname": "cam-01",
                "vendor": "Hikvision",
                "bigr_category": "iot",
                "confidence_score": 0.72,
                "open_ports": [80, 554],
                "os_hint": "IP Camera",
                "switch_host": None,
                "switch_port": None,
            },
            {
                "ip": "192.168.1.100",
                "mac": "aa:bb:cc:dd:ee:03",
                "hostname": "web-srv",
                "vendor": "Dell",
                "bigr_category": "uygulamalar",
                "confidence_score": 0.90,
                "open_ports": [80, 443, 8080],
                "os_hint": "Linux",
                "switch_host": None,
                "switch_port": None,
            },
        ]

    def test_basic_topology(self, sample_assets):
        """3 assets produce nodes and edges."""
        graph = build_topology(sample_assets)
        assert len(graph.nodes) >= 3  # at least 3 device nodes
        assert len(graph.edges) >= 3  # at least 3 edges connecting devices

    def test_gateway_node_type(self, sample_assets):
        """Gateway IP gets type='gateway'."""
        graph = build_topology(sample_assets)
        gw_nodes = [n for n in graph.nodes if n.node_type == "gateway"]
        assert len(gw_nodes) >= 1
        assert gw_nodes[0].ip == "192.168.1.1"

    def test_gateway_larger_size(self, sample_assets):
        """Gateway node has larger size than device nodes."""
        graph = build_topology(sample_assets)
        gw_node = next(n for n in graph.nodes if n.node_type == "gateway")
        device_nodes = [n for n in graph.nodes if n.node_type == "device"]
        if device_nodes:
            assert gw_node.size > device_nodes[0].size

    def test_category_colors(self, sample_assets):
        """Nodes are colored by BİGR category."""
        graph = build_topology(sample_assets)
        iot_nodes = [n for n in graph.nodes if n.bigr_category == "iot"]
        assert len(iot_nodes) >= 1
        assert iot_nodes[0].color == CATEGORY_COLORS["iot"]

    def test_subnet_grouping(self, sample_assets):
        """A subnet node is created for each /24."""
        graph = build_topology(sample_assets)
        subnet_nodes = [n for n in graph.nodes if n.node_type == "subnet"]
        assert len(subnet_nodes) >= 1
        assert subnet_nodes[0].id == "192.168.1.0/24"

    def test_edges_connect_to_subnet(self, sample_assets):
        """Device nodes are connected to their subnet node."""
        graph = build_topology(sample_assets)
        subnet_edges = [e for e in graph.edges if e.edge_type == "subnet"]
        # Each device should connect to its subnet
        assert len(subnet_edges) >= 2  # at least cam and web-srv

    def test_gateway_connects_to_subnet(self, sample_assets):
        """Gateway connects to its subnet node."""
        graph = build_topology(sample_assets)
        gw_edges = [e for e in graph.edges if e.edge_type == "gateway"]
        assert len(gw_edges) >= 1
        # Gateway edge should connect to subnet
        gw_edge = gw_edges[0]
        assert "192.168.1.0/24" in (gw_edge.source, gw_edge.target)

    def test_empty_assets(self):
        """No assets produces empty graph."""
        graph = build_topology([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_single_asset(self):
        """One asset produces minimal graph."""
        assets = [
            {
                "ip": "192.168.1.50",
                "mac": "aa:bb:cc:dd:ee:02",
                "hostname": "cam-01",
                "vendor": "Hikvision",
                "bigr_category": "iot",
                "confidence_score": 0.72,
                "open_ports": [80],
                "os_hint": "IP Camera",
            },
        ]
        graph = build_topology(assets)
        assert len(graph.nodes) >= 1  # at least the device node
        # Should have a subnet node too
        subnet_nodes = [n for n in graph.nodes if n.node_type == "subnet"]
        assert len(subnet_nodes) == 1


# ---------------------------------------------------------------------------
# TestBuildSubnetTopology
# ---------------------------------------------------------------------------


class TestBuildSubnetTopology:
    """Tests for build_subnet_topology function."""

    def test_filters_by_subnet(self):
        """Only assets in the specified subnet are included."""
        assets = [
            {"ip": "192.168.1.1", "bigr_category": "ag_ve_sistemler", "open_ports": [53]},
            {"ip": "192.168.1.50", "bigr_category": "iot", "open_ports": [80]},
            {"ip": "10.0.0.5", "bigr_category": "uygulamalar", "open_ports": [443]},
        ]
        graph = build_subnet_topology(assets, "192.168.1.0/24")
        ips = {n.ip for n in graph.nodes if n.ip}
        assert "192.168.1.1" in ips
        assert "192.168.1.50" in ips
        assert "10.0.0.5" not in ips

    def test_different_subnet_excluded(self):
        """Assets from other subnets are excluded."""
        assets = [
            {"ip": "10.0.0.1", "bigr_category": "ag_ve_sistemler", "open_ports": [53]},
            {"ip": "10.0.0.50", "bigr_category": "iot", "open_ports": [80]},
            {"ip": "192.168.1.100", "bigr_category": "uygulamalar", "open_ports": [443]},
        ]
        graph = build_subnet_topology(assets, "10.0.0.0/24")
        ips = {n.ip for n in graph.nodes if n.ip}
        assert "10.0.0.1" in ips
        assert "10.0.0.50" in ips
        assert "192.168.1.100" not in ips


# ---------------------------------------------------------------------------
# TestCategoryColors
# ---------------------------------------------------------------------------


class TestCategoryColors:
    """Tests for CATEGORY_COLORS mapping."""

    def test_all_categories_have_colors(self):
        """Every BigrCategory value has a color."""
        from bigr.models import BigrCategory
        for cat in BigrCategory:
            assert cat.value in CATEGORY_COLORS, f"Missing color for {cat.value}"

    def test_color_format(self):
        """Colors are valid hex format (#xxxxxx)."""
        hex_pattern = re.compile(r"^#[0-9a-fA-F]{6}$")
        for cat, color in CATEGORY_COLORS.items():
            assert hex_pattern.match(color), f"Invalid color format for {cat}: {color}"


# ---------------------------------------------------------------------------
# TestNodeSizes
# ---------------------------------------------------------------------------


class TestNodeSizes:
    """Tests for NODE_SIZES mapping."""

    def test_gateway_largest(self):
        """Gateway > switch > device."""
        assert NODE_SIZES["gateway"] > NODE_SIZES["switch"]
        assert NODE_SIZES["switch"] > NODE_SIZES["device"]

    def test_device_default(self):
        """Default device size is 10."""
        assert NODE_SIZES["device"] == 10


# ---------------------------------------------------------------------------
# TestTopologyApiEndpoints
# ---------------------------------------------------------------------------


class TestTopologyApiEndpoints:
    """Tests for topology API endpoints in the dashboard."""

    @pytest.fixture
    def sample_data(self, tmp_path: Path) -> Path:
        data = {
            "target": "192.168.1.0/24",
            "scan_method": "hybrid",
            "duration_seconds": 12.5,
            "total_assets": 2,
            "category_summary": {"ag_ve_sistemler": 1, "iot": 1},
            "assets": [
                {
                    "ip": "192.168.1.1",
                    "mac": "00:1e:bd:aa:bb:cc",
                    "hostname": "router-01",
                    "vendor": "Cisco",
                    "open_ports": [22, 80, 443],
                    "os_hint": "Linux",
                    "bigr_category": "ag_ve_sistemler",
                    "bigr_category_tr": "Ag ve Sistemler",
                    "confidence_score": 0.85,
                },
                {
                    "ip": "192.168.1.50",
                    "mac": "a4:14:37:00:11:22",
                    "hostname": "cam-01",
                    "vendor": "Hikvision",
                    "open_ports": [80, 554],
                    "os_hint": "IP Camera",
                    "bigr_category": "iot",
                    "bigr_category_tr": "IoT",
                    "confidence_score": 0.72,
                },
            ],
        }
        json_path = tmp_path / "assets.json"
        json_path.write_text(json.dumps(data))
        return json_path

    @pytest.fixture
    def app(self, sample_data: Path):
        from bigr.dashboard.app import create_app
        return create_app(data_path=str(sample_data))

    @pytest.mark.asyncio
    async def test_topology_endpoint(self, app):
        """/api/topology returns valid graph JSON."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/topology")
            assert resp.status_code == 200
            data = resp.json()
            assert "nodes" in data
            assert "edges" in data
            assert "stats" in data
            assert data["stats"]["total_nodes"] >= 2

    @pytest.mark.asyncio
    async def test_topology_subnet_endpoint(self, app):
        """/api/topology/subnet/x returns filtered graph."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/topology/subnet/192.168.1.0/24")
            assert resp.status_code == 200
            data = resp.json()
            assert "nodes" in data
            assert "edges" in data

    @pytest.mark.asyncio
    async def test_topology_page_returns_html(self, app):
        """/topology returns an HTML page."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/topology")
            assert resp.status_code == 200
            assert "text/html" in resp.headers.get("content-type", "")
            assert "d3" in resp.text.lower() or "topology" in resp.text.lower()
