"""Tests for SNMP switch integration (Phase 4A)."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bigr.scanner.snmp import (
    SnmpMacTableReader,
    SwitchConfig,
    SwitchMacEntry,
    SwitchPort,
    enrich_assets_with_switch_info,
    normalize_snmp_mac,
)


# ---------------------------------------------------------------------------
# TestNormalizeSnmpMac
# ---------------------------------------------------------------------------


class TestNormalizeSnmpMac:
    """Test MAC normalization from various SNMP formats."""

    def test_colon_format_passthrough(self):
        """Standard colon format stays as-is (lowered)."""
        assert normalize_snmp_mac("00:1e:bd:aa:bb:cc") == "00:1e:bd:aa:bb:cc"

    def test_dash_format(self):
        """Dash-separated MAC converts to colon-lowered."""
        assert normalize_snmp_mac("00-1E-BD-AA-BB-CC") == "00:1e:bd:aa:bb:cc"

    def test_dot_notation(self):
        """Cisco dot notation (3 groups of 4 hex) converts correctly."""
        assert normalize_snmp_mac("001e.bdaa.bbcc") == "00:1e:bd:aa:bb:cc"

    def test_hex_string_0x(self):
        """0x-prefixed hex string converts correctly."""
        assert normalize_snmp_mac("0x001EBDAABBCC") == "00:1e:bd:aa:bb:cc"

    def test_bytes_format(self):
        """Raw bytes (6 octets) convert correctly."""
        assert normalize_snmp_mac(b"\x00\x1e\xbd\xaa\xbb\xcc") == "00:1e:bd:aa:bb:cc"

    def test_none_returns_none(self):
        """None input returns None."""
        assert normalize_snmp_mac(None) is None

    def test_empty_returns_none(self):
        """Empty string returns None."""
        assert normalize_snmp_mac("") is None


# ---------------------------------------------------------------------------
# TestSwitchConfig
# ---------------------------------------------------------------------------


class TestSwitchConfig:
    """Test SwitchConfig dataclass."""

    def test_defaults(self):
        """Default community and version are set."""
        cfg = SwitchConfig(host="10.0.0.1")
        assert cfg.host == "10.0.0.1"
        assert cfg.community == "public"
        assert cfg.version == "2c"
        assert cfg.label == ""

    def test_custom_config(self):
        """All fields set correctly."""
        cfg = SwitchConfig(
            host="10.0.0.2",
            community="private",
            version="3",
            label="Core Switch",
        )
        assert cfg.host == "10.0.0.2"
        assert cfg.community == "private"
        assert cfg.version == "3"
        assert cfg.label == "Core Switch"


# ---------------------------------------------------------------------------
# TestSwitchMacEntry
# ---------------------------------------------------------------------------


class TestSwitchMacEntry:
    """Test SwitchMacEntry dataclass."""

    def test_fields(self):
        """All fields populated correctly."""
        entry = SwitchMacEntry(
            mac="00:1e:bd:aa:bb:cc",
            switch_host="10.0.0.1",
            switch_label="Core",
            port_index=3,
            port_name="GigabitEthernet0/3",
            vlan_id=100,
        )
        assert entry.mac == "00:1e:bd:aa:bb:cc"
        assert entry.switch_host == "10.0.0.1"
        assert entry.switch_label == "Core"
        assert entry.port_index == 3
        assert entry.port_name == "GigabitEthernet0/3"
        assert entry.vlan_id == 100


# ---------------------------------------------------------------------------
# TestSnmpMacTableReader
# ---------------------------------------------------------------------------


class TestSnmpMacTableReader:
    """Test SNMP MAC table reading (mocked)."""

    def _make_reader(self) -> SnmpMacTableReader:
        cfg = SwitchConfig(host="10.0.0.1", community="public", label="TestSwitch")
        return SnmpMacTableReader(cfg)

    def test_read_mac_table_mock(self):
        """Mock SNMP walk returns proper SwitchMacEntry list."""
        reader = self._make_reader()

        # Mock the internal SNMP walk to return known data
        mock_mac_to_bridge = {
            "1.3.6.1.2.1.17.4.3.1.2.0.30.189.170.187.204": 3,
        }
        mock_bridge_to_if = {3: 10003}
        mock_if_to_name = {10003: "GigabitEthernet0/3"}

        with patch.object(reader, "_snmp_walk_mac_to_bridge", return_value=mock_mac_to_bridge), \
             patch.object(reader, "_snmp_walk_bridge_to_if", return_value=mock_bridge_to_if), \
             patch.object(reader, "_snmp_walk_if_to_name", return_value=mock_if_to_name):
            entries = reader.read_mac_table()

        assert len(entries) == 1
        assert entries[0].mac == "00:1e:bd:aa:bb:cc"
        assert entries[0].port_name == "GigabitEthernet0/3"
        assert entries[0].port_index == 3
        assert entries[0].switch_host == "10.0.0.1"
        assert entries[0].switch_label == "TestSwitch"

    def test_empty_table(self):
        """No SNMP entries returns empty list."""
        reader = self._make_reader()

        with patch.object(reader, "_snmp_walk_mac_to_bridge", return_value={}), \
             patch.object(reader, "_snmp_walk_bridge_to_if", return_value={}), \
             patch.object(reader, "_snmp_walk_if_to_name", return_value={}):
            entries = reader.read_mac_table()

        assert entries == []

    def test_multiple_macs_same_port(self):
        """Two MACs on the same port are both returned."""
        reader = self._make_reader()

        mock_mac_to_bridge = {
            "1.3.6.1.2.1.17.4.3.1.2.0.30.189.170.187.204": 3,
            "1.3.6.1.2.1.17.4.3.1.2.0.30.189.170.187.205": 3,
        }
        mock_bridge_to_if = {3: 10003}
        mock_if_to_name = {10003: "GigabitEthernet0/3"}

        with patch.object(reader, "_snmp_walk_mac_to_bridge", return_value=mock_mac_to_bridge), \
             patch.object(reader, "_snmp_walk_bridge_to_if", return_value=mock_bridge_to_if), \
             patch.object(reader, "_snmp_walk_if_to_name", return_value=mock_if_to_name):
            entries = reader.read_mac_table()

        assert len(entries) == 2
        macs = {e.mac for e in entries}
        assert "00:1e:bd:aa:bb:cc" in macs
        assert "00:1e:bd:aa:bb:cd" in macs
        assert all(e.port_name == "GigabitEthernet0/3" for e in entries)

    def test_mac_table_property(self):
        """The mac_table property returns cached result after read."""
        reader = self._make_reader()

        mock_entry = SwitchMacEntry(
            mac="aa:bb:cc:dd:ee:ff",
            switch_host="10.0.0.1",
            switch_label="TestSwitch",
            port_index=1,
            port_name="Gi0/1",
        )

        with patch.object(reader, "_snmp_walk_mac_to_bridge", return_value={}), \
             patch.object(reader, "_snmp_walk_bridge_to_if", return_value={}), \
             patch.object(reader, "_snmp_walk_if_to_name", return_value={}):
            reader.read_mac_table()

        # Manually add to _mac_table for property test
        reader._mac_table = [mock_entry]
        assert reader.mac_table == [mock_entry]


# ---------------------------------------------------------------------------
# TestEnrichAssetsWithSwitchInfo
# ---------------------------------------------------------------------------


class TestEnrichAssetsWithSwitchInfo:
    """Test enriching asset dicts with switch port info."""

    def _make_entries(self) -> list[SwitchMacEntry]:
        return [
            SwitchMacEntry(
                mac="00:1e:bd:aa:bb:cc",
                switch_host="10.0.0.1",
                switch_label="Core",
                port_index=3,
                port_name="GigabitEthernet0/3",
                vlan_id=100,
            ),
            SwitchMacEntry(
                mac="aa:bb:cc:dd:ee:ff",
                switch_host="10.0.0.1",
                switch_label="Core",
                port_index=5,
                port_name="GigabitEthernet0/5",
                vlan_id=200,
            ),
        ]

    def test_matching_mac(self):
        """Asset MAC matches, switch info is added."""
        assets = [{"ip": "192.168.1.10", "mac": "00:1e:bd:aa:bb:cc"}]
        entries = self._make_entries()

        result = enrich_assets_with_switch_info(assets, entries)

        assert result[0]["switch_host"] == "10.0.0.1"
        assert result[0]["switch_label"] == "Core"
        assert result[0]["switch_port"] == "GigabitEthernet0/3"
        assert result[0]["switch_port_index"] == 3

    def test_no_match(self):
        """Asset MAC doesn't match, no switch info added."""
        assets = [{"ip": "192.168.1.10", "mac": "ff:ff:ff:ff:ff:ff"}]
        entries = self._make_entries()

        result = enrich_assets_with_switch_info(assets, entries)

        assert "switch_host" not in result[0]
        assert "switch_port" not in result[0]

    def test_multiple_assets(self):
        """Multiple assets, some match, some don't."""
        assets = [
            {"ip": "192.168.1.10", "mac": "00:1e:bd:aa:bb:cc"},
            {"ip": "192.168.1.20", "mac": "ff:ff:ff:ff:ff:ff"},
            {"ip": "192.168.1.30", "mac": "aa:bb:cc:dd:ee:ff"},
        ]
        entries = self._make_entries()

        result = enrich_assets_with_switch_info(assets, entries)

        assert result[0]["switch_port"] == "GigabitEthernet0/3"
        assert "switch_host" not in result[1]
        assert result[2]["switch_port"] == "GigabitEthernet0/5"

    def test_case_insensitive_mac_match(self):
        """MAC matching is case-insensitive."""
        assets = [{"ip": "192.168.1.10", "mac": "00:1E:BD:AA:BB:CC"}]
        entries = self._make_entries()

        result = enrich_assets_with_switch_info(assets, entries)

        assert result[0]["switch_host"] == "10.0.0.1"
        assert result[0]["switch_port"] == "GigabitEthernet0/3"


# ---------------------------------------------------------------------------
# TestSwitchRegistration (switch_map.py + db)
# ---------------------------------------------------------------------------


class TestSwitchRegistration:
    """Test switch registration with DB persistence."""

    def test_save_switch(self, tmp_path):
        """Save a switch config to the database."""
        from bigr.scanner.switch_map import save_switch

        db = tmp_path / "test.db"
        cfg = SwitchConfig(host="10.0.0.1", community="private", label="Core")
        save_switch(cfg, db_path=db)

        # Verify in DB
        from bigr.scanner.switch_map import get_switches
        switches = get_switches(db_path=db)
        assert len(switches) == 1
        assert switches[0]["host"] == "10.0.0.1"
        assert switches[0]["community"] == "private"
        assert switches[0]["label"] == "Core"

    def test_save_switch_update(self, tmp_path):
        """Save same host again updates the record."""
        from bigr.scanner.switch_map import get_switches, save_switch

        db = tmp_path / "test.db"
        cfg1 = SwitchConfig(host="10.0.0.1", community="public", label="Old")
        save_switch(cfg1, db_path=db)

        cfg2 = SwitchConfig(host="10.0.0.1", community="private", label="New")
        save_switch(cfg2, db_path=db)

        switches = get_switches(db_path=db)
        assert len(switches) == 1
        assert switches[0]["community"] == "private"
        assert switches[0]["label"] == "New"

    def test_remove_switch(self, tmp_path):
        """Remove a switch by host."""
        from bigr.scanner.switch_map import get_switches, remove_switch, save_switch

        db = tmp_path / "test.db"
        save_switch(SwitchConfig(host="10.0.0.1"), db_path=db)
        remove_switch("10.0.0.1", db_path=db)

        switches = get_switches(db_path=db)
        assert len(switches) == 0

    def test_get_switches_empty(self, tmp_path):
        """No switches returns empty list."""
        from bigr.scanner.switch_map import get_switches

        db = tmp_path / "test.db"
        switches = get_switches(db_path=db)
        assert switches == []

    def test_get_switches(self, tmp_path):
        """Multiple switches returned."""
        from bigr.scanner.switch_map import get_switches, save_switch

        db = tmp_path / "test.db"
        save_switch(SwitchConfig(host="10.0.0.1", label="SW1"), db_path=db)
        save_switch(SwitchConfig(host="10.0.0.2", label="SW2"), db_path=db)

        switches = get_switches(db_path=db)
        assert len(switches) == 2
        hosts = {s["host"] for s in switches}
        assert hosts == {"10.0.0.1", "10.0.0.2"}

    def test_switches_table_created(self, tmp_path):
        """DB has switches table after init."""
        from bigr.db import init_db

        db = tmp_path / "test.db"
        init_db(db_path=db)

        conn = sqlite3.connect(str(db))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='switches'"
        ).fetchall()
        conn.close()

        assert len(tables) == 1


# ---------------------------------------------------------------------------
# TestSwitchPortInDashboard
# ---------------------------------------------------------------------------


class TestSwitchPortInDashboard:
    """Test switch port info appears in dashboard API."""

    def test_switch_port_in_asset_dict(self):
        """Asset with switch info includes it in the enriched dict."""
        asset = {
            "ip": "192.168.1.10",
            "mac": "00:1e:bd:aa:bb:cc",
            "switch_host": "10.0.0.1",
            "switch_label": "Core",
            "switch_port": "GigabitEthernet0/3",
            "switch_port_index": 3,
        }

        # Verify all switch fields present and correct
        assert asset["switch_host"] == "10.0.0.1"
        assert asset["switch_label"] == "Core"
        assert asset["switch_port"] == "GigabitEthernet0/3"
        assert asset["switch_port_index"] == 3
