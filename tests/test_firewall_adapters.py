"""Tests for the Windows, Linux firewall adapters and platform detection.

This module tests:
- WindowsFirewallAdapter (WFP stub)
- LinuxFirewallAdapter (nftables stub)
- Platform detection and adapter factory (platform.py)
- Interface compliance across all adapters

Since we develop on macOS, both Windows and Linux adapters run in stub mode.
Tests verify correct stub behaviour, state transitions, and data structures.
"""

from __future__ import annotations

import platform

import pytest

from bigr.firewall.adapters.windows import WindowsFirewallAdapter
from bigr.firewall.adapters.linux import LinuxFirewallAdapter
from bigr.firewall.models import FirewallRule
from bigr.firewall.platform import detect_platform, get_adapter, get_all_adapters


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(
    rule_id: str = "r1",
    rule_type: str = "block_ip",
    target: str = "10.0.0.1",
    protocol: str = "tcp",
    direction: str = "outbound",
) -> FirewallRule:
    """Create a FirewallRule for testing."""
    return FirewallRule(
        id=rule_id,
        rule_type=rule_type,
        target=target,
        protocol=protocol,
        direction=direction,
        reason="test rule",
    )


def _sample_rules() -> list[FirewallRule]:
    """Return a mixed set of rules for testing."""
    return [
        _make_rule("r1", "block_ip", "10.0.0.1"),
        _make_rule("r2", "block_port", "443"),
        _make_rule("r3", "block_domain", "malware.example.com"),
        _make_rule("r4", "allow_ip", "192.168.1.1"),
        _make_rule("r5", "allow_domain", "trusted.example.com"),
    ]


# ===========================================================================
# Windows Adapter
# ===========================================================================


class TestWindowsAdapter:
    """Tests for WindowsFirewallAdapter."""

    @pytest.fixture()
    def adapter(self) -> WindowsFirewallAdapter:
        return WindowsFirewallAdapter()

    @pytest.mark.asyncio
    async def test_install_returns_stub_on_non_windows(self, adapter: WindowsFirewallAdapter) -> None:
        """On macOS/Linux install() should return status='stub'."""
        result = await adapter.install()
        if platform.system() != "Windows":
            assert result["status"] == "stub"
        assert result["platform"] == "windows"
        assert "engine" in result

    @pytest.mark.asyncio
    async def test_install_sets_installed_flag(self, adapter: WindowsFirewallAdapter) -> None:
        assert adapter._is_installed is False
        await adapter.install()
        assert adapter._is_installed is True

    @pytest.mark.asyncio
    async def test_uninstall_resets_state(self, adapter: WindowsFirewallAdapter) -> None:
        await adapter.install()
        rules = [_make_rule()]
        await adapter.apply_rules(rules)
        assert adapter._is_installed is True
        assert adapter._rules_applied == 1

        result = await adapter.uninstall()
        assert result["status"] == "ok"
        assert adapter._is_installed is False
        assert adapter._rules_applied == 0

    @pytest.mark.asyncio
    async def test_apply_rules_counts_correctly(self, adapter: WindowsFirewallAdapter) -> None:
        rules = _sample_rules()
        result = await adapter.apply_rules(rules)
        assert result["rules_pushed"] == 5
        assert adapter._rules_applied == 5

    @pytest.mark.asyncio
    async def test_apply_rules_categorises_types(self, adapter: WindowsFirewallAdapter) -> None:
        rules = _sample_rules()
        result = await adapter.apply_rules(rules)
        breakdown = result["breakdown"]
        assert breakdown["ip_rules"] == 2      # block_ip + allow_ip
        assert breakdown["port_rules"] == 1    # block_port
        assert breakdown["domain_rules"] == 2  # block_domain + allow_domain

    @pytest.mark.asyncio
    async def test_apply_rules_empty_list(self, adapter: WindowsFirewallAdapter) -> None:
        result = await adapter.apply_rules([])
        assert result["rules_pushed"] == 0
        assert result["breakdown"]["ip_rules"] == 0
        assert result["breakdown"]["port_rules"] == 0
        assert result["breakdown"]["domain_rules"] == 0
        assert adapter._rules_applied == 0

    @pytest.mark.asyncio
    async def test_apply_rules_returns_wfp_layers(self, adapter: WindowsFirewallAdapter) -> None:
        result = await adapter.apply_rules(_sample_rules())
        layers = result["wfp_layers"]
        assert "FWPM_LAYER_ALE_AUTH_CONNECT_V4" in layers
        assert "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4" in layers

    @pytest.mark.asyncio
    async def test_apply_rules_produces_filter_descriptors(self, adapter: WindowsFirewallAdapter) -> None:
        rules = [_make_rule("r1", "block_ip", "10.0.0.1")]
        result = await adapter.apply_rules(rules)
        descriptors = result["filter_descriptors"]
        assert len(descriptors) == 1
        d = descriptors[0]
        assert d["rule_id"] == "r1"
        assert d["wfp_action"] == "FWP_ACTION_BLOCK"
        assert d["wfp_condition"] == "FWP_CONDITION_IP_REMOTE_ADDRESS"
        assert "FWPM_LAYER_ALE_AUTH_CONNECT_V4" in d["wfp_layer"]

    @pytest.mark.asyncio
    async def test_apply_rules_permit_action_for_allow(self, adapter: WindowsFirewallAdapter) -> None:
        rules = [_make_rule("r1", "allow_ip", "192.168.1.1")]
        result = await adapter.apply_rules(rules)
        d = result["filter_descriptors"][0]
        assert d["wfp_action"] == "FWP_ACTION_PERMIT"

    @pytest.mark.asyncio
    async def test_apply_rules_port_descriptor(self, adapter: WindowsFirewallAdapter) -> None:
        rules = [_make_rule("r1", "block_port", "8080")]
        result = await adapter.apply_rules(rules)
        d = result["filter_descriptors"][0]
        assert d["wfp_condition"] == "FWP_CONDITION_IP_REMOTE_PORT"

    @pytest.mark.asyncio
    async def test_apply_rules_domain_descriptor_note(self, adapter: WindowsFirewallAdapter) -> None:
        rules = [_make_rule("r1", "block_domain", "evil.example.com")]
        result = await adapter.apply_rules(rules)
        d = result["filter_descriptors"][0]
        assert d["wfp_condition"] == "DNS_REDIRECT"
        assert "note" in d
        assert "callout" in d["note"].lower()

    @pytest.mark.asyncio
    async def test_get_status_fields(self, adapter: WindowsFirewallAdapter) -> None:
        status = await adapter.get_status()
        assert status["platform"] == "windows"
        assert status["engine"] == "wfp"
        assert status["is_installed"] is False
        assert status["rules_applied"] == 0
        assert status["requires_admin"] is True
        assert "supported_layers" in status
        assert len(status["supported_layers"]) == 4

    @pytest.mark.asyncio
    async def test_get_status_after_install(self, adapter: WindowsFirewallAdapter) -> None:
        await adapter.install()
        status = await adapter.get_status()
        assert status["is_installed"] is True
        assert status["sublayer"] == WindowsFirewallAdapter.BIGR_SUBLAYER_KEY

    def test_platform_name(self, adapter: WindowsFirewallAdapter) -> None:
        assert adapter.platform_name() == "windows"

    def test_wfp_layers_class_constant(self) -> None:
        assert len(WindowsFirewallAdapter.WFP_LAYERS) == 4
        for layer in WindowsFirewallAdapter.WFP_LAYERS:
            assert layer.startswith("FWPM_LAYER_ALE_AUTH_")

    def test_sublayer_key_class_constant(self) -> None:
        assert WindowsFirewallAdapter.BIGR_SUBLAYER_KEY == "BIGR-FILTER-SUBLAYER-0001"


# ===========================================================================
# Linux Adapter
# ===========================================================================


class TestLinuxAdapter:
    """Tests for LinuxFirewallAdapter."""

    @pytest.fixture()
    def adapter(self) -> LinuxFirewallAdapter:
        return LinuxFirewallAdapter()

    @pytest.mark.asyncio
    async def test_install_returns_stub_on_non_linux(self, adapter: LinuxFirewallAdapter) -> None:
        result = await adapter.install()
        if platform.system() != "Linux":
            assert result["status"] == "stub"
        assert result["platform"] == "linux"
        assert "engine" in result

    @pytest.mark.asyncio
    async def test_install_sets_installed_flag(self, adapter: LinuxFirewallAdapter) -> None:
        assert adapter._is_installed is False
        await adapter.install()
        assert adapter._is_installed is True

    @pytest.mark.asyncio
    async def test_install_returns_table_name(self, adapter: LinuxFirewallAdapter) -> None:
        result = await adapter.install()
        assert result["table"] == "inet bigr_filter"

    @pytest.mark.asyncio
    async def test_uninstall_resets_state(self, adapter: LinuxFirewallAdapter) -> None:
        await adapter.install()
        await adapter.apply_rules([_make_rule()])
        assert adapter._is_installed is True
        assert adapter._rules_applied == 1

        result = await adapter.uninstall()
        assert result["status"] == "ok"
        assert adapter._is_installed is False
        assert adapter._rules_applied == 0

    @pytest.mark.asyncio
    async def test_apply_rules_counts_correctly(self, adapter: LinuxFirewallAdapter) -> None:
        rules = _sample_rules()
        result = await adapter.apply_rules(rules)
        assert result["rules_pushed"] == 5
        assert adapter._rules_applied == 5

    @pytest.mark.asyncio
    async def test_apply_rules_generates_nft_commands(self, adapter: LinuxFirewallAdapter) -> None:
        rules = _sample_rules()
        result = await adapter.apply_rules(rules)
        cmds = result["nft_commands_preview"]
        assert len(cmds) > 0
        # First two commands should be flushes
        assert "flush" in cmds[0]
        assert "flush" in cmds[1]

    @pytest.mark.asyncio
    async def test_apply_rules_block_ip_command(self, adapter: LinuxFirewallAdapter) -> None:
        rules = [_make_rule("r1", "block_ip", "10.0.0.1")]
        result = await adapter.apply_rules(rules)
        cmds = result["nft_commands_preview"]
        ip_cmd = [c for c in cmds if "10.0.0.1" in c]
        assert len(ip_cmd) == 1
        assert "ip daddr 10.0.0.1" in ip_cmd[0]
        assert "drop" in ip_cmd[0]

    @pytest.mark.asyncio
    async def test_apply_rules_block_port_command(self, adapter: LinuxFirewallAdapter) -> None:
        rules = [_make_rule("r1", "block_port", "8080", protocol="tcp")]
        result = await adapter.apply_rules(rules)
        cmds = result["nft_commands_preview"]
        port_cmd = [c for c in cmds if "8080" in c]
        assert len(port_cmd) == 1
        assert "tcp dport 8080" in port_cmd[0]
        assert "drop" in port_cmd[0]

    @pytest.mark.asyncio
    async def test_apply_rules_block_port_uses_rule_protocol(self, adapter: LinuxFirewallAdapter) -> None:
        rules = [_make_rule("r1", "block_port", "53", protocol="udp")]
        result = await adapter.apply_rules(rules)
        cmds = result["nft_commands_preview"]
        port_cmd = [c for c in cmds if "53" in c]
        assert len(port_cmd) == 1
        assert "udp dport 53" in port_cmd[0]

    @pytest.mark.asyncio
    async def test_apply_rules_allow_ip_command(self, adapter: LinuxFirewallAdapter) -> None:
        rules = [_make_rule("r1", "allow_ip", "192.168.1.1")]
        result = await adapter.apply_rules(rules)
        cmds = result["nft_commands_preview"]
        ip_cmd = [c for c in cmds if "192.168.1.1" in c]
        assert len(ip_cmd) == 1
        assert "ip daddr 192.168.1.1" in ip_cmd[0]
        assert "accept" in ip_cmd[0]

    @pytest.mark.asyncio
    async def test_apply_rules_empty_list(self, adapter: LinuxFirewallAdapter) -> None:
        result = await adapter.apply_rules([])
        assert result["rules_pushed"] == 0
        assert adapter._rules_applied == 0
        # Even empty should have flush commands
        cmds = result["nft_commands_preview"]
        assert len(cmds) == 2  # Two flushes only
        assert "flush" in cmds[0]

    @pytest.mark.asyncio
    async def test_apply_rules_returns_backend(self, adapter: LinuxFirewallAdapter) -> None:
        result = await adapter.apply_rules([_make_rule()])
        assert result["backend"] == "nftables"

    @pytest.mark.asyncio
    async def test_apply_rules_nft_commands_total(self, adapter: LinuxFirewallAdapter) -> None:
        rules = _sample_rules()
        result = await adapter.apply_rules(rules)
        # 2 flushes + at least 1 command per rule
        assert result["nft_commands_total"] >= 2 + len(rules)

    @pytest.mark.asyncio
    async def test_get_status_fields(self, adapter: LinuxFirewallAdapter) -> None:
        status = await adapter.get_status()
        assert status["platform"] == "linux"
        assert status["engine"] == "nftables"
        assert status["is_installed"] is False
        assert status["rules_applied"] == 0
        assert status["requires_root"] is True
        assert status["nftables_table"] == "inet bigr_filter"
        assert "nftables" in status["supported_backends"]
        assert "iptables" in status["supported_backends"]

    @pytest.mark.asyncio
    async def test_get_status_after_install_and_rules(self, adapter: LinuxFirewallAdapter) -> None:
        await adapter.install()
        await adapter.apply_rules(_sample_rules())
        status = await adapter.get_status()
        assert status["is_installed"] is True
        assert status["rules_applied"] == 5

    def test_platform_name(self, adapter: LinuxFirewallAdapter) -> None:
        assert adapter.platform_name() == "linux"

    def test_nft_table_class_constant(self) -> None:
        assert LinuxFirewallAdapter.NFT_TABLE == "inet bigr_filter"

    def test_ipt_chain_class_constant(self) -> None:
        assert LinuxFirewallAdapter.IPT_CHAIN == "BIGR_FILTER"

    @pytest.mark.asyncio
    async def test_apply_rules_block_domain_generates_set_comment(self, adapter: LinuxFirewallAdapter) -> None:
        rules = [_make_rule("r1", "block_domain", "evil.example.com")]
        result = await adapter.apply_rules(rules)
        cmds = result["nft_commands_preview"]
        # Should include a comment about DNS resolve
        domain_cmds = [c for c in cmds if "evil.example.com" in c]
        assert len(domain_cmds) >= 1


# ===========================================================================
# Platform Detection
# ===========================================================================


class TestPlatformDetection:
    """Tests for detect_platform(), get_adapter(), and get_all_adapters()."""

    def test_detect_platform_returns_string(self) -> None:
        result = detect_platform()
        assert isinstance(result, str)

    def test_detect_platform_is_known(self) -> None:
        result = detect_platform()
        assert result in ("macos", "windows", "linux", "unknown")

    def test_detect_platform_matches_system(self) -> None:
        """On the current host, detect_platform should match platform.system()."""
        system = platform.system()
        result = detect_platform()
        if system == "Darwin":
            assert result == "macos"
        elif system == "Windows":
            assert result == "windows"
        elif system == "Linux":
            assert result == "linux"

    def test_get_adapter_returns_instance(self) -> None:
        """get_adapter() with override should return an adapter instance."""
        adapter = get_adapter("windows")
        assert adapter is not None

    def test_get_adapter_override_windows(self) -> None:
        adapter = get_adapter("windows")
        assert isinstance(adapter, WindowsFirewallAdapter)
        assert adapter.platform_name() == "windows"

    def test_get_adapter_override_linux(self) -> None:
        adapter = get_adapter("linux")
        assert isinstance(adapter, LinuxFirewallAdapter)
        assert adapter.platform_name() == "linux"

    def test_get_adapter_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported platform"):
            get_adapter("freebsd")

    def test_get_adapter_unknown_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported platform"):
            get_adapter("unknown")

    def test_get_all_adapters_structure(self) -> None:
        info = get_all_adapters()
        assert "current_platform" in info
        assert "adapters" in info
        assert "macos" in info["adapters"]
        assert "windows" in info["adapters"]
        assert "linux" in info["adapters"]

    def test_get_all_adapters_has_current_platform(self) -> None:
        info = get_all_adapters()
        current = info["current_platform"]
        assert current in ("macos", "windows", "linux", "unknown")
        # The current platform's entry should have is_current=True
        if current in info["adapters"]:
            assert info["adapters"][current]["is_current"] is True

    def test_get_all_adapters_non_current_is_false(self) -> None:
        info = get_all_adapters()
        current = info["current_platform"]
        for name, meta in info["adapters"].items():
            if name != current:
                assert meta["is_current"] is False

    def test_get_all_adapters_has_required_fields(self) -> None:
        info = get_all_adapters()
        for _name, meta in info["adapters"].items():
            assert "name" in meta
            assert "engine" in meta
            assert "is_current" in meta
            assert "requires" in meta
            assert "min_version" in meta

    def test_get_all_adapters_engine_names(self) -> None:
        info = get_all_adapters()
        assert info["adapters"]["macos"]["engine"] == "ne_filter"
        assert info["adapters"]["windows"]["engine"] == "wfp"
        assert info["adapters"]["linux"]["engine"] == "nftables"


# ===========================================================================
# Adapter Interface Compliance
# ===========================================================================


class TestAdapterInterface:
    """Verify all adapters implement the required interface methods."""

    @pytest.fixture(params=["windows", "linux"])
    def adapter(self, request: pytest.FixtureRequest) -> WindowsFirewallAdapter | LinuxFirewallAdapter:
        return get_adapter(request.param)

    def test_has_install_method(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        assert hasattr(adapter, "install")
        assert callable(adapter.install)

    def test_has_uninstall_method(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        assert hasattr(adapter, "uninstall")
        assert callable(adapter.uninstall)

    def test_has_apply_rules_method(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        assert hasattr(adapter, "apply_rules")
        assert callable(adapter.apply_rules)

    def test_has_get_status_method(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        assert hasattr(adapter, "get_status")
        assert callable(adapter.get_status)

    def test_has_platform_name_method(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        assert hasattr(adapter, "platform_name")
        assert callable(adapter.platform_name)

    def test_platform_name_returns_string(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        name = adapter.platform_name()
        assert isinstance(name, str)
        assert name in ("windows", "linux", "macos")

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        """Verify install -> apply_rules -> get_status -> uninstall cycle."""
        # Install
        install_result = await adapter.install()
        assert "status" in install_result

        # Apply rules
        rules = _sample_rules()
        apply_result = await adapter.apply_rules(rules)
        assert "rules_pushed" in apply_result
        assert apply_result["rules_pushed"] == len(rules)

        # Status
        status = await adapter.get_status()
        assert status["is_installed"] is True
        assert status["rules_applied"] == len(rules)

        # Uninstall
        uninstall_result = await adapter.uninstall()
        assert uninstall_result["status"] == "ok"

        # Verify reset
        status_after = await adapter.get_status()
        assert status_after["is_installed"] is False
        assert status_after["rules_applied"] == 0

    @pytest.mark.asyncio
    async def test_install_is_idempotent(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        """Calling install() twice should not fail."""
        await adapter.install()
        result = await adapter.install()
        assert "status" in result

    @pytest.mark.asyncio
    async def test_uninstall_without_install(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        """Calling uninstall() before install() should not fail."""
        result = await adapter.uninstall()
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_apply_rules_returns_dict(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        result = await adapter.apply_rules([_make_rule()])
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_status_returns_dict(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        result = await adapter.get_status()
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_get_status_has_platform_field(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        status = await adapter.get_status()
        assert "platform" in status
        assert status["platform"] == adapter.platform_name()

    @pytest.mark.asyncio
    async def test_get_status_has_engine_field(self, adapter: WindowsFirewallAdapter | LinuxFirewallAdapter) -> None:
        status = await adapter.get_status()
        assert "engine" in status
        assert isinstance(status["engine"], str)
