"""Tests for Guardian configuration."""

from __future__ import annotations

from bigr.guardian.config import (
    BlocklistSource,
    DEFAULT_BLOCKLISTS,
    GuardianConfig,
    load_guardian_config,
)


class TestBlocklistSource:
    def test_create_source(self):
        src = BlocklistSource(
            name="Test", url="https://test.com/hosts"
        )
        assert src.name == "Test"
        assert src.format == "hosts"
        assert src.category == "malware"

    def test_custom_format(self):
        src = BlocklistSource(
            name="Domains", url="https://test.com/domains", format="domains"
        )
        assert src.format == "domains"


class TestDefaultBlocklists:
    def test_has_sources(self):
        assert len(DEFAULT_BLOCKLISTS) >= 2

    def test_stevenblack_present(self):
        names = [bl.name for bl in DEFAULT_BLOCKLISTS]
        assert any("StevenBlack" in n for n in names)

    def test_oisd_present(self):
        names = [bl.name for bl in DEFAULT_BLOCKLISTS]
        assert any("OISD" in n for n in names)


class TestGuardianConfig:
    def test_defaults(self):
        cfg = GuardianConfig()
        assert cfg.dns_host == "0.0.0.0"
        assert cfg.dns_port == 53
        assert cfg.upstream_doh_url == "https://1.1.1.1/dns-query"
        assert cfg.upstream_fallback_ip == "9.9.9.9"
        assert cfg.cache_size == 10000
        assert cfg.cache_ttl == 3600
        assert cfg.blocklist_update_hours == 24
        assert cfg.sinkhole_ip == "0.0.0.0"
        assert len(cfg.blocklists) >= 2

    def test_custom_config(self):
        cfg = GuardianConfig(
            dns_port=5353,
            cache_size=5000,
            sinkhole_ip="127.0.0.1",
        )
        assert cfg.dns_port == 5353
        assert cfg.cache_size == 5000
        assert cfg.sinkhole_ip == "127.0.0.1"

    def test_blocklists_are_independent_copies(self):
        cfg1 = GuardianConfig()
        cfg2 = GuardianConfig()
        cfg1.blocklists.append(
            BlocklistSource(name="Extra", url="https://extra.com")
        )
        assert len(cfg1.blocklists) != len(cfg2.blocklists)


class TestLoadGuardianConfig:
    def test_load_returns_config(self):
        cfg = load_guardian_config()
        assert isinstance(cfg, GuardianConfig)
        assert cfg.dns_port > 0
