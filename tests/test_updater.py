"""Tests for bigr.agent.updater — version comparison and update logic."""

from __future__ import annotations

import pytest

from bigr.agent.updater import _compare_versions, get_local_version


class TestVersionComparison:
    def test_equal_versions(self):
        assert _compare_versions("1.0.0", "1.0.0") == 0

    def test_newer_major(self):
        assert _compare_versions("2.0.0", "1.0.0") > 0

    def test_newer_minor(self):
        assert _compare_versions("1.1.0", "1.0.0") > 0

    def test_newer_patch(self):
        assert _compare_versions("1.0.1", "1.0.0") > 0

    def test_older_version(self):
        assert _compare_versions("0.9.0", "1.0.0") < 0

    def test_different_lengths(self):
        assert _compare_versions("1.0.0.1", "1.0.0") > 0
        assert _compare_versions("1.0", "1.0.0") == 0


class TestGetLocalVersion:
    def test_returns_string(self):
        v = get_local_version()
        assert isinstance(v, str)
        # Should be something like "0.1.0" or fallback "0.0.0"
        assert "." in v
