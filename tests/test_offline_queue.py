"""Tests for bigr.agent.queue — OfflineQueue file-based queue."""

from __future__ import annotations

import json

import pytest

from bigr.agent.queue import OfflineQueue


@pytest.fixture()
def queue(tmp_path):
    """Create an OfflineQueue backed by a temp directory."""
    return OfflineQueue(tmp_path / "queue")


class TestEnqueue:
    def test_enqueue_creates_file(self, queue):
        path = queue.enqueue({"target": "10.0.0.0/24"}, "discovery")
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["target"] == "10.0.0.0/24"

    def test_enqueue_filename_contains_type(self, queue):
        path = queue.enqueue({}, "shield")
        assert "_shield.json" in path.name

    def test_enqueue_multiple_ordered(self, queue):
        queue.enqueue({"seq": 1}, "discovery")
        queue.enqueue({"seq": 2}, "discovery")
        queue.enqueue({"seq": 3}, "shield")
        assert queue.count() == 3
        files = queue.pending()
        # Verify ordering (oldest first)
        for i, f in enumerate(files):
            data = json.loads(f.read_text())
            assert data["seq"] == i + 1


class TestPending:
    def test_empty_queue_returns_empty(self, queue):
        assert queue.pending() == []
        assert queue.count() == 0

    def test_pending_returns_sorted(self, queue):
        queue.enqueue({"a": 1}, "discovery")
        queue.enqueue({"b": 2}, "shield")
        files = queue.pending()
        assert len(files) == 2
        # First file should have earlier timestamp
        assert files[0].name < files[1].name


class TestDrain:
    def test_drain_sends_all(self, queue):
        queue.enqueue({"target": "10.0.0.0/24"}, "discovery")
        queue.enqueue({"target": "192.168.1.0/24"}, "shield")

        sent_items = []

        def mock_send(payload, payload_type):
            sent_items.append((payload, payload_type))

        sent, failed = queue.drain(mock_send)
        assert sent == 2
        assert failed == 0
        assert queue.count() == 0
        assert sent_items[0][1] == "discovery"
        assert sent_items[1][1] == "shield"

    def test_drain_stops_on_failure(self, queue):
        queue.enqueue({"seq": 1}, "discovery")
        queue.enqueue({"seq": 2}, "discovery")
        queue.enqueue({"seq": 3}, "discovery")

        call_count = 0

        def fail_on_second(payload, payload_type):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ConnectionError("Server down")

        sent, failed = queue.drain(fail_on_second)
        assert sent == 1
        assert failed == 1
        # 2 items should remain (the failed one + the one never attempted)
        assert queue.count() == 2

    def test_drain_empty_queue(self, queue):
        sent, failed = queue.drain(lambda p, t: None)
        assert sent == 0
        assert failed == 0

    def test_drain_removes_corrupt_files(self, queue):
        # Write a corrupt file directly
        corrupt = queue.queue_dir / "0000_discovery.json"
        corrupt.write_text("NOT VALID JSON", encoding="utf-8")
        queue.enqueue({"ok": True}, "discovery")

        sent_items = []
        sent, failed = queue.drain(lambda p, t: sent_items.append(p))
        assert failed == 1  # corrupt file counted as failed
        assert sent == 1  # valid file sent
        assert not corrupt.exists()  # corrupt file removed


class TestClear:
    def test_clear_removes_all(self, queue):
        queue.enqueue({}, "discovery")
        queue.enqueue({}, "shield")
        queue.enqueue({}, "discovery")
        removed = queue.clear()
        assert removed == 3
        assert queue.count() == 0

    def test_clear_empty(self, queue):
        removed = queue.clear()
        assert removed == 0
