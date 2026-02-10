"""Offline queue — file-based queue for scan results when cloud API is unreachable.

Stores queued payloads as individual JSON files under ~/.bigr/queue/.
Drains (sends) queued items at the start of each scan cycle.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_QUEUE_DIR = Path.home() / ".bigr" / "queue"


class OfflineQueue:
    """File-based queue for resilient scan result delivery.

    Each enqueued item is written as a separate JSON file in the queue directory.
    Files are named ``{timestamp_ns}_{type}.json`` for ordering.
    """

    def __init__(self, queue_dir: Path | None = None) -> None:
        self._dir = queue_dir or _DEFAULT_QUEUE_DIR
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def queue_dir(self) -> Path:
        return self._dir

    def enqueue(self, payload: dict, payload_type: str = "discovery") -> Path:
        """Write a payload to the queue. Returns the file path."""
        ts = time.time_ns()
        filename = f"{ts}_{payload_type}.json"
        path = self._dir / filename
        path.write_text(json.dumps(payload), encoding="utf-8")
        logger.info("Queued %s payload: %s", payload_type, filename)
        return path

    def pending(self) -> list[Path]:
        """Return sorted list of queued files (oldest first)."""
        if not self._dir.exists():
            return []
        files = sorted(self._dir.glob("*.json"))
        return files

    def count(self) -> int:
        """Return number of pending items."""
        return len(self.pending())

    def drain(self, send_fn: callable) -> tuple[int, int]:
        """Attempt to send all queued items using *send_fn*.

        ``send_fn(payload_dict, payload_type)`` should raise on failure.

        Returns (sent, failed) counts.
        """
        files = self.pending()
        if not files:
            return 0, 0

        sent = 0
        failed = 0

        for path in files:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Corrupt queue file %s: %s — removing", path.name, exc)
                path.unlink(missing_ok=True)
                failed += 1
                continue

            # Infer type from filename: {ts}_{type}.json
            parts = path.stem.split("_", 1)
            payload_type = parts[1] if len(parts) > 1 else "discovery"

            try:
                send_fn(payload, payload_type)
                path.unlink(missing_ok=True)
                sent += 1
                logger.info("Drained %s: %s", payload_type, path.name)
            except Exception as exc:
                logger.warning("Drain failed for %s: %s — will retry next cycle", path.name, exc)
                failed += 1
                break  # Stop on first failure (server likely still down)

        return sent, failed

    def clear(self) -> int:
        """Remove all queued files. Returns count removed."""
        files = self.pending()
        for f in files:
            f.unlink(missing_ok=True)
        return len(files)
