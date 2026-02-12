"""Guardian daemon — lifecycle management for the DNS filtering server."""

from __future__ import annotations

import asyncio
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from bigr.guardian.config import GuardianConfig, load_guardian_config
from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.dns.cache import DNSCache
from bigr.guardian.dns.decision import QueryDecisionEngine
from bigr.guardian.dns.resolver import UpstreamResolver
from bigr.guardian.dns.rules import CustomRulesManager
from bigr.guardian.dns.server import GuardianDNSServer
from bigr.guardian.health import GuardianHealthChecker
from bigr.guardian.stats import StatsTracker

logger = logging.getLogger(__name__)

_DEFAULT_DIR = Path.home() / ".bigr"


def _is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


class GuardianDaemon:
    """Guardian DNS filtering daemon with PID management.

    Parameters
    ----------
    config:
        Guardian configuration. If None, loaded from environment.
    bigr_dir:
        Base directory for PID/log files.
    """

    def __init__(
        self,
        config: GuardianConfig | None = None,
        bigr_dir: Path | None = None,
    ) -> None:
        self._config = config or load_guardian_config()
        self._dir = bigr_dir or _DEFAULT_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._pid_path = self._dir / "guardian.pid"
        self._log_path = self._dir / "guardian.log"
        self._running = False
        self._logger = self._setup_logger()

        # Components (initialized in start)
        self._cache: DNSCache | None = None
        self._resolver: UpstreamResolver | None = None
        self._blocklist: BlocklistManager | None = None
        self._rules: CustomRulesManager | None = None
        self._decision_engine: QueryDecisionEngine | None = None
        self._dns_server: GuardianDNSServer | None = None
        self._stats: StatsTracker | None = None
        self._health: GuardianHealthChecker | None = None

    def _setup_logger(self) -> logging.Logger:
        log = logging.getLogger(f"bigr.guardian.{id(self)}")
        log.setLevel(logging.INFO)
        if not log.handlers:
            handler = RotatingFileHandler(
                self._log_path, maxBytes=5 * 1024 * 1024, backupCount=3
            )
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            log.addHandler(handler)
        return log

    async def start(self) -> None:
        """Initialize all components and start the DNS server."""
        # PID check
        if self._pid_path.exists():
            try:
                existing = int(self._pid_path.read_text().strip())
            except (ValueError, OSError):
                existing = None
            if existing and _is_process_alive(existing):
                raise RuntimeError(
                    f"Guardian already running (PID {existing}). "
                    "Use 'bigr guardian stop'."
                )
            self._pid_path.unlink(missing_ok=True)

        self._pid_path.write_text(str(os.getpid()))
        self._running = True

        # Initialize components
        self._cache = DNSCache(
            max_size=self._config.cache_size,
            default_ttl=self._config.cache_ttl,
        )
        self._resolver = UpstreamResolver(
            doh_url=self._config.upstream_doh_url,
            fallback_ip=self._config.upstream_fallback_ip,
        )
        self._blocklist = BlocklistManager(self._config)
        self._rules = CustomRulesManager()
        self._stats = StatsTracker()

        self._decision_engine = QueryDecisionEngine(
            blocklist_manager=self._blocklist,
            rules_manager=self._rules,
            sinkhole_ip=self._config.sinkhole_ip,
        )

        self._dns_server = GuardianDNSServer(
            decision_engine=self._decision_engine,
            resolver=self._resolver,
            cache=self._cache,
            host=self._config.dns_host,
            port=self._config.dns_port,
            stats_callback=self._stats.record_query,
        )

        self._health = GuardianHealthChecker(
            resolver=self._resolver,
            blocklist=self._blocklist,
            cache=self._cache,
            config=self._config,
        )

        # Register components with API
        from bigr.guardian.api.routes import set_components
        set_components(
            blocklist=self._blocklist,
            rules=self._rules,
            stats=self._stats,
            dns_server=self._dns_server,
            health=self._health,
        )

        # Load data from DB
        from bigr.core.database import get_session_factory
        factory = get_session_factory()
        async with factory() as session:
            await self._blocklist.load_from_db(session)
            await self._rules.load_from_db(session)

        # Start DNS server
        await self._dns_server.start()

        # Start stats flush loop
        await self._stats.start_flush_loop(factory)

        self._logger.info(
            "Guardian started (PID %d). DNS on %s:%d, %d blocked domains",
            os.getpid(),
            self._config.dns_host,
            self._config.dns_port,
            self._blocklist.domain_count,
        )

    async def stop(self) -> None:
        """Stop all components and clean up."""
        self._running = False

        if self._stats:
            await self._stats.stop_flush_loop()
        if self._dns_server:
            await self._dns_server.stop()

        self._logger.info("Guardian stopped.")
        if self._pid_path.exists():
            try:
                self._pid_path.unlink()
            except OSError:
                pass

    def get_status(self) -> dict:
        """Return current Guardian status from PID file."""
        if not self._pid_path.exists():
            return {"running": False, "message": "Not running (no PID file)."}
        try:
            pid = int(self._pid_path.read_text().strip())
        except (ValueError, OSError):
            return {"running": False, "message": "Invalid PID file."}
        if _is_process_alive(pid):
            return {"running": True, "pid": pid, "message": f"Running (PID {pid})."}
        self._pid_path.unlink(missing_ok=True)
        return {"running": False, "message": "Not running (stale PID cleaned)."}
