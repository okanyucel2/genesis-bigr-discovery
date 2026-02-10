"""Tests for the BİGR Collective Intelligence module ("Waze Effect").

Tests cover:
    - DifferentialPrivacy: randomized response, Laplace noise, k-anonymity, confidence
    - CollectiveEngine: submit, aggregate, verify, cleanup, stats, contribution
    - API endpoints: POST /signal, GET /threats, GET /stats, GET /contribution, GET /feed
"""

from __future__ import annotations

import hashlib
import hmac
import math
import statistics
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bigr.collective.engine import CollectiveEngine
from bigr.collective.models import (
    CollectiveSignalReport,
    CollectiveStats,
    ContributionStatus,
    ThreatSignal,
)
from bigr.collective.privacy import DifferentialPrivacy
from bigr.core.database import Base
from bigr.core.models_db import CollectiveSignalDB


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest_asyncio.fixture
async def db_session():
    """Create a fresh in-memory SQLite database for each test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", echo=False
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def privacy():
    """Create a DifferentialPrivacy instance with default params."""
    return DifferentialPrivacy(epsilon=1.0, k_anonymity=3)


@pytest.fixture
def strict_privacy():
    """Create a strict DifferentialPrivacy instance (lower epsilon, higher k)."""
    return DifferentialPrivacy(epsilon=0.5, k_anonymity=5)


@pytest.fixture
def engine():
    """Create a CollectiveEngine with a test HMAC key."""
    return CollectiveEngine(
        hmac_key="test-hmac-key-12345",
        epsilon=1.0,
        k_anonymity=3,
    )


def _make_signal(
    subnet_hash: str = "abc123",
    signal_type: str = "port_scan",
    severity: float = 0.7,
    port: int | None = 445,
    agent_hash: str = "agent_aaa",
) -> ThreatSignal:
    """Helper to create a ThreatSignal."""
    return ThreatSignal(
        subnet_hash=subnet_hash,
        signal_type=signal_type,
        severity=severity,
        port=port,
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_hash=agent_hash,
    )


def _hmac_hash(key: str, value: str) -> str:
    """Reproduce the engine's HMAC hashing."""
    return hmac.new(
        key.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ===========================================================================
# DifferentialPrivacy tests
# ===========================================================================


class TestDifferentialPrivacy:
    """Tests for the DifferentialPrivacy class."""

    def test_randomized_response_probability(self, privacy: DifferentialPrivacy):
        """Randomized response should be truthful ~73% of the time for epsilon=1.0."""
        # p = e^1 / (1 + e^1) = 2.718 / 3.718 ≈ 0.731
        expected_p = math.exp(1.0) / (1.0 + math.exp(1.0))
        n = 10000
        true_count = sum(
            1 for _ in range(n)
            if privacy.randomized_response(True) is True
        )
        observed_p = true_count / n

        # Should be within 5% of expected
        assert abs(observed_p - expected_p) < 0.05, (
            f"Expected ~{expected_p:.3f}, got {observed_p:.3f}"
        )

    def test_randomized_response_false_input(self, privacy: DifferentialPrivacy):
        """Randomized response with False should flip to True ~27% of the time."""
        expected_flip = 1.0 - math.exp(1.0) / (1.0 + math.exp(1.0))
        n = 10000
        true_count = sum(
            1 for _ in range(n)
            if privacy.randomized_response(False) is True
        )
        observed_flip = true_count / n

        assert abs(observed_flip - expected_flip) < 0.05

    def test_strict_privacy_flips_more(self, strict_privacy: DifferentialPrivacy):
        """Lower epsilon should flip more often (less truthful)."""
        n = 10000
        strict_true = sum(
            1 for _ in range(n)
            if strict_privacy.randomized_response(True) is True
        )
        strict_p = strict_true / n

        # epsilon=0.5 → p = e^0.5 / (1+e^0.5) ≈ 0.622
        expected_p = math.exp(0.5) / (1.0 + math.exp(0.5))
        assert abs(strict_p - expected_p) < 0.05

    def test_noise_stays_in_bounds(self, privacy: DifferentialPrivacy):
        """Noised severity should always be in [0, 1]."""
        for _ in range(1000):
            for severity in [0.0, 0.1, 0.5, 0.9, 1.0]:
                noised = privacy.add_noise_to_severity(severity)
                assert 0.0 <= noised <= 1.0, f"Out of bounds: {noised}"

    def test_noise_is_centered(self, privacy: DifferentialPrivacy):
        """Average noise should be approximately zero (severity 0.5)."""
        n = 5000
        noised_values = [privacy.add_noise_to_severity(0.5) for _ in range(n)]
        mean = statistics.mean(noised_values)
        # Should be within 0.1 of 0.5
        assert abs(mean - 0.5) < 0.1, f"Mean noise too biased: {mean}"

    def test_k_anonymity_threshold(self, privacy: DifferentialPrivacy):
        """k-anonymity with k=3 should require at least 3 reporters."""
        assert privacy.meets_k_anonymity(0) is False
        assert privacy.meets_k_anonymity(1) is False
        assert privacy.meets_k_anonymity(2) is False
        assert privacy.meets_k_anonymity(3) is True
        assert privacy.meets_k_anonymity(10) is True
        assert privacy.meets_k_anonymity(100) is True

    def test_k_anonymity_strict(self, strict_privacy: DifferentialPrivacy):
        """k-anonymity with k=5 should require at least 5 reporters."""
        assert strict_privacy.meets_k_anonymity(4) is False
        assert strict_privacy.meets_k_anonymity(5) is True

    def test_confidence_calculation_basic(self, privacy: DifferentialPrivacy):
        """Confidence should increase with reporter count."""
        c1 = privacy.calculate_confidence(1, 0.8)
        c5 = privacy.calculate_confidence(5, 0.8)
        c10 = privacy.calculate_confidence(10, 0.8)

        assert c1 < c5 < c10

    def test_confidence_capped_at_ten(self, privacy: DifferentialPrivacy):
        """Confidence crowd factor should cap at 10 reporters."""
        c10 = privacy.calculate_confidence(10, 1.0)
        c20 = privacy.calculate_confidence(20, 1.0)
        assert c10 == c20 == 1.0

    def test_confidence_consistency_matters(self, privacy: DifferentialPrivacy):
        """Higher consistency should yield higher confidence."""
        low_consistency = privacy.calculate_confidence(5, 0.3)
        high_consistency = privacy.calculate_confidence(5, 0.9)
        assert low_consistency < high_consistency

    def test_confidence_zero_reporters(self, privacy: DifferentialPrivacy):
        """Zero reporters should yield zero confidence."""
        assert privacy.calculate_confidence(0, 1.0) == 0.0

    def test_invalid_epsilon_raises(self):
        """Epsilon <= 0 should raise ValueError."""
        with pytest.raises(ValueError, match="epsilon must be positive"):
            DifferentialPrivacy(epsilon=0.0)
        with pytest.raises(ValueError, match="epsilon must be positive"):
            DifferentialPrivacy(epsilon=-1.0)

    def test_invalid_k_raises(self):
        """k_anonymity < 1 should raise ValueError."""
        with pytest.raises(ValueError, match="k_anonymity must be at least 1"):
            DifferentialPrivacy(epsilon=1.0, k_anonymity=0)


# ===========================================================================
# CollectiveEngine tests
# ===========================================================================


class TestCollectiveEngine:
    """Tests for the CollectiveEngine class."""

    @pytest.mark.asyncio
    async def test_submit_signal_stores_in_db(
        self, engine: CollectiveEngine, db_session: AsyncSession
    ):
        """Submitting a signal should store it in the database."""
        signal = _make_signal()
        result = await engine.submit_signal(signal, db_session)

        # Result should be accepted or suppressed
        assert result["status"] in ("accepted", "suppressed")

        if result["status"] == "accepted":
            # Verify it was stored
            from sqlalchemy import select, func

            count = (
                await db_session.execute(
                    select(func.count(CollectiveSignalDB.id))
                )
            ).scalar()
            assert count == 1

    @pytest.mark.asyncio
    async def test_submit_signal_noises_severity(
        self, engine: CollectiveEngine, db_session: AsyncSession
    ):
        """Submitted signal severity should be noised (not exact original)."""
        # Submit many signals and check that at least some differ from original
        original_severity = 0.5
        stored_severities = []

        for i in range(50):
            signal = _make_signal(
                severity=original_severity,
                agent_hash=f"agent_{i}",
            )
            result = await engine.submit_signal(signal, db_session)
            if result["status"] == "accepted":
                stored_severities.append(result["noised_severity"])

        # Not all should be exactly 0.5 (noise was added)
        if len(stored_severities) > 5:
            unique_values = set(stored_severities)
            assert len(unique_values) > 1, "All severities are identical - noise not working"

    @pytest.mark.asyncio
    async def test_get_community_threats_only_verified(
        self, db_session: AsyncSession
    ):
        """get_community_threats should only return k-anonymous signals."""
        engine = CollectiveEngine(
            hmac_key="test-key", epsilon=10.0, k_anonymity=3
        )
        now = datetime.now(timezone.utc)

        # Add 3 signals from different agents for the same threat
        for i in range(3):
            db_session.add(
                CollectiveSignalDB(
                    subnet_hash="subnet_verified",
                    signal_type="port_scan",
                    severity=0.7,
                    port=445,
                    agent_hash=f"agent_{i}",
                    reported_at=now.isoformat(),
                    is_noised=1,
                )
            )

        # Add 1 signal for a different threat (below k-anonymity)
        db_session.add(
            CollectiveSignalDB(
                subnet_hash="subnet_unverified",
                signal_type="brute_force",
                severity=0.8,
                port=22,
                agent_hash="agent_solo",
                reported_at=now.isoformat(),
                is_noised=1,
            )
        )
        await db_session.commit()

        threats = await engine.get_community_threats(db_session, min_confidence=0.0)

        # Only the verified one should appear
        subnet_hashes = {t.subnet_hash for t in threats}
        assert "subnet_verified" in subnet_hashes
        assert "subnet_unverified" not in subnet_hashes

    @pytest.mark.asyncio
    async def test_signals_below_k_anonymity_hidden(
        self, db_session: AsyncSession
    ):
        """Signals with fewer than k reporters must be hidden."""
        engine = CollectiveEngine(
            hmac_key="test-key", epsilon=10.0, k_anonymity=5
        )
        now = datetime.now(timezone.utc)

        # Only 3 agents report (k=5 required)
        for i in range(3):
            db_session.add(
                CollectiveSignalDB(
                    subnet_hash="not_enough",
                    signal_type="suspicious",
                    severity=0.6,
                    port=None,
                    agent_hash=f"agent_{i}",
                    reported_at=now.isoformat(),
                    is_noised=1,
                )
            )
        await db_session.commit()

        threats = await engine.get_community_threats(db_session, min_confidence=0.0)
        assert len(threats) == 0

    @pytest.mark.asyncio
    async def test_cleanup_removes_old_signals(
        self, engine: CollectiveEngine, db_session: AsyncSession
    ):
        """cleanup_expired should remove signals older than max_age_hours."""
        old_time = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()
        recent_time = datetime.now(timezone.utc).isoformat()

        db_session.add(
            CollectiveSignalDB(
                subnet_hash="old_subnet",
                signal_type="port_scan",
                severity=0.5,
                port=80,
                agent_hash="agent_old",
                reported_at=old_time,
                is_noised=1,
            )
        )
        db_session.add(
            CollectiveSignalDB(
                subnet_hash="new_subnet",
                signal_type="malware_c2",
                severity=0.9,
                port=443,
                agent_hash="agent_new",
                reported_at=recent_time,
                is_noised=1,
            )
        )
        await db_session.commit()

        removed = await engine.cleanup_expired(db_session, max_age_hours=72)
        assert removed == 1

        # Verify the recent one is still there
        from sqlalchemy import select, func

        count = (
            await db_session.execute(
                select(func.count(CollectiveSignalDB.id))
            )
        ).scalar()
        assert count == 1

    @pytest.mark.asyncio
    async def test_stats_calculation(
        self, engine: CollectiveEngine, db_session: AsyncSession
    ):
        """get_stats should return correct counts."""
        now = datetime.now(timezone.utc)

        # Add signals from 3 different agents across 2 subnets
        for i in range(3):
            db_session.add(
                CollectiveSignalDB(
                    subnet_hash=f"subnet_{i % 2}",
                    signal_type="port_scan",
                    severity=0.6,
                    port=445,
                    agent_hash=f"agent_{i}",
                    reported_at=now.isoformat(),
                    is_noised=1,
                )
            )
        await db_session.commit()

        stats = await engine.get_stats(db_session)

        assert stats.total_signals == 3
        assert stats.active_agents == 3
        assert stats.subnets_monitored == 2
        assert 0.0 <= stats.community_protection_score <= 100.0
        assert stats.last_updated != ""

    @pytest.mark.asyncio
    async def test_contribution_status(
        self, engine: CollectiveEngine, db_session: AsyncSession
    ):
        """get_contribution_status should count this agent's signals."""
        now = datetime.now(timezone.utc)

        # Add signals: 3 from "my_agent", 2 from another agent across 1 subnet
        for i in range(3):
            db_session.add(
                CollectiveSignalDB(
                    subnet_hash="shared_subnet",
                    signal_type="port_scan",
                    severity=0.5,
                    port=445,
                    agent_hash="my_agent",
                    reported_at=now.isoformat(),
                    is_noised=1,
                )
            )
        for i in range(2):
            db_session.add(
                CollectiveSignalDB(
                    subnet_hash="shared_subnet",
                    signal_type="port_scan",
                    severity=0.6,
                    port=445,
                    agent_hash=f"other_{i}",
                    reported_at=now.isoformat(),
                    is_noised=1,
                )
            )
        await db_session.commit()

        status = await engine.get_contribution_status("my_agent", db_session)

        assert status.signals_contributed == 3
        assert status.is_contributing is True
        assert status.privacy_level == "standard"

    @pytest.mark.asyncio
    async def test_aggregation_groups_correctly(
        self, engine: CollectiveEngine, db_session: AsyncSession
    ):
        """Aggregation should group by (subnet_hash, signal_type)."""
        now = datetime.now(timezone.utc)

        # Two different signal types on same subnet
        for i in range(3):
            db_session.add(
                CollectiveSignalDB(
                    subnet_hash="subnet_a",
                    signal_type="port_scan",
                    severity=0.5,
                    port=445,
                    agent_hash=f"agent_ps_{i}",
                    reported_at=now.isoformat(),
                    is_noised=1,
                )
            )
        for i in range(3):
            db_session.add(
                CollectiveSignalDB(
                    subnet_hash="subnet_a",
                    signal_type="malware_c2",
                    severity=0.9,
                    port=443,
                    agent_hash=f"agent_mc_{i}",
                    reported_at=now.isoformat(),
                    is_noised=1,
                )
            )
        await db_session.commit()

        threats = await engine.get_community_threats(db_session, min_confidence=0.0)

        # Should have 2 different reports for subnet_a
        assert len(threats) == 2
        signal_types = {t.signal_type for t in threats}
        assert signal_types == {"port_scan", "malware_c2"}

    @pytest.mark.asyncio
    async def test_feed_returns_verified_only(
        self, db_session: AsyncSession
    ):
        """get_feed should only return verified signals."""
        engine = CollectiveEngine(
            hmac_key="test-key", epsilon=10.0, k_anonymity=2
        )
        now = datetime.now(timezone.utc)

        # 2 agents (meets k=2)
        for i in range(2):
            db_session.add(
                CollectiveSignalDB(
                    subnet_hash="verified_feed",
                    signal_type="brute_force",
                    severity=0.8,
                    port=22,
                    agent_hash=f"feed_agent_{i}",
                    reported_at=now.isoformat(),
                    is_noised=1,
                )
            )
        # 1 agent (below k=2)
        db_session.add(
            CollectiveSignalDB(
                subnet_hash="unverified_feed",
                signal_type="suspicious",
                severity=0.3,
                port=None,
                agent_hash="solo_agent",
                reported_at=now.isoformat(),
                is_noised=1,
            )
        )
        await db_session.commit()

        feed = await engine.get_feed(db_session, limit=10)
        assert len(feed) == 1
        assert feed[0].subnet_hash == "verified_feed"

    @pytest.mark.asyncio
    async def test_feed_respects_limit(
        self, db_session: AsyncSession
    ):
        """get_feed should respect the limit parameter."""
        engine = CollectiveEngine(
            hmac_key="test-key", epsilon=10.0, k_anonymity=2
        )
        now = datetime.now(timezone.utc)

        # Create 5 verified threats
        for s in range(5):
            for i in range(2):
                db_session.add(
                    CollectiveSignalDB(
                        subnet_hash=f"subnet_{s}",
                        signal_type="port_scan",
                        severity=0.5,
                        port=80,
                        agent_hash=f"agent_{i}",
                        reported_at=now.isoformat(),
                        is_noised=1,
                    )
                )
        await db_session.commit()

        feed = await engine.get_feed(db_session, limit=3)
        assert len(feed) <= 3


# ===========================================================================
# API endpoint tests
# ===========================================================================


@pytest_asyncio.fixture
async def test_app():
    """Create a test FastAPI app with the collective router."""
    from fastapi import FastAPI

    from bigr.collective.api import router

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    app = FastAPI()
    app.include_router(router)

    # Override the get_db dependency
    from bigr.core.database import get_db

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    yield app, session_factory

    await engine.dispose()


class TestCollectiveAPI:
    """Tests for the collective intelligence API endpoints."""

    @pytest.mark.asyncio
    async def test_post_signal(self, test_app):
        """POST /api/collective/signal should accept a valid signal."""
        app, _ = test_app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/collective/signal",
                json={
                    "subnet_hash": "abc123def456",
                    "signal_type": "port_scan",
                    "severity": 0.7,
                    "port": 445,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "agent_hash": "agent_test_hash",
                },
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] in ("accepted", "suppressed")

    @pytest.mark.asyncio
    async def test_get_threats(self, test_app):
        """GET /api/collective/threats should return verified threats."""
        app, session_factory = test_app
        now = datetime.now(timezone.utc)

        # Seed some signals directly
        async with session_factory() as session:
            for i in range(4):
                session.add(
                    CollectiveSignalDB(
                        subnet_hash="threat_subnet",
                        signal_type="malware_c2",
                        severity=0.8,
                        port=443,
                        agent_hash=f"agent_{i}",
                        reported_at=now.isoformat(),
                        is_noised=1,
                    )
                )
            await session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Use min_confidence=0 to avoid filtering by confidence
            response = await client.get(
                "/api/collective/threats",
                params={"min_confidence": 0.0},
            )
            assert response.status_code == 200
            data = response.json()
            assert "threats" in data
            assert "total" in data
            # With 4 unique agents and k=3, should have verified threats
            assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_get_stats(self, test_app):
        """GET /api/collective/stats should return valid statistics."""
        app, _ = test_app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/collective/stats")
            assert response.status_code == 200
            data = response.json()
            assert "total_signals" in data
            assert "active_agents" in data
            assert "verified_threats" in data
            assert "subnets_monitored" in data
            assert "community_protection_score" in data
            assert 0 <= data["community_protection_score"] <= 100

    @pytest.mark.asyncio
    async def test_get_contribution(self, test_app):
        """GET /api/collective/contribution should return contribution status."""
        app, _ = test_app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/api/collective/contribution",
                params={"agent_hash": "test_agent"},
            )
            assert response.status_code == 200
            data = response.json()
            assert "signals_contributed" in data
            assert "signals_received" in data
            assert "is_contributing" in data
            assert "opt_in" in data
            assert "privacy_level" in data

    @pytest.mark.asyncio
    async def test_get_feed(self, test_app):
        """GET /api/collective/feed should return the collective feed."""
        app, session_factory = test_app
        now = datetime.now(timezone.utc)

        # Seed verified signals
        async with session_factory() as session:
            for i in range(3):
                session.add(
                    CollectiveSignalDB(
                        subnet_hash="feed_subnet",
                        signal_type="brute_force",
                        severity=0.6,
                        port=22,
                        agent_hash=f"feed_agent_{i}",
                        reported_at=now.isoformat(),
                        is_noised=1,
                    )
                )
            await session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/collective/feed", params={"limit": 10})
            assert response.status_code == 200
            data = response.json()
            assert "signals" in data
            assert "total" in data

    @pytest.mark.asyncio
    async def test_post_cleanup(self, test_app):
        """POST /api/collective/cleanup should remove old signals."""
        app, session_factory = test_app
        old_time = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()

        async with session_factory() as session:
            session.add(
                CollectiveSignalDB(
                    subnet_hash="old",
                    signal_type="suspicious",
                    severity=0.4,
                    port=None,
                    agent_hash="old_agent",
                    reported_at=old_time,
                    is_noised=1,
                )
            )
            await session.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/collective/cleanup",
                params={"max_age_hours": 72},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["removed"] >= 1

    @pytest.mark.asyncio
    async def test_signal_validation(self, test_app):
        """POST /api/collective/signal should reject invalid data."""
        app, _ = test_app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Missing required fields
            response = await client.post(
                "/api/collective/signal",
                json={"subnet_hash": "abc"},
            )
            assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_severity_validation(self, test_app):
        """POST /api/collective/signal should reject severity out of range."""
        app, _ = test_app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/collective/signal",
                json={
                    "subnet_hash": "abc",
                    "signal_type": "port_scan",
                    "severity": 1.5,  # Out of range
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "agent_hash": "agent_x",
                },
            )
            assert response.status_code == 422


# ===========================================================================
# Model validation tests
# ===========================================================================


class TestModels:
    """Tests for Pydantic model validation."""

    def test_threat_signal_valid(self):
        """Valid ThreatSignal should be created without error."""
        signal = ThreatSignal(
            subnet_hash="abc123",
            signal_type="port_scan",
            severity=0.5,
            port=445,
            timestamp="2026-02-10T12:00:00+00:00",
            agent_hash="agent_hash_123",
        )
        assert signal.severity == 0.5
        assert signal.port == 445

    def test_threat_signal_optional_port(self):
        """ThreatSignal with no port should work."""
        signal = ThreatSignal(
            subnet_hash="abc123",
            signal_type="suspicious",
            severity=0.3,
            timestamp="2026-02-10T12:00:00+00:00",
            agent_hash="agent_hash_123",
        )
        assert signal.port is None

    def test_collective_stats_valid(self):
        """CollectiveStats should validate protection score range."""
        stats = CollectiveStats(
            total_signals=100,
            active_agents=5,
            verified_threats=10,
            subnets_monitored=20,
            community_protection_score=75.5,
            last_updated="2026-02-10T12:00:00+00:00",
        )
        assert stats.community_protection_score == 75.5

    def test_contribution_status_valid(self):
        """ContributionStatus model validation."""
        status = ContributionStatus(
            signals_contributed=42,
            signals_received=100,
            is_contributing=True,
            opt_in=True,
            privacy_level="strict",
        )
        assert status.privacy_level == "strict"
