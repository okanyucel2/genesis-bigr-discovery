"""Tests for custom rules manager."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bigr.core.database import Base
from bigr.guardian.dns.rules import CustomRulesManager
from bigr.guardian.models import GuardianCustomRuleDB


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


@pytest.fixture
def rules():
    return CustomRulesManager()


class TestAddRule:
    async def test_add_block_rule(self, rules: CustomRulesManager, session: AsyncSession):
        rule_id = await rules.add_rule(
            session, action="block", domain="evil.com", reason="Known malware"
        )
        assert rule_id is not None
        action, rid, cat = rules.check_rule("evil.com")
        assert action == "block"
        assert rid == rule_id

    async def test_add_allow_rule(self, rules: CustomRulesManager, session: AsyncSession):
        rule_id = await rules.add_rule(
            session, action="allow", domain="safe.com"
        )
        action, rid, cat = rules.check_rule("safe.com")
        assert action == "allow"

    async def test_invalid_action_raises(self, rules: CustomRulesManager, session: AsyncSession):
        with pytest.raises(ValueError, match="Invalid action"):
            await rules.add_rule(session, action="invalid", domain="test.com")

    async def test_rule_persisted_in_db(self, rules: CustomRulesManager, session: AsyncSession):
        rule_id = await rules.add_rule(
            session, action="block", domain="persist.com"
        )
        result = await session.execute(
            select(GuardianCustomRuleDB).where(GuardianCustomRuleDB.id == rule_id)
        )
        row = result.scalar_one()
        assert row.domain == "persist.com"
        assert row.action == "block"

    async def test_domain_lowercased(self, rules: CustomRulesManager, session: AsyncSession):
        await rules.add_rule(session, action="block", domain="UPPER.COM")
        action, _, _ = rules.check_rule("upper.com")
        assert action == "block"


class TestRemoveRule:
    async def test_remove_existing(self, rules: CustomRulesManager, session: AsyncSession):
        rule_id = await rules.add_rule(
            session, action="block", domain="remove.com"
        )
        removed = await rules.remove_rule(session, rule_id)
        assert removed is True
        action, _, _ = rules.check_rule("remove.com")
        assert action is None

    async def test_remove_nonexistent(self, rules: CustomRulesManager, session: AsyncSession):
        removed = await rules.remove_rule(session, "nonexistent-id")
        assert removed is False

    async def test_soft_delete(self, rules: CustomRulesManager, session: AsyncSession):
        rule_id = await rules.add_rule(
            session, action="block", domain="soft.com"
        )
        await rules.remove_rule(session, rule_id)

        result = await session.execute(
            select(GuardianCustomRuleDB).where(GuardianCustomRuleDB.id == rule_id)
        )
        row = result.scalar_one()
        assert row.is_active == 0


class TestCheckRule:
    async def test_exact_match(self, rules: CustomRulesManager, session: AsyncSession):
        await rules.add_rule(session, action="block", domain="match.com")
        action, _, _ = rules.check_rule("match.com")
        assert action == "block"

    async def test_no_match(self, rules: CustomRulesManager, session: AsyncSession):
        action, rule_id, cat = rules.check_rule("nomatch.com")
        assert action is None
        assert rule_id is None
        assert cat is None

    async def test_trailing_dot(self, rules: CustomRulesManager, session: AsyncSession):
        await rules.add_rule(session, action="block", domain="dot.com")
        action, _, _ = rules.check_rule("dot.com.")
        assert action == "block"


class TestHitCount:
    async def test_increment_hit_count(self, rules: CustomRulesManager, session: AsyncSession):
        rule_id = await rules.add_rule(
            session, action="block", domain="hits.com"
        )
        await rules.increment_hit_count(session, rule_id)
        await rules.increment_hit_count(session, rule_id)

        result = await session.execute(
            select(GuardianCustomRuleDB).where(GuardianCustomRuleDB.id == rule_id)
        )
        row = result.scalar_one()
        assert row.hit_count == 2


class TestLoadFromDB:
    async def test_load_active_rules(self, rules: CustomRulesManager, session: AsyncSession):
        # Add two rules, deactivate one
        r1 = await rules.add_rule(session, action="block", domain="active.com")
        r2 = await rules.add_rule(session, action="block", domain="inactive.com")
        await rules.remove_rule(session, r2)

        # Create fresh manager and load
        fresh_rules = CustomRulesManager()
        count = await fresh_rules.load_from_db(session)
        assert count == 1
        assert fresh_rules.check_rule("active.com")[0] == "block"
        assert fresh_rules.check_rule("inactive.com")[0] is None


class TestGetAllRules:
    async def test_returns_active_rules(self, rules: CustomRulesManager, session: AsyncSession):
        await rules.add_rule(
            session, action="block", domain="a.com", reason="Test"
        )
        await rules.add_rule(
            session, action="allow", domain="b.com"
        )

        all_rules = await rules.get_all_rules(session)
        assert len(all_rules) == 2
        domains = {r["domain"] for r in all_rules}
        assert "a.com" in domains
        assert "b.com" in domains
