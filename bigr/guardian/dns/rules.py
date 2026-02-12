"""Custom rules manager — user-defined allow/block rules with DB backing."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from bigr.guardian.models import GuardianCustomRuleDB

logger = logging.getLogger(__name__)


class CustomRulesManager:
    """Manage user-defined DNS rules (allow/block) with memory cache.

    Rules are stored in the database and cached in memory for fast lookups.
    """

    def __init__(self) -> None:
        # domain -> (action, rule_id, category)
        self._rules: dict[str, tuple[str, str, str]] = {}

    async def load_from_db(self, session: AsyncSession) -> int:
        """Load active rules from database into memory cache."""
        result = await session.execute(
            select(GuardianCustomRuleDB).where(
                GuardianCustomRuleDB.is_active == 1
            )
        )
        rules = result.scalars().all()
        self._rules.clear()
        for r in rules:
            self._rules[r.domain.lower()] = (r.action, r.id, r.category)
        logger.info("Loaded %d custom rules from DB", len(self._rules))
        return len(self._rules)

    async def add_rule(
        self,
        session: AsyncSession,
        action: str,
        domain: str,
        category: str = "custom",
        reason: str = "",
    ) -> str:
        """Add a new custom rule.

        Parameters
        ----------
        action: "block" or "allow"
        domain: Domain to match
        category: Rule category
        reason: Human-readable reason

        Returns
        -------
        rule_id
        """
        if action not in ("block", "allow"):
            raise ValueError(f"Invalid action: {action}. Must be 'block' or 'allow'.")

        rule_id = str(uuid.uuid4())
        domain = domain.lower().rstrip(".")
        rule = GuardianCustomRuleDB(
            id=rule_id,
            action=action,
            domain=domain,
            category=category,
            reason=reason,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        session.add(rule)
        await session.commit()

        # Update memory cache
        self._rules[domain] = (action, rule_id, category)
        logger.info("Added %s rule for %s (id=%s)", action, domain, rule_id)
        return rule_id

    async def remove_rule(self, session: AsyncSession, rule_id: str) -> bool:
        """Soft-delete a rule by setting is_active=0.

        Returns True if rule was found and deactivated.
        """
        result = await session.execute(
            select(GuardianCustomRuleDB).where(GuardianCustomRuleDB.id == rule_id)
        )
        rule = result.scalar_one_or_none()
        if rule is None:
            return False

        rule.is_active = 0
        await session.commit()

        # Remove from memory cache
        domain = rule.domain.lower()
        if domain in self._rules and self._rules[domain][1] == rule_id:
            del self._rules[domain]

        logger.info("Deactivated rule %s (domain=%s)", rule_id, domain)
        return True

    def check_rule(self, domain: str) -> tuple[str | None, str | None, str | None]:
        """Check if a domain matches a custom rule.

        Returns
        -------
        (action, rule_id, category) or (None, None, None) if no match.
        """
        domain = domain.lower().rstrip(".")

        # Exact match
        if domain in self._rules:
            action, rule_id, category = self._rules[domain]
            return action, rule_id, category

        return None, None, None

    async def increment_hit_count(
        self, session: AsyncSession, rule_id: str
    ) -> None:
        """Increment hit count for a rule (fire-and-forget)."""
        try:
            await session.execute(
                update(GuardianCustomRuleDB)
                .where(GuardianCustomRuleDB.id == rule_id)
                .values(hit_count=GuardianCustomRuleDB.hit_count + 1)
            )
            await session.commit()
        except Exception:
            logger.debug("Failed to increment hit count for rule %s", rule_id)

    async def get_all_rules(self, session: AsyncSession) -> list[dict]:
        """Return all active rules as dicts."""
        result = await session.execute(
            select(GuardianCustomRuleDB).where(
                GuardianCustomRuleDB.is_active == 1
            )
        )
        rules = result.scalars().all()
        return [
            {
                "id": r.id,
                "action": r.action,
                "domain": r.domain,
                "category": r.category,
                "reason": r.reason,
                "hit_count": r.hit_count,
                "created_at": r.created_at,
            }
            for r in rules
        ]
