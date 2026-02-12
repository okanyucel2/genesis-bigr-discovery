"""Query decision engine — determines block/allow for DNS queries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from bigr.guardian.dns.blocklist import BlocklistManager
from bigr.guardian.dns.rules import CustomRulesManager


class DecisionAction(str, Enum):
    """Action to take for a DNS query."""

    ALLOW = "allow"
    BLOCK = "block"


class DecisionReason(str, Enum):
    """Reason for the decision."""

    CUSTOM_ALLOW = "custom_allow"
    CUSTOM_BLOCK = "custom_block"
    BLOCKLIST = "blocklist"
    DEFAULT_ALLOW = "default_allow"


@dataclass
class QueryDecision:
    """Result of the decision engine for a single DNS query."""

    action: DecisionAction
    reason: DecisionReason
    category: str = ""
    rule_id: str | None = None
    should_resolve: bool = True
    sinkhole_ip: str = "0.0.0.0"


class QueryDecisionEngine:
    """Decide whether to allow or block a DNS query.

    Priority order (highest to lowest):
    1. Custom allow rule → resolve normally
    2. Custom block rule → sinkhole
    3. Blocklist match → sinkhole
    4. Default → resolve normally
    """

    def __init__(
        self,
        blocklist_manager: BlocklistManager,
        rules_manager: CustomRulesManager,
        sinkhole_ip: str = "0.0.0.0",
    ) -> None:
        self._blocklist = blocklist_manager
        self._rules = rules_manager
        self._sinkhole_ip = sinkhole_ip

    def decide(self, domain: str) -> QueryDecision:
        """Decide what to do with a DNS query for the given domain.

        Parameters
        ----------
        domain:
            The queried domain name (e.g. "ads.tracker.com").

        Returns
        -------
        QueryDecision with action, reason, and resolution instructions.
        """
        domain = domain.lower().rstrip(".")

        # 1. Check custom rules first (both allow and block)
        action, rule_id, category = self._rules.check_rule(domain)
        if action == "allow":
            return QueryDecision(
                action=DecisionAction.ALLOW,
                reason=DecisionReason.CUSTOM_ALLOW,
                category=category or "",
                rule_id=rule_id,
                should_resolve=True,
            )
        if action == "block":
            return QueryDecision(
                action=DecisionAction.BLOCK,
                reason=DecisionReason.CUSTOM_BLOCK,
                category=category or "",
                rule_id=rule_id,
                should_resolve=False,
                sinkhole_ip=self._sinkhole_ip,
            )

        # 2. Check blocklist
        blocked, bl_category = self._blocklist.is_blocked(domain)
        if blocked:
            return QueryDecision(
                action=DecisionAction.BLOCK,
                reason=DecisionReason.BLOCKLIST,
                category=bl_category,
                should_resolve=False,
                sinkhole_ip=self._sinkhole_ip,
            )

        # 3. Default: allow
        return QueryDecision(
            action=DecisionAction.ALLOW,
            reason=DecisionReason.DEFAULT_ALLOW,
            should_resolve=True,
        )
