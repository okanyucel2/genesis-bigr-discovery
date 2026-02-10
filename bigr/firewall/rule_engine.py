"""Platform-independent firewall rule matching engine."""

from __future__ import annotations

from bigr.firewall.models import FirewallRule


class FirewallRuleEngine:
    """Platform-independent firewall rule matching engine.

    This engine evaluates connections against rules. The actual
    enforcement happens in the platform-specific adapter (NEFilter
    on macOS, WFP on Windows).
    """

    def __init__(self) -> None:
        self._rules: list[FirewallRule] = []
        self._ip_blocklist: set[str] = set()
        self._ip_allowlist: set[str] = set()
        self._port_blocklist: set[int] = set()
        self._domain_blocklist: set[str] = set()
        self._domain_allowlist: set[str] = set()

    def load_rules(self, rules: list[FirewallRule]) -> None:
        """Load rules and build lookup sets for fast matching."""
        self._rules = [r for r in rules if r.is_active]
        self._ip_blocklist.clear()
        self._ip_allowlist.clear()
        self._port_blocklist.clear()
        self._domain_blocklist.clear()
        self._domain_allowlist.clear()

        for rule in self._rules:
            if rule.rule_type == "block_ip":
                self._ip_blocklist.add(rule.target)
            elif rule.rule_type == "allow_ip":
                self._ip_allowlist.add(rule.target)
            elif rule.rule_type == "block_port":
                self._port_blocklist.add(int(rule.target))
            elif rule.rule_type == "block_domain":
                self._domain_blocklist.add(rule.target.lower())
            elif rule.rule_type == "allow_domain":
                self._domain_allowlist.add(rule.target.lower())

    def evaluate(
        self,
        dest_ip: str,
        dest_port: int,
        protocol: str = "tcp",
        domain: str | None = None,
        direction: str = "outbound",
    ) -> tuple[str, FirewallRule | None]:
        """Evaluate a connection against loaded rules.

        Returns ("allowed", None) or ("blocked", matching_rule).

        Priority: allow rules > block rules (whitelist wins).
        """
        # 1. Check allowlist first (whitelist always wins)
        if dest_ip in self._ip_allowlist:
            return ("allowed", None)
        if domain and domain.lower() in self._domain_allowlist:
            return ("allowed", None)

        # 2. Check IP blocklist
        if dest_ip in self._ip_blocklist:
            rule = self._find_rule("block_ip", dest_ip)
            return ("blocked", rule)

        # 3. Check port blocklist
        if dest_port in self._port_blocklist:
            rule = self._find_rule("block_port", str(dest_port))
            return ("blocked", rule)

        # 4. Check domain blocklist
        if domain and domain.lower() in self._domain_blocklist:
            rule = self._find_rule("block_domain", domain.lower())
            return ("blocked", rule)

        # 5. Default: allow
        return ("allowed", None)

    def _find_rule(self, rule_type: str, target: str) -> FirewallRule | None:
        """Find the first matching rule."""
        for rule in self._rules:
            if rule.rule_type == rule_type and rule.target == target:
                return rule
        return None

    @property
    def stats(self) -> dict:
        """Return rule statistics."""
        return {
            "total_rules": len(self._rules),
            "ip_blocks": len(self._ip_blocklist),
            "ip_allows": len(self._ip_allowlist),
            "port_blocks": len(self._port_blocklist),
            "domain_blocks": len(self._domain_blocklist),
            "domain_allows": len(self._domain_allowlist),
        }
