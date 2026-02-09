"""YAML-based classification rules engine.

Loads rules from YAML files in the rules/ directory and applies them
to assets for BİGR scoring. This replaces hardcoded scoring logic
with configurable, user-editable rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class RuleMatch:
    """Conditions for a rule to trigger."""
    ports_include_all: list[int] = field(default_factory=list)
    ports_include_any: list[int] = field(default_factory=list)
    ports_exclude: list[int] = field(default_factory=list)
    vendor_contains: list[str] = field(default_factory=list)
    hostname_pattern: str | None = None


@dataclass
class Rule:
    """A single classification rule."""
    name: str
    match: RuleMatch
    scores: dict[str, float]  # category -> score delta
    description: str = ""

    def evaluate_ports(self, open_ports: list[int]) -> bool:
        """Check if port conditions match."""
        port_set = set(open_ports)

        if self.match.ports_include_all:
            if not set(self.match.ports_include_all).issubset(port_set):
                return False

        if self.match.ports_include_any:
            if not set(self.match.ports_include_any) & port_set:
                return False

        if self.match.ports_exclude:
            if set(self.match.ports_exclude) & port_set:
                return False

        # At least one port condition must be specified
        return bool(
            self.match.ports_include_all
            or self.match.ports_include_any
        )

    def evaluate_vendor(self, vendor: str | None) -> bool:
        """Check if vendor conditions match."""
        if not self.match.vendor_contains or not vendor:
            return False
        vendor_lower = vendor.lower()
        return any(v.lower() in vendor_lower for v in self.match.vendor_contains)

    def evaluate_hostname(self, hostname: str | None) -> bool:
        """Check if hostname pattern matches."""
        if not self.match.hostname_pattern or not hostname:
            return False
        return bool(re.search(self.match.hostname_pattern, hostname, re.IGNORECASE))


@dataclass
class RuleSet:
    """Collection of rules loaded from YAML files."""
    port_rules: list[Rule] = field(default_factory=list)
    vendor_rules: list[Rule] = field(default_factory=list)
    hostname_rules: list[Rule] = field(default_factory=list)

    @property
    def total_rules(self) -> int:
        return len(self.port_rules) + len(self.vendor_rules) + len(self.hostname_rules)


def _parse_rule(data: dict) -> Rule:
    """Parse a single rule from YAML dict."""
    match_data = data.get("match", {})
    match = RuleMatch(
        ports_include_all=match_data.get("ports_include_all", []),
        ports_include_any=match_data.get("ports_include_any", []),
        ports_exclude=match_data.get("ports_exclude", []),
        vendor_contains=match_data.get("vendor_contains", []),
        hostname_pattern=match_data.get("hostname_pattern"),
    )
    return Rule(
        name=data.get("name", "unnamed"),
        match=match,
        scores=data.get("scores", {}),
        description=data.get("description", ""),
    )


def load_rules(rules_dir: str | Path | None = None) -> RuleSet:
    """Load all YAML rule files from the rules directory.

    Args:
        rules_dir: Path to rules directory. Defaults to project's rules/ dir.
    """
    if rules_dir is None:
        rules_dir = Path(__file__).parent.parent.parent / "rules"
    else:
        rules_dir = Path(rules_dir)

    ruleset = RuleSet()

    if not rules_dir.exists():
        return ruleset

    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        with yaml_file.open(encoding="utf-8") as f:
            raw_rules = yaml.safe_load(f)

        if not isinstance(raw_rules, list):
            continue

        category = yaml_file.stem  # port_rules, vendor_rules, hostname_rules
        for raw_rule in raw_rules:
            rule = _parse_rule(raw_rule)
            if category == "port_rules":
                ruleset.port_rules.append(rule)
            elif category == "vendor_rules":
                ruleset.vendor_rules.append(rule)
            elif category == "hostname_rules":
                ruleset.hostname_rules.append(rule)

    return ruleset


def apply_port_rules(rules: list[Rule], open_ports: list[int]) -> tuple[dict[str, float], list[str]]:
    """Apply port rules and return score deltas + evidence."""
    scores: dict[str, float] = {}
    evidence: list[str] = []

    for rule in rules:
        if rule.evaluate_ports(open_ports):
            for cat, delta in rule.scores.items():
                scores[cat] = scores.get(cat, 0) + delta
            evidence.append(f"{rule.name}: {rule.description or 'matched'}")

    return scores, evidence


def apply_vendor_rules(rules: list[Rule], vendor: str | None) -> tuple[dict[str, float], str | None]:
    """Apply vendor rules and return score deltas + evidence."""
    for rule in rules:
        if rule.evaluate_vendor(vendor):
            evidence = f"{vendor} → {rule.name}"
            return rule.scores, evidence
    return {}, None


def apply_hostname_rules(rules: list[Rule], hostname: str | None) -> tuple[dict[str, float], list[str]]:
    """Apply hostname rules and return score deltas + evidence."""
    scores: dict[str, float] = {}
    evidence: list[str] = []

    for rule in rules:
        if rule.evaluate_hostname(hostname):
            for cat, delta in rule.scores.items():
                scores[cat] = scores.get(cat, 0) + delta
            evidence.append(f"hostname '{hostname}' → {rule.name}")
            break  # First hostname match wins

    return scores, evidence
