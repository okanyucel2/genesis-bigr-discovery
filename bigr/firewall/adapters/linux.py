"""Linux nftables / iptables firewall adapter."""

from __future__ import annotations

import platform

from bigr.firewall.adapters.base import FirewallAdapter
from bigr.firewall.models import FirewallRule


class LinuxFirewallAdapter(FirewallAdapter):
    """Linux firewall adapter using nftables (preferred) or iptables (legacy).

    nftables (kernel 3.13+, userspace ``nft`` tool) is the modern Linux
    packet classification framework that replaces iptables/ip6tables/arptables
    under a single, unified API.

    BİGR creates its own nftables table and chains to avoid conflicting with
    existing system rules::

        table inet bigr_filter {
            chain input {
                type filter hook input priority 0; policy accept;
            }
            chain output {
                type filter hook output priority 0; policy accept;
            }
        }

    For systems that only ship iptables, we fall back to creating a custom
    chain (``BIGR_FILTER``) and inserting jump rules from ``INPUT``/``OUTPUT``.

    This adapter is **STUBBED** for cross-platform development.
    On actual Linux, it would shell out to ``nft`` or ``iptables`` via
    :mod:`asyncio.create_subprocess_exec`.
    """

    NFT_TABLE = "inet bigr_filter"
    IPT_CHAIN = "BIGR_FILTER"

    def __init__(self) -> None:
        self._is_installed: bool = False
        self._rules_applied: int = 0
        self._backend: str = "nftables"  # "nftables" or "iptables"

    # ------------------------------------------------------------------
    # FirewallAdapter interface
    # ------------------------------------------------------------------

    async def install(self) -> dict:
        """Create the BİGR nftables table and chains.

        On real Linux this would:

        1. Detect backend:
           ``which nft`` -> nftables, else ``which iptables`` -> iptables.
        2. For nftables::

              nft add table inet bigr_filter
              nft add chain inet bigr_filter input \\
                  '{ type filter hook input priority 0; policy accept; }'
              nft add chain inet bigr_filter output \\
                  '{ type filter hook output priority 0; policy accept; }'

        3. For iptables fallback::

              iptables -N BIGR_FILTER
              iptables -I INPUT -j BIGR_FILTER
              iptables -I OUTPUT -j BIGR_FILTER
        """
        if platform.system() != "Linux":
            self._is_installed = True
            return {
                "status": "stub",
                "message": "Linux firewall adapter stub activated.",
                "platform": "linux",
                "engine": f"{self._backend}_stub",
                "table": self.NFT_TABLE,
            }

        # --- Real Linux path (unreachable on macOS/Windows) ---
        self._is_installed = True
        return {
            "status": "ok",
            "platform": "linux",
            "engine": self._backend,
            "message": f"BIGR {self._backend} table created",
            "table": self.NFT_TABLE,
        }

    async def uninstall(self) -> dict:
        """Remove the BİGR nftables table (or iptables chain).

        For nftables::

            nft delete table inet bigr_filter

        For iptables::

            iptables -D INPUT -j BIGR_FILTER
            iptables -D OUTPUT -j BIGR_FILTER
            iptables -F BIGR_FILTER
            iptables -X BIGR_FILTER
        """
        self._is_installed = False
        self._rules_applied = 0
        return {
            "status": "ok",
            "message": f"BIGR {self._backend} table removed",
        }

    async def apply_rules(self, rules: list[FirewallRule]) -> dict:
        """Push rules into the nftables table (or iptables chain).

        Uses atomic rule replacement to avoid flicker:

        1. ``nft flush chain inet bigr_filter output``
        2. ``nft flush chain inet bigr_filter input``
        3. Add all rules in a single ``nft -f`` batch.

        Rule-type to nft-command mapping:

        - ``block_ip``::

              nft add rule inet bigr_filter output ip daddr {ip} drop

        - ``block_port``::

              nft add rule inet bigr_filter output tcp dport {port} drop

        - ``block_domain``::

              # nftables has no native DNS; would require conntrack + DNS redirect.
              nft add rule inet bigr_filter output ip daddr @bigr_dns_set drop

        - ``allow_ip``::

              nft add rule inet bigr_filter output ip daddr {ip} accept

        - ``allow_domain``::

              nft add rule inet bigr_filter output ip daddr @bigr_dns_allow_set accept
        """
        self._rules_applied = len(rules)

        # Generate nft commands (for documentation / debugging)
        nft_commands: list[str] = []
        nft_commands.append(f"nft flush chain {self.NFT_TABLE} output")
        nft_commands.append(f"nft flush chain {self.NFT_TABLE} input")

        for rule in rules:
            if rule.rule_type == "block_ip":
                nft_commands.append(
                    f"nft add rule {self.NFT_TABLE} output ip daddr {rule.target} drop"
                )
            elif rule.rule_type == "block_port":
                proto = rule.protocol if rule.protocol != "any" else "tcp"
                nft_commands.append(
                    f"nft add rule {self.NFT_TABLE} output {proto} dport {rule.target} drop"
                )
            elif rule.rule_type == "allow_ip":
                nft_commands.append(
                    f"nft add rule {self.NFT_TABLE} output ip daddr {rule.target} accept"
                )
            elif rule.rule_type == "block_domain":
                nft_commands.append(
                    f"# domain '{rule.target}' -> resolve + add to @bigr_dns_set"
                )
                nft_commands.append(
                    f"nft add rule {self.NFT_TABLE} output ip daddr @bigr_dns_set drop"
                )
            elif rule.rule_type == "allow_domain":
                nft_commands.append(
                    f"# domain '{rule.target}' -> resolve + add to @bigr_dns_allow_set"
                )
                nft_commands.append(
                    f"nft add rule {self.NFT_TABLE} output ip daddr @bigr_dns_allow_set accept"
                )

        return {
            "status": "stub",
            "rules_pushed": len(rules),
            "backend": self._backend,
            "nft_commands_preview": nft_commands[:10],  # First 10 for debugging
            "nft_commands_total": len(nft_commands),
            "message": f"Rules queued for {self._backend} (stub mode)",
        }

    async def get_status(self) -> dict:
        """Return adapter-specific status including nftables details."""
        return {
            "platform": "linux",
            "engine": self._backend,
            "is_installed": self._is_installed,
            "rules_applied": self._rules_applied,
            "requires_root": True,
            "nftables_table": self.NFT_TABLE,
            "iptables_chain": self.IPT_CHAIN,
            "supported_backends": ["nftables", "iptables"],
        }

    def platform_name(self) -> str:
        """Return ``'linux'``."""
        return "linux"
