"""TCP/IP stack fingerprinting for OS detection."""

from __future__ import annotations

from bigr.classifier.fingerprint_v2 import TcpFingerprint

# TTL-based OS detection database
# Key: (min_ttl, max_ttl) inclusive range
TTL_OS_MAP = {
    (60, 65): "Linux",
    (120, 129): "Windows",
    (250, 256): "Network Equipment (Cisco/Solaris)",
}

# Window size hints
WINDOW_OS_MAP = {
    65535: "Windows XP/2003",
    8192: "Windows 7/8",
    29200: "Linux (modern)",
    5840: "Linux (older)",
    14600: "Linux",
    32768: "Network Equipment",
}

# Known TCP option orderings per OS
TCP_OPTION_SIGNATURES: dict[tuple[str, ...], str] = {
    ("MSS", "SACK_PERM", "Timestamps", "NOP", "Window_Scale"): "Linux",
    ("MSS", "NOP", "Window_Scale", "NOP", "NOP", "SACK_PERM"): "Windows",
    ("MSS", "NOP", "Window_Scale", "NOP", "NOP", "Timestamps", "SACK_PERM", "EOL"): "macOS",
}


def guess_os_by_ttl(ttl: int) -> str | None:
    """Guess OS family from observed TTL value.

    Different OSes use different initial TTL:
    - Linux: 64
    - Windows: 128
    - Cisco/Solaris: 255
    - macOS: 64

    Network hops reduce TTL, so we check ranges.
    """
    for (low, high), os_name in TTL_OS_MAP.items():
        if low <= ttl <= high:
            return os_name
    return None


def guess_os_by_window_size(window_size: int) -> str | None:
    """Guess OS from TCP window size."""
    return WINDOW_OS_MAP.get(window_size)


def analyze_tcp_options(options: list[str]) -> str | None:
    """Analyze TCP options ordering for OS fingerprint.

    Different OSes have different default TCP option sets:
    - Linux: MSS, SACK_PERM, Timestamps, NOP, Window_Scale
    - Windows: MSS, NOP, Window_Scale, NOP, NOP, SACK_PERM
    - macOS: MSS, NOP, Window_Scale, NOP, NOP, Timestamps, SACK_PERM, EOL
    """
    if not options:
        return None

    options_tuple = tuple(options)

    # Exact match first
    if options_tuple in TCP_OPTION_SIGNATURES:
        return TCP_OPTION_SIGNATURES[options_tuple]

    # Partial/prefix matching as fallback
    for sig, os_name in TCP_OPTION_SIGNATURES.items():
        if len(options) >= 3 and options[:3] == list(sig[:3]):
            return os_name

    return None


def build_tcp_fingerprint(
    ttl: int | None = None,
    window_size: int | None = None,
    df_bit: bool | None = None,
    tcp_options: list[str] | None = None,
) -> TcpFingerprint:
    """Build a TCP fingerprint from observed values."""
    os_guesses: list[str] = []

    if ttl is not None:
        ttl_guess = guess_os_by_ttl(ttl)
        if ttl_guess:
            os_guesses.append(ttl_guess)

    if window_size is not None:
        ws_guess = guess_os_by_window_size(window_size)
        if ws_guess:
            os_guesses.append(ws_guess)

    opts = tcp_options or []
    if opts:
        opt_guess = analyze_tcp_options(opts)
        if opt_guess:
            os_guesses.append(opt_guess)

    # Pick the most common guess, or first if tie
    os_guess: str | None = None
    if os_guesses:
        # Count occurrences
        counts: dict[str, int] = {}
        for g in os_guesses:
            # Normalize: "Linux (modern)" -> "Linux"
            base = g.split("(")[0].strip() if "(" in g else g
            counts[base] = counts.get(base, 0) + 1
        os_guess = max(counts, key=lambda k: counts[k])

    return TcpFingerprint(
        ttl=ttl,
        window_size=window_size,
        df_bit=df_bit,
        tcp_options=opts,
        os_guess=os_guess,
    )
