"""Differential privacy primitives for collective threat sharing.

Implements:
- Randomized response (epsilon-differential privacy)
- Laplace noise mechanism for severity scores
- k-anonymity threshold enforcement
- Crowd-based confidence calculation
"""

from __future__ import annotations

import math
import random


class DifferentialPrivacy:
    """Implements differential privacy for threat signal sharing.

    Privacy is controlled by two parameters:
    - epsilon: The privacy budget. Lower = more private, higher = more accurate.
      Typical range: 0.1 (very private) to 10.0 (very accurate).
    - k_anonymity: Minimum number of unique reporters before a signal is shared.
      Higher k = harder to de-anonymize any single reporter.
    """

    def __init__(self, epsilon: float = 1.0, k_anonymity: int = 3) -> None:
        if epsilon <= 0:
            raise ValueError("epsilon must be positive")
        if k_anonymity < 1:
            raise ValueError("k_anonymity must be at least 1")
        self.epsilon = epsilon
        self.k_anonymity = k_anonymity

    def randomized_response(self, true_value: bool) -> bool:
        """Flip the answer with probability based on epsilon.

        With probability p = e^epsilon / (1 + e^epsilon), report truthfully.
        Otherwise, flip the response.
        This provides epsilon-differential privacy for binary attributes.

        Args:
            true_value: The actual boolean value to report.

        Returns:
            The (possibly flipped) response.
        """
        p = math.exp(self.epsilon) / (1.0 + math.exp(self.epsilon))
        if random.random() < p:
            return true_value
        return not true_value

    def add_noise_to_severity(self, severity: float) -> float:
        """Add Laplace noise to severity scores.

        Uses the Laplace mechanism: noise ~ Laplace(0, sensitivity/epsilon).
        The severity is bounded in [0, 1], so sensitivity = 1.0.
        After adding noise, the result is clamped back to [0, 1].

        Args:
            severity: The true severity value in [0.0, 1.0].

        Returns:
            Noised severity clamped to [0.0, 1.0].
        """
        sensitivity = 1.0  # severity is bounded [0, 1]
        scale = sensitivity / self.epsilon

        # Sample from Laplace(0, scale) using inverse CDF
        u = random.random() - 0.5
        noise = -scale * _sign(u) * math.log(1.0 - 2.0 * abs(u))

        noised = severity + noise
        return round(max(0.0, min(1.0, noised)), 2)

    def meets_k_anonymity(self, reporter_count: int) -> bool:
        """Check if a signal has enough unique reporters to be shared.

        Args:
            reporter_count: Number of unique agents that reported this signal.

        Returns:
            True if the signal meets the k-anonymity threshold.
        """
        return reporter_count >= self.k_anonymity

    def calculate_confidence(
        self, reporter_count: int, consistency: float
    ) -> float:
        """Calculate confidence based on crowd size and consistency.

        Confidence is the product of:
        - crowd_factor: Diminishing returns up to 10 reporters (capped at 1.0)
        - consistency: How similar the severity reports are (0.0-1.0)

        Args:
            reporter_count: Number of unique agents reporting.
            consistency: Score similarity metric (0.0-1.0).

        Returns:
            Confidence value in [0.0, 1.0].
        """
        crowd_factor = min(1.0, reporter_count / 10.0)
        return round(crowd_factor * consistency, 2)


def _sign(x: float) -> float:
    """Return the sign of x."""
    if x > 0:
        return 1.0
    elif x < 0:
        return -1.0
    return 0.0
