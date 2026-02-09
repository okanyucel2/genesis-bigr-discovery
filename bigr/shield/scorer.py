"""Shield score calculator."""

from __future__ import annotations

from bigr.shield.models import ModuleScore, ShieldGrade

MODULE_WEIGHTS: dict[str, int] = {
    "tls": 20,
    "ports": 20,
    "cve": 25,
    "headers": 10,
    "dns": 10,
    "creds": 10,
    "owasp": 5,
}


def calculate_shield_score(
    module_scores: dict[str, ModuleScore],
) -> tuple[float, ShieldGrade]:
    """Calculate weighted shield score from module scores.

    Only modules that were actually scanned (present in module_scores) are
    included.  Weights are re-normalized so that the enabled modules sum to
    100%.

    Returns:
        A tuple of (score: float 0-100, grade: ShieldGrade).
    """
    if not module_scores:
        return 0.0, ShieldGrade.F

    # Sum weights for enabled modules only
    total_weight = 0.0
    for module_name in module_scores:
        total_weight += MODULE_WEIGHTS.get(module_name, 0)

    if total_weight == 0:
        # All modules have zero weight -- shouldn't happen, but handle it
        # Fall back to simple average
        scores = [ms.score for ms in module_scores.values()]
        avg = sum(scores) / len(scores) if scores else 0.0
        return round(avg, 2), ShieldGrade.from_score(avg)

    # Calculate weighted average, re-normalizing to 100%
    weighted_sum = 0.0
    for module_name, ms in module_scores.items():
        weight = MODULE_WEIGHTS.get(module_name, 0)
        weighted_sum += ms.score * (weight / total_weight)

    score = round(weighted_sum, 2)
    grade = ShieldGrade.from_score(score)
    return score, grade
