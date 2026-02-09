"""Tests for bigr.shield.scorer — Shield score calculator."""

from __future__ import annotations

import pytest

from bigr.shield.models import ModuleScore, ShieldGrade
from bigr.shield.scorer import calculate_shield_score


class TestCalculateShieldScore:
    """Tests for calculate_shield_score()."""

    def test_single_module_perfect(self):
        """Single module with score 100 should give A+."""
        scores = {"tls": ModuleScore(module="tls", score=100.0)}
        score, grade = calculate_shield_score(scores)
        assert score == 100.0
        assert grade == ShieldGrade.A_PLUS

    def test_single_module_low(self):
        """Single module with score 30 should give F."""
        scores = {"tls": ModuleScore(module="tls", score=30.0)}
        score, grade = calculate_shield_score(scores)
        assert score == 30.0
        assert grade == ShieldGrade.F

    def test_multi_module_weighted(self):
        """Multiple modules should be weighted and normalized correctly."""
        # tls=20 weight, ports=20 weight, cve=25 weight
        # Total weight = 65
        # Weighted = (90*20/65) + (80*20/65) + (70*25/65)
        # = 27.692 + 24.615 + 26.923 = 79.23
        scores = {
            "tls": ModuleScore(module="tls", score=90.0),
            "ports": ModuleScore(module="ports", score=80.0),
            "cve": ModuleScore(module="cve", score=70.0),
        }
        score, grade = calculate_shield_score(scores)
        assert score == pytest.approx(79.23, abs=0.01)
        assert grade == ShieldGrade.B

    def test_multi_module_all_perfect(self):
        """All modules at 100 should give 100/A+."""
        scores = {
            "tls": ModuleScore(module="tls", score=100.0),
            "ports": ModuleScore(module="ports", score=100.0),
            "cve": ModuleScore(module="cve", score=100.0),
            "headers": ModuleScore(module="headers", score=100.0),
            "dns": ModuleScore(module="dns", score=100.0),
            "creds": ModuleScore(module="creds", score=100.0),
            "owasp": ModuleScore(module="owasp", score=100.0),
        }
        score, grade = calculate_shield_score(scores)
        assert score == 100.0
        assert grade == ShieldGrade.A_PLUS

    def test_multi_module_all_zero(self):
        """All modules at 0 should give 0/F."""
        scores = {
            "tls": ModuleScore(module="tls", score=0.0),
            "ports": ModuleScore(module="ports", score=0.0),
        }
        score, grade = calculate_shield_score(scores)
        assert score == 0.0
        assert grade == ShieldGrade.F

    def test_empty_module_scores(self):
        """Empty module scores should return 0/F."""
        score, grade = calculate_shield_score({})
        assert score == 0.0
        assert grade == ShieldGrade.F

    def test_only_enabled_modules_counted(self):
        """Only modules present in the dict should affect the score."""
        # If only tls module runs with score 80:
        # tls weight=20, total_weight=20, score = 80*(20/20) = 80
        scores_one = {"tls": ModuleScore(module="tls", score=80.0)}
        score_one, _ = calculate_shield_score(scores_one)
        assert score_one == 80.0

        # Adding another module with lower score should change result
        scores_two = {
            "tls": ModuleScore(module="tls", score=80.0),
            "ports": ModuleScore(module="ports", score=60.0),
        }
        score_two, _ = calculate_shield_score(scores_two)
        # tls=80*20/40 + ports=60*20/40 = 40 + 30 = 70
        assert score_two == 70.0
        assert score_two != score_one

    def test_grade_mapping_from_score(self):
        """Verify grade assignment for various score values."""
        test_cases = [
            (97, ShieldGrade.A_PLUS),
            (92, ShieldGrade.A),
            (87, ShieldGrade.B_PLUS),
            (78, ShieldGrade.B),
            (72, ShieldGrade.C_PLUS),
            (65, ShieldGrade.C),
            (45, ShieldGrade.D),
            (20, ShieldGrade.F),
        ]
        for score_val, expected_grade in test_cases:
            scores = {"tls": ModuleScore(module="tls", score=float(score_val))}
            _, grade = calculate_shield_score(scores)
            assert grade == expected_grade, f"Score {score_val} expected {expected_grade}, got {grade}"

    def test_unknown_module_name(self):
        """A module not in MODULE_WEIGHTS gets weight 0; falls back to average."""
        scores = {"unknown_module": ModuleScore(module="unknown_module", score=75.0)}
        score, grade = calculate_shield_score(scores)
        # total_weight = 0, falls back to simple average
        assert score == 75.0
        assert grade == ShieldGrade.B

    def test_mix_known_and_unknown_module(self):
        """Unknown module weight is 0, so it contributes nothing to weighted sum."""
        scores = {
            "tls": ModuleScore(module="tls", score=80.0),
            "custom": ModuleScore(module="custom", score=50.0),  # weight=0
        }
        score, _ = calculate_shield_score(scores)
        # total_weight = 20 (only tls), so score = 80.0*(20/20) = 80.0
        # custom has weight 0, contributes 50.0*(0/20)=0
        assert score == 80.0
