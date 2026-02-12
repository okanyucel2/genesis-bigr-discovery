"""Tests for Safety Streak service."""

from bigr.engagement.streak import (
    STREAK_THRESHOLD,
    calculate_streak,
    get_milestone,
    get_next_milestone,
)


class TestCalculateStreak:
    def test_first_green_day_starts_streak(self):
        result = calculate_streak(
            kalkan_score=85,
            current_streak=0,
            longest_streak=0,
            total_safe_days=0,
            streak_broken_count=0,
        )
        assert result.current_streak_days == 1
        assert result.longest_streak_days == 1
        assert result.streak_broken is False
        assert result.total_safe_days == 1

    def test_consecutive_green_increments(self):
        result = calculate_streak(
            kalkan_score=90,
            current_streak=5,
            longest_streak=10,
            total_safe_days=20,
            streak_broken_count=0,
        )
        assert result.current_streak_days == 6
        assert result.longest_streak_days == 10
        assert result.total_safe_days == 21

    def test_score_below_threshold_breaks_streak(self):
        result = calculate_streak(
            kalkan_score=70,
            current_streak=15,
            longest_streak=15,
            total_safe_days=30,
            streak_broken_count=0,
        )
        assert result.current_streak_days == 0
        assert result.streak_broken is True
        assert result.streak_broken_count == 1
        assert result.total_safe_days == 30  # not incremented

    def test_longest_streak_preserved_after_break(self):
        result = calculate_streak(
            kalkan_score=50,
            current_streak=5,
            longest_streak=20,
            total_safe_days=50,
            streak_broken_count=2,
        )
        assert result.current_streak_days == 0
        assert result.longest_streak_days == 20
        assert result.streak_broken_count == 3

    def test_new_longest_streak(self):
        result = calculate_streak(
            kalkan_score=95,
            current_streak=20,
            longest_streak=20,
            total_safe_days=40,
            streak_broken_count=1,
        )
        assert result.current_streak_days == 21
        assert result.longest_streak_days == 21

    def test_threshold_boundary_passes(self):
        result = calculate_streak(
            kalkan_score=STREAK_THRESHOLD,
            current_streak=3,
            longest_streak=5,
            total_safe_days=10,
            streak_broken_count=0,
        )
        assert result.current_streak_days == 4
        assert result.streak_broken is False


class TestGetMilestone:
    def test_7_days_first_week(self):
        m = get_milestone(7)
        assert m is not None
        assert m.title_tr == "Ilk Hafta"
        assert m.badge == "fire"

    def test_30_days_monthly(self):
        m = get_milestone(30)
        assert m is not None
        assert m.title_tr == "Aylik Koruyucu"
        assert m.badge == "shield"

    def test_90_days_quarterly(self):
        m = get_milestone(90)
        assert m is not None
        assert m.title_tr == "Ceyrek Sampiyonu"
        assert m.badge == "star"

    def test_below_7_no_milestone(self):
        m = get_milestone(3)
        assert m is None

    def test_45_days_returns_monthly(self):
        m = get_milestone(45)
        assert m is not None
        assert m.title_tr == "Aylik Koruyucu"


class TestGetNextMilestone:
    def test_next_after_0_is_first_week(self):
        n = get_next_milestone(0)
        assert n is not None
        assert n["title_tr"] == "Ilk Hafta"
        assert n["days_remaining"] == 7

    def test_next_after_10_is_monthly(self):
        n = get_next_milestone(10)
        assert n is not None
        assert n["title_tr"] == "Aylik Koruyucu"
        assert n["days_remaining"] == 20

    def test_next_after_42_is_quarterly(self):
        n = get_next_milestone(42)
        assert n is not None
        assert n["title_tr"] == "Ceyrek Sampiyonu"
        assert n["days_remaining"] == 48

    def test_next_after_100_is_none(self):
        n = get_next_milestone(100)
        assert n is None
