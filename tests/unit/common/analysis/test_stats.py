from __future__ import annotations

import pytest

from attacks.common.analysis.stats import (
    compare_groups,
    compute_effect_size,
    compute_group_statistics,
    estimate_required_samples,
)


# --- compute_group_statistics ---


class TestComputeGroupStatistics:
    def test_known_values(self):
        result = compute_group_statistics("group_a", [100, 200, 300])

        assert result.group_name == "group_a"
        assert result.count == 3
        assert result.mean_ns == 200.0
        assert result.median_ns == 200.0
        assert result.std_ns == pytest.approx(100.0, rel=0.01)
        assert result.percentile_5 <= 110
        assert result.percentile_95 >= 290

    def test_single_value(self):
        result = compute_group_statistics("single", [42])

        assert result.mean_ns == 42.0
        assert result.median_ns == 42.0
        assert result.std_ns == 0.0
        assert result.count == 1

    def test_all_identical_values(self):
        result = compute_group_statistics("identical", [500, 500, 500, 500])

        assert result.mean_ns == 500.0
        assert result.std_ns == 0.0


# --- compare_groups ---


class TestCompareGroups:
    def test_separated_distributions_are_significant(self):
        low_group = [100 + i for i in range(100)]
        high_group = [10_000 + i for i in range(100)]

        result = compare_groups("low", low_group, "high", high_group)

        assert result.significant == True
        assert result.p_value < 0.05
        assert result.test_name == "Welch's t-test"

    def test_identical_distributions_are_not_significant(self):
        values = list(range(100))

        result = compare_groups("a", values, "b", values)

        assert result.significant == False
        assert result.p_value > 0.05

    @pytest.mark.parametrize("significance_level", [0.01, 0.10])
    def test_significance_level_affects_result(self, significance_level: float):
        low_group = [100 + i for i in range(50)]
        high_group = [10_000 + i for i in range(50)]

        result = compare_groups(
            "low", low_group, "high", high_group,
            significance_level=significance_level,
        )

        assert result.significant == (result.p_value < significance_level)


# --- compute_effect_size ---


class TestComputeEffectSize:
    def test_well_separated_groups_large_effect(self):
        low_group = [100 + i for i in range(50)]
        high_group = [10_000 + i for i in range(50)]

        effect = compute_effect_size(low_group, high_group)

        assert abs(effect) > 0.8

    def test_identical_groups_zero_effect(self):
        values = [100] * 50

        effect = compute_effect_size(values, values)

        assert effect == pytest.approx(0.0, abs=0.01)


# --- estimate_required_samples ---


class TestEstimateRequiredSamples:
    def test_distinguishable_pilots_returns_positive(self):
        low_pilot = [100 + i for i in range(30)]
        high_pilot = [10_000 + i for i in range(30)]

        required_n = estimate_required_samples(low_pilot, high_pilot)

        assert required_n > 0

    def test_identical_pilots_returns_negative(self):
        values = [100] * 30

        required_n = estimate_required_samples(values, values)

        assert required_n == -1
