from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np
from scipy import stats as scipy_stats

logger = logging.getLogger(__name__)


@dataclass
class GroupStatistics:
    group_name: str
    count: int
    mean_ns: float
    median_ns: float
    std_ns: float
    percentile_5: float
    percentile_95: float


@dataclass
class ComparisonResult:
    group_a: str
    group_b: str
    statistic: float
    p_value: float
    significant: bool
    test_name: str


def compute_group_statistics(group_name: str, timing_values_ns: list[int]) -> GroupStatistics:
    """Compute descriptive statistics for a group of timing samples."""
    array = np.array(timing_values_ns, dtype=np.float64)
    return GroupStatistics(
        group_name=group_name,
        count=len(array),
        mean_ns=float(np.mean(array)),
        median_ns=float(np.median(array)),
        std_ns=float(np.std(array, ddof=1)) if len(array) > 1 else 0.0,
        percentile_5=float(np.percentile(array, 5)),
        percentile_95=float(np.percentile(array, 95)),
    )


def compare_groups(
    group_a_name: str,
    group_a_values: list[int],
    group_b_name: str,
    group_b_values: list[int],
    significance_level: float = 0.05,
) -> ComparisonResult:
    """Compare two groups using Welch's t-test for unequal variances."""
    array_a = np.array(group_a_values, dtype=np.float64)
    array_b = np.array(group_b_values, dtype=np.float64)

    statistic, p_value = scipy_stats.ttest_ind(array_a, array_b, equal_var=False)

    result = ComparisonResult(
        group_a=group_a_name,
        group_b=group_b_name,
        statistic=float(statistic),
        p_value=float(p_value),
        significant=p_value < significance_level,
        test_name="Welch's t-test",
    )

    logger.info(
        "Comparison %s vs %s: t=%.4f p=%.6f significant=%s",
        group_a_name,
        group_b_name,
        result.statistic,
        result.p_value,
        result.significant,
    )

    return result


def compute_effect_size(group_a_values: list[int], group_b_values: list[int]) -> float:
    """Compute Cohen's d effect size between two groups."""
    array_a = np.array(group_a_values, dtype=np.float64)
    array_b = np.array(group_b_values, dtype=np.float64)

    mean_difference = np.mean(array_a) - np.mean(array_b)
    pooled_std = np.sqrt(
        (np.var(array_a, ddof=1) + np.var(array_b, ddof=1)) / 2
    )

    if pooled_std == 0:
        return 0.0

    return float(mean_difference / pooled_std)


def estimate_required_samples(
    pilot_group_a: list[int],
    pilot_group_b: list[int],
    desired_power: float = 0.8,
    significance_level: float = 0.05,
) -> int:
    """Estimate the number of samples needed per group to achieve desired statistical power.

    Uses the pilot data to estimate effect size, then computes required N.
    """
    effect_size = abs(compute_effect_size(pilot_group_a, pilot_group_b))

    if effect_size == 0:
        logger.warning("Effect size is zero — cannot estimate required samples")
        return -1

    # Two-sample t-test power analysis approximation
    z_alpha = scipy_stats.norm.ppf(1 - significance_level / 2)
    z_beta = scipy_stats.norm.ppf(desired_power)
    required_n = int(np.ceil(2 * ((z_alpha + z_beta) / effect_size) ** 2))

    logger.info(
        "Estimated %d samples per group needed (effect_size=%.4f, power=%.2f, alpha=%.3f)",
        required_n,
        effect_size,
        desired_power,
        significance_level,
    )

    return required_n
