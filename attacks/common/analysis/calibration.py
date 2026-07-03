from __future__ import annotations

import logging
from dataclasses import dataclass

from attacks.common.analysis.stats import GroupStatistics

logger = logging.getLogger(__name__)


class CalibrationError(ValueError):
    """Raised when timing data yields no usable per-iteration signal.

    Subclasses ValueError so existing callers that catch ValueError keep working.
    The most important case is "all MAC means are within noise", which is exactly
    what a constant-time (patched) SAE implementation produces.
    """


@dataclass(frozen=True)
class CalibrationResult:
    baseline_ns: float
    nanoseconds_per_iteration: float
    detected_cluster_count: int
    noise_threshold_ns: float


class TimingCalibrator:
    """Extracts ns_per_iteration and baseline from SAE timing data.

    Uses the discrete clustering structure described in the Dragonblood paper
    (Vanhoef & Ronen, 2019): per-MAC means cluster at baseline + k*Δt for
    integer k, where Δt is the time per hash-to-curve iteration.
    """

    def calibrate(
        self,
        statistics_per_mac: dict[str, GroupStatistics],
    ) -> CalibrationResult:
        """Analyze per-MAC timing statistics to extract calibration constants.

        Raises ValueError if calibration fails (e.g. all MACs produce the
        same iteration count, so no timing difference is observable).
        """
        if len(statistics_per_mac) < 2:
            raise CalibrationError(
                f"Need at least 2 MACs to calibrate, got {len(statistics_per_mac)}"
            )

        sorted_means = sorted(
            statistics.mean_ns for statistics in statistics_per_mac.values()
        )
        baseline_ns = sorted_means[0]

        gaps = [
            sorted_means[index + 1] - sorted_means[index]
            for index in range(len(sorted_means) - 1)
        ]

        noise_threshold_ns = self._compute_noise_threshold(statistics_per_mac)

        significant_gaps = [gap for gap in gaps if gap > noise_threshold_ns]

        if not significant_gaps:
            raise CalibrationError(
                f"Could not calibrate: all {len(sorted_means)} MAC means are within "
                f"noise (threshold={noise_threshold_ns:.0f}ns). "
                f"Try increasing --max-macs or --samples."
            )

        nanoseconds_per_iteration = min(significant_gaps)

        detected_cluster_count = self._count_clusters(
            sorted_means, nanoseconds_per_iteration, noise_threshold_ns,
        )

        self._validate_gap_multiples(significant_gaps, nanoseconds_per_iteration)

        logger.info(
            "Calibrated: baseline=%.0fns, Δt=%.0fns, %d clusters detected, noise_threshold=%.0fns",
            baseline_ns,
            nanoseconds_per_iteration,
            detected_cluster_count,
            noise_threshold_ns,
        )

        return CalibrationResult(
            baseline_ns=baseline_ns,
            nanoseconds_per_iteration=nanoseconds_per_iteration,
            detected_cluster_count=detected_cluster_count,
            noise_threshold_ns=noise_threshold_ns,
        )

    def estimate_iteration_count(
        self,
        mean_ns: float,
        calibration: CalibrationResult,
    ) -> int:
        """Estimate the hash-to-curve iteration count from a mean response time."""
        offset = mean_ns - calibration.baseline_ns
        return max(1, round(offset / calibration.nanoseconds_per_iteration) + 1)

    def _compute_noise_threshold(
        self,
        statistics_per_mac: dict[str, GroupStatistics],
    ) -> float:
        """3× the average standard error across MACs."""
        total_standard_error = 0.0
        for statistics in statistics_per_mac.values():
            if statistics.count > 1:
                standard_error = statistics.std_ns / (statistics.count ** 0.5)
            else:
                standard_error = 0.0
            total_standard_error += standard_error

        average_standard_error = total_standard_error / len(statistics_per_mac)
        return 3 * average_standard_error

    def _count_clusters(
        self,
        sorted_means: list[float],
        nanoseconds_per_iteration: float,
        noise_threshold: float,
    ) -> int:
        """Count distinct timing clusters in the sorted means."""
        cluster_count = 1
        current_cluster_center = sorted_means[0]

        for mean in sorted_means[1:]:
            if mean - current_cluster_center > noise_threshold:
                cluster_count += 1
                current_cluster_center = mean

        return cluster_count

    def _validate_gap_multiples(
        self,
        significant_gaps: list[float],
        nanoseconds_per_iteration: float,
    ) -> None:
        """Warn if larger gaps aren't clean integer multiples of the fundamental."""
        for gap in significant_gaps:
            ratio = gap / nanoseconds_per_iteration
            if abs(ratio - round(ratio)) > 0.3:
                logger.warning(
                    "Gap %.0fns is not a clean multiple of %.0fns (ratio=%.2f)",
                    gap,
                    nanoseconds_per_iteration,
                    ratio,
                )
