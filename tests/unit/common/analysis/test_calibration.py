from __future__ import annotations

import pytest

from attacks.common.analysis.calibration import CalibrationError, TimingCalibrator
from attacks.common.analysis.stats import GroupStatistics


def make_group_statistics(
    group_name: str,
    mean_ns: float,
    std_ns: float = 10_000.0,
    count: int = 200,
) -> GroupStatistics:
    return GroupStatistics(
        group_name=group_name,
        count=count,
        mean_ns=mean_ns,
        median_ns=mean_ns,
        std_ns=std_ns,
        percentile_5=mean_ns - 2 * std_ns,
        percentile_95=mean_ns + 2 * std_ns,
    )


class TestTimingCalibratorCleanSignal:
    def test_detects_ns_per_iteration_from_discrete_clusters(self):
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_000),
            "mac_1": make_group_statistics("mac_1", 500_000),
            "mac_2": make_group_statistics("mac_2", 1_000_000),
            "mac_3": make_group_statistics("mac_3", 1_500_000),
            "mac_4": make_group_statistics("mac_4", 1_500_000),
        }

        calibrator = TimingCalibrator()
        result = calibrator.calibrate(statistics)

        assert abs(result.nanoseconds_per_iteration - 500_000) < 10_000

    def test_baseline_is_minimum_mean(self):
        statistics = {
            "mac_0": make_group_statistics("mac_0", 1_000_000),
            "mac_1": make_group_statistics("mac_1", 500_000),
            "mac_2": make_group_statistics("mac_2", 1_500_000),
        }

        calibrator = TimingCalibrator()
        result = calibrator.calibrate(statistics)

        assert abs(result.baseline_ns - 500_000) < 10_000

    def test_detects_correct_cluster_count(self):
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_000),
            "mac_1": make_group_statistics("mac_1", 500_000),
            "mac_2": make_group_statistics("mac_2", 1_000_000),
            "mac_3": make_group_statistics("mac_3", 1_500_000),
        }

        calibrator = TimingCalibrator()
        result = calibrator.calibrate(statistics)

        assert result.detected_cluster_count == 3


class TestTimingCalibratorNoisySignal:
    def test_filters_noise_level_gaps(self):
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_100, std_ns=5_000),
            "mac_1": make_group_statistics("mac_1", 500_200, std_ns=5_000),
            "mac_2": make_group_statistics("mac_2", 1_000_000, std_ns=5_000),
            "mac_3": make_group_statistics("mac_3", 1_500_300, std_ns=5_000),
        }

        calibrator = TimingCalibrator()
        result = calibrator.calibrate(statistics)

        assert 450_000 < result.nanoseconds_per_iteration < 550_000

    def test_works_with_large_baseline_offset(self):
        baseline = 100_000_000
        delta = 500_000
        statistics = {
            "mac_0": make_group_statistics("mac_0", baseline + 1 * delta, std_ns=20_000),
            "mac_1": make_group_statistics("mac_1", baseline + 1 * delta, std_ns=20_000),
            "mac_2": make_group_statistics("mac_2", baseline + 2 * delta, std_ns=20_000),
            "mac_3": make_group_statistics("mac_3", baseline + 3 * delta, std_ns=20_000),
            "mac_4": make_group_statistics("mac_4", baseline + 5 * delta, std_ns=20_000),
        }

        calibrator = TimingCalibrator()
        result = calibrator.calibrate(statistics)

        assert 450_000 < result.nanoseconds_per_iteration < 550_000
        assert abs(result.baseline_ns - (baseline + delta)) < 50_000


class TestTimingCalibratorEdgeCases:
    def test_raises_when_all_macs_same_iteration_count(self):
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_000, std_ns=10_000),
            "mac_1": make_group_statistics("mac_1", 500_050, std_ns=10_000),
            "mac_2": make_group_statistics("mac_2", 500_100, std_ns=10_000),
        }

        calibrator = TimingCalibrator()

        with pytest.raises(ValueError, match="Could not calibrate"):
            calibrator.calibrate(statistics)

    def test_works_with_two_macs_different_iterations(self):
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_000),
            "mac_1": make_group_statistics("mac_1", 1_000_000),
        }

        calibrator = TimingCalibrator()
        result = calibrator.calibrate(statistics)

        assert abs(result.nanoseconds_per_iteration - 500_000) < 10_000
        assert result.detected_cluster_count == 2

    def test_raises_with_single_mac(self):
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_000),
        }

        calibrator = TimingCalibrator()

        with pytest.raises(ValueError, match="Need at least 2 MACs"):
            calibrator.calibrate(statistics)


class TestTimingCalibratorRaisesCalibrationError:
    def test_no_signal_raises_calibration_error(self):
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_000, std_ns=10_000),
            "mac_1": make_group_statistics("mac_1", 500_050, std_ns=10_000),
            "mac_2": make_group_statistics("mac_2", 500_100, std_ns=10_000),
        }

        calibrator = TimingCalibrator()

        with pytest.raises(CalibrationError):
            calibrator.calibrate(statistics)

    def test_calibration_error_is_value_error_subclass(self):
        # Callers that still catch ValueError must keep working.
        assert issubclass(CalibrationError, ValueError)


class TestTimingCalibratorEstimateIterationCount:
    def test_estimates_correct_iteration_for_baseline(self):
        calibrator = TimingCalibrator()
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_000),
            "mac_1": make_group_statistics("mac_1", 1_000_000),
        }
        result = calibrator.calibrate(statistics)

        assert calibrator.estimate_iteration_count(500_000, result) == 1

    def test_estimates_correct_iteration_for_offset(self):
        calibrator = TimingCalibrator()
        statistics = {
            "mac_0": make_group_statistics("mac_0", 500_000),
            "mac_1": make_group_statistics("mac_1", 1_000_000),
        }
        result = calibrator.calibrate(statistics)

        assert calibrator.estimate_iteration_count(1_000_000, result) == 2
        assert calibrator.estimate_iteration_count(1_500_000, result) == 3
