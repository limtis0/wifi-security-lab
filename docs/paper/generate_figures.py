"""Regenerate the figures used in the Dragonblood project paper.

Reads the real attack outputs under ``results/`` (raw_samples.csv and
analysis.json) and writes vector PDF figures into ``docs/paper/figures/``.
Run via ``build.sh`` before compiling paper.tex, or directly:

    .venv/bin/python docs/paper/generate_figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as pyplot
import numpy
import pandas

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIRECTORY = REPOSITORY_ROOT / "results"
FIGURES_DIRECTORY = Path(__file__).resolve().parent / "figures"

NANOSECONDS_PER_MILLISECOND = 1_000_000.0
NANOSECONDS_PER_MICROSECOND = 1_000.0

TIMING_GROUP_LABELS = {
    "short_pw": "short",
    "medium_password": "medium",
    "a_very_long_password_string": "long",
}


def configure_matplotlib_style() -> None:
    pyplot.rcParams.update(
        {
            "figure.dpi": 150,
            "savefig.bbox": "tight",
            "font.size": 11,
            "axes.titlesize": 12,
            "axes.grid": True,
            "grid.alpha": 0.3,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )


def find_latest_run_directory(attack_name: str) -> Path:
    """Return the most recent timestamped run directory for an attack."""
    attack_directory = RESULTS_DIRECTORY / attack_name
    run_directories = [path for path in attack_directory.iterdir() if path.is_dir()]
    if not run_directories:
        raise FileNotFoundError(f"No run directories found under {attack_directory}")
    return sorted(run_directories, key=lambda path: path.name)[-1]


def load_analysis(run_directory: Path) -> dict:
    analysis_path = run_directory / "analysis.json"
    return json.loads(analysis_path.read_text())


def load_samples(run_directory: Path) -> pandas.DataFrame:
    return pandas.read_csv(run_directory / "raw_samples.csv")


def generate_timing_figures() -> None:
    run_directory = find_latest_run_directory("dragonblood-timing")
    samples = load_samples(run_directory)
    analysis = load_analysis(run_directory)

    ordered_groups = [
        group for group in TIMING_GROUP_LABELS if group in set(samples["password_group"])
    ]
    display_labels = [TIMING_GROUP_LABELS[group] for group in ordered_groups]

    milliseconds_per_group = [
        samples.loc[samples["password_group"] == group, "response_time_ns"].to_numpy()
        / NANOSECONDS_PER_MILLISECOND
        for group in ordered_groups
    ]

    significant_pair = _find_significant_pair(analysis)

    _plot_timing_boxplot(milliseconds_per_group, display_labels, significant_pair)
    _plot_timing_histogram(milliseconds_per_group, display_labels)


def _find_significant_pair(analysis: dict) -> tuple[str, str, float] | None:
    for comparison in analysis["metadata"]["comparisons"]:
        if comparison["significant"]:
            group_a = TIMING_GROUP_LABELS.get(comparison["group_a"], comparison["group_a"])
            group_b = TIMING_GROUP_LABELS.get(comparison["group_b"], comparison["group_b"])
            return group_a, group_b, comparison["p_value"]
    return None


def _plot_timing_boxplot(
    milliseconds_per_group: list,
    display_labels: list[str],
    significant_pair: tuple[str, str, float] | None,
) -> None:
    figure, axes = pyplot.subplots(figsize=(5.0, 3.4))
    axes.boxplot(milliseconds_per_group, tick_labels=display_labels, showmeans=True)
    axes.set_xlabel("Password group")
    axes.set_ylabel("SAE Commit response time (ms)")
    axes.set_title("SAE timing per password group")

    if significant_pair is not None:
        group_a, group_b, p_value = significant_pair
        axes.text(
            0.98,
            0.02,
            f"Welch's t-test ({group_a} vs {group_b}): p = {p_value:.3f}",
            transform=axes.transAxes,
            horizontalalignment="right",
            verticalalignment="bottom",
            fontsize=9,
            bbox={"boxstyle": "round", "facecolor": "white", "alpha": 0.8},
        )

    figure.savefig(FIGURES_DIRECTORY / "timing_boxplot.pdf")
    pyplot.close(figure)


def _plot_timing_histogram(
    milliseconds_per_group: list,
    display_labels: list[str],
) -> None:
    figure, axes = pyplot.subplots(figsize=(5.0, 3.4))
    for measurements, label in zip(milliseconds_per_group, display_labels):
        axes.hist(measurements, bins=8, alpha=0.55, label=label, edgecolor="black")
    axes.set_xlabel("SAE Commit response time (ms)")
    axes.set_ylabel("Count")
    axes.set_title("Response-time distribution per password group")
    axes.legend(title="Password")
    figure.savefig(FIGURES_DIRECTORY / "timing_hist.pdf")
    pyplot.close(figure)


def generate_recovery_figures() -> None:
    run_directory = find_latest_run_directory("dragonblood-recovery")
    samples = load_samples(run_directory)
    analysis = load_analysis(run_directory)
    metadata = analysis["metadata"]

    _plot_recovery_narrowing(metadata)
    _plot_recovery_clusters(samples, metadata)


def _plot_recovery_narrowing(metadata: dict) -> None:
    dictionary_size = metadata["dictionary_size"]
    candidates_per_round = metadata["candidates_per_round"]
    recovered_password = metadata["recovered_password"]

    candidate_counts = [dictionary_size] + list(candidates_per_round)
    round_indices = list(range(len(candidate_counts)))

    figure, axes = pyplot.subplots(figsize=(5.4, 3.4))
    axes.plot(round_indices, candidate_counts, marker="o", color="#b2182b")
    axes.set_yscale("log")
    axes.set_xlabel("Spoofed MAC addresses used (cumulative)")
    axes.set_ylabel("Remaining password candidates (log)")
    axes.set_title("Dictionary narrowing via multi-MAC intersection")
    axes.set_xticks(round_indices)

    axes.annotate(
        f"recovered: {recovered_password}",
        xy=(round_indices[-1], candidate_counts[-1]),
        xytext=(round_indices[-1] - 3.2, candidate_counts[-1] * 8),
        arrowprops={"arrowstyle": "->"},
        fontsize=9,
    )
    figure.savefig(FIGURES_DIRECTORY / "recovery_narrowing.pdf")
    pyplot.close(figure)


def _plot_recovery_clusters(samples: pandas.DataFrame, metadata: dict) -> None:
    mean_microseconds_per_mac = (
        samples.groupby("password_group")["response_time_ns"].mean()
        / NANOSECONDS_PER_MICROSECOND
    ).sort_values()

    baseline_microseconds = mean_microseconds_per_mac.iloc[0]
    estimated_iterations = metadata["estimated_iterations_per_mac"]

    delta_per_iteration = _estimate_delta_microseconds(
        mean_microseconds_per_mac, baseline_microseconds, estimated_iterations
    )

    figure, axes = pyplot.subplots(figsize=(5.6, 3.6))
    positions = numpy.arange(len(mean_microseconds_per_mac))
    axes.scatter(positions, mean_microseconds_per_mac.to_numpy(), color="#2166ac", zorder=3)

    highest_iteration = max(estimated_iterations.values())
    for iteration in range(1, highest_iteration + 1):
        cluster_center = baseline_microseconds + (iteration - 1) * delta_per_iteration
        axes.axhline(cluster_center, color="grey", linestyle="--", linewidth=0.8, alpha=0.6)
        axes.text(
            len(positions) - 0.5,
            cluster_center,
            f"{iteration} iter",
            fontsize=8,
            verticalalignment="center",
            color="grey",
        )

    axes.set_xlabel("Spoofed MAC address (sorted by mean response time)")
    axes.set_ylabel("Mean SAE Commit time (µs)")
    axes.set_title("Per-MAC timing clusters at baseline + k·Δt")
    axes.set_xticks(positions)
    axes.set_xticklabels([mac.split(":")[-1] for mac in mean_microseconds_per_mac.index], rotation=45)
    figure.savefig(FIGURES_DIRECTORY / "recovery_clusters.pdf")
    pyplot.close(figure)


def _estimate_delta_microseconds(
    mean_microseconds_per_mac: pandas.Series,
    baseline_microseconds: float,
    estimated_iterations: dict[str, int],
) -> float:
    """Estimate the per-iteration time from MACs whose iteration count is known.

    Uses the calibration relationship mean = baseline + (iterations - 1) * Delta,
    averaged over every MAC that required more than one iteration.
    """
    per_mac_estimates = []
    for mac_address, iterations in estimated_iterations.items():
        if iterations > 1 and mac_address in mean_microseconds_per_mac.index:
            offset = mean_microseconds_per_mac[mac_address] - baseline_microseconds
            per_mac_estimates.append(offset / (iterations - 1))

    if not per_mac_estimates:
        return baseline_microseconds

    return float(numpy.mean(per_mac_estimates))


def main() -> None:
    FIGURES_DIRECTORY.mkdir(parents=True, exist_ok=True)
    configure_matplotlib_style()
    generate_timing_figures()
    generate_recovery_figures()
    written_figures = sorted(path.name for path in FIGURES_DIRECTORY.glob("*.pdf"))
    print(f"Wrote {len(written_figures)} figures to {FIGURES_DIRECTORY}:")
    for figure_name in written_figures:
        print(f"  - {figure_name}")


if __name__ == "__main__":
    main()
