from __future__ import annotations

import logging
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

logger = logging.getLogger(__name__)


def ns_to_ms(nanoseconds: int) -> float:
    return nanoseconds / 1_000_000


def plot_timing_histogram(
    grouped_samples: dict[str, list[int]],
    output_path: Path,
) -> Path:
    """Plot overlaid histograms of timing distributions per group."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure, axes = plt.subplots(figsize=(10, 6))

    for group_name, timing_values in grouped_samples.items():
        if timing_values:
            values_ms = [ns_to_ms(nanoseconds) for nanoseconds in timing_values]
            axes.hist(values_ms, bins=50, alpha=0.5, label=group_name)

    axes.set_xlabel("Response Time (ms)")
    axes.set_ylabel("Frequency")
    axes.set_title("SAE Commit Response Time Distribution")
    if grouped_samples:
        axes.legend()

    figure.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(figure)

    logger.info("Saved timing histogram to %s", output_path)
    return output_path


def plot_timing_boxplot(
    grouped_samples: dict[str, list[int]],
    output_path: Path,
) -> Path:
    """Plot box plots of timing distributions per group."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure, axes = plt.subplots(figsize=(10, 6))

    group_names = list(grouped_samples.keys())
    data = []
    for group_name in group_names:
        timing_values = grouped_samples[group_name]
        if timing_values:
            data.append([ns_to_ms(nanoseconds) for nanoseconds in timing_values])
        else:
            data.append([])

    if data:
        axes.boxplot(data, tick_labels=group_names)

    axes.set_xlabel("Password Group")
    axes.set_ylabel("Response Time (ms)")
    axes.set_title("SAE Commit Response Time Box Plot")

    figure.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(figure)

    logger.info("Saved timing box plot to %s", output_path)
    return output_path


def plot_timing_cdf(
    grouped_samples: dict[str, list[int]],
    output_path: Path,
) -> Path:
    """Plot cumulative distribution functions of timing per group."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure, axes = plt.subplots(figsize=(10, 6))

    for group_name, timing_values in grouped_samples.items():
        if timing_values:
            sorted_values = np.sort([ns_to_ms(nanoseconds) for nanoseconds in timing_values])
            cumulative_probabilities = np.arange(1, len(sorted_values) + 1) / len(sorted_values)
            axes.plot(sorted_values, cumulative_probabilities, label=group_name)

    axes.set_xlabel("Response Time (ms)")
    axes.set_ylabel("Cumulative Probability")
    axes.set_title("SAE Commit Response Time CDF")
    if grouped_samples:
        axes.legend()

    figure.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(figure)

    logger.info("Saved timing CDF to %s", output_path)
    return output_path
