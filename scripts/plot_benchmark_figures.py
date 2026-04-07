from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt


def load_scenario_summary(csv_path: Path) -> list[dict]:
    rows: list[dict] = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            denial_counts_raw = row.get("denial_reason_counts", "{}")
            try:
                denial_counts = json.loads(denial_counts_raw) if denial_counts_raw else {}
            except json.JSONDecodeError:
                denial_counts = {}
            rows.append(
                {
                    "scenario": row["scenario"],
                    "events": int(float(row["events"])),
                    "avg_latency_ms": float(row["avg_latency_ms"]),
                    "p50_latency_ms": float(row["p50_latency_ms"]),
                    "p95_latency_ms": float(row["p95_latency_ms"]),
                    "poisoned_event_count": int(float(row["poisoned_event_count"])),
                    "poisoned_event_rate": float(row["poisoned_event_rate"]),
                    "denial_reason_counts": denial_counts,
                }
            )
    return rows


def save_poison_rate_chart(rows: list[dict], out_path: Path) -> None:
    scenarios = [r["scenario"] for r in rows]
    rates = [r["poisoned_event_rate"] for r in rows]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(scenarios, rates)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Poisoned Event Rate")
    ax.set_title("Poisoned Event Rate by Scenario")
    ax.tick_params(axis="x", rotation=20)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def save_latency_chart(rows: list[dict], out_path: Path) -> None:
    scenarios = [r["scenario"] for r in rows]
    p50_vals = [r["p50_latency_ms"] for r in rows]
    p95_vals = [r["p95_latency_ms"] for r in rows]

    x = list(range(len(scenarios)))
    width = 0.38

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([i - width / 2 for i in x], p50_vals, width=width, label="p50")
    ax.bar([i + width / 2 for i in x], p95_vals, width=width, label="p95")
    ax.set_xticks(x)
    ax.set_xticklabels(scenarios, rotation=20)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Latency by Scenario (p50 vs p95)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def save_denial_distribution_chart(rows: list[dict], out_path: Path) -> None:
    scenarios = [r["scenario"] for r in rows]
    all_reasons = sorted(
        {
            reason
            for r in rows
            for reason in r["denial_reason_counts"].keys()
        }
    )
    if not all_reasons:
        all_reasons = ["none"]

    # Explicit distinct color palette for each denial reason
    _PALETTE = [
        "#1f77b4",  # blue
        "#ff7f0e",  # orange
        "#2ca02c",  # green
        "#d62728",  # red
        "#9467bd",  # purple
        "#8c564b",  # brown
        "#e377c2",  # pink
        "#7f7f7f",  # grey
        "#bcbd22",  # olive
        "#17becf",  # cyan
    ]
    reason_colors = {
        reason: _PALETTE[i % len(_PALETTE)]
        for i, reason in enumerate(all_reasons)
    }

    values_by_reason: dict[str, list[int]] = {}
    for reason in all_reasons:
        values_by_reason[reason] = [
            int(r["denial_reason_counts"].get(reason, 0)) for r in rows
        ]

    fig, ax = plt.subplots(figsize=(11, 6))
    bottoms = [0] * len(scenarios)
    for reason in all_reasons:
        vals = values_by_reason[reason]
        bars = ax.bar(
            scenarios,
            vals,
            bottom=bottoms,
            label=reason,
            color=reason_colors[reason],
        )
        # Add count labels on each bar segment (skip zero-height segments)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_y() + bar.get_height() / 2,
                    str(v),
                    ha="center",
                    va="center",
                    fontsize=9,
                    fontweight="bold",
                    color="white",
                )
        bottoms = [b + v for b, v in zip(bottoms, vals)]

    ax.set_ylabel("Count")
    ax.set_title("Denial Reason Distribution by Scenario")
    ax.tick_params(axis="x", rotation=20)
    ax.legend(title="Denial Reason", loc="upper right")
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate benchmark figures from scenario_summary.csv"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to benchmark result directory containing scenario_summary.csv",
    )
    args = parser.parse_args()

    in_dir = Path(args.input)
    summary_csv = in_dir / "scenario_summary.csv"
    if not summary_csv.exists():
        raise SystemExit(f"Missing scenario_summary.csv in {in_dir}")

    rows = load_scenario_summary(summary_csv)
    if not rows:
        raise SystemExit("No rows found in scenario_summary.csv")

    figures_dir = in_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    poison_path = figures_dir / "figure_poison_rate_by_scenario.png"
    latency_path = figures_dir / "figure_latency_p50_p95_by_scenario.png"
    denial_path = figures_dir / "figure_denial_reason_distribution.png"

    save_poison_rate_chart(rows, poison_path)
    save_latency_chart(rows, latency_path)
    save_denial_distribution_chart(rows, denial_path)

    print("Figures generated:")
    print(poison_path)
    print(latency_path)
    print(denial_path)


if __name__ == "__main__":
    main()
