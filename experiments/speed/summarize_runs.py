#!/usr/bin/env python3
# Aggregate per-run JSON files into a per-scenario summary.json with percentiles.

import glob
import json
import statistics
import sys
from pathlib import Path

METRICS = ["total_s", "detection_s", "response_s", "ansible_s", "integrator_s"]


def percentile(values, rank):
    ordered = sorted(values)
    position = (len(ordered) - 1) * rank / 100
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (position - low), 3)


def summarize_metric(values):
    return {
        "mean": round(statistics.mean(values), 3),
        "std": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0,
        "min": round(min(values), 3),
        "max": round(max(values), 3),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
    }


def summarize_scenario(scenario_dir):
    runs = [json.loads(Path(f).read_text()) for f in glob.glob(f"{scenario_dir}/run_*.json")]
    if not runs:
        return None
    summary = {"scenario": scenario_dir.name, "n": len(runs)}
    for metric in METRICS:
        values = [run[metric] for run in runs if run.get(metric) is not None]
        if values:
            summary[metric] = summarize_metric(values)
    return summary


def main():
    base = Path(sys.argv[1])
    for scenario in sys.argv[2:]:
        summary = summarize_scenario(base / scenario)
        if summary is None:
            continue
        (base / scenario / "summary.json").write_text(json.dumps(summary, indent=2))
        print(f"  wrote {base / scenario}/summary.json (n={summary['n']})")


if __name__ == "__main__":
    main()
