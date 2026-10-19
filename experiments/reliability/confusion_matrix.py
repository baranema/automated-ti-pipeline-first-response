#!/usr/bin/env python3
# Turn a per-event JSONL (scenario, label, predicted) into matrix.json.

import json
import sys
from collections import defaultdict
from pathlib import Path


def verdict_for(label, predicted):
    positive = predicted == "trigger"
    if label == "malicious":
        return "TP" if positive else "FN"
    return "FP" if positive else "TN"


def metrics_for(counts):
    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    accuracy = (tp + tn) / total if total else None
    return {
        **counts,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "f1": round(f1, 3) if f1 is not None else None,
        "accuracy": round(accuracy, 3) if accuracy is not None else None,
    }


def empty_counts():
    return {"TP": 0, "FP": 0, "FN": 0, "TN": 0}


def main():
    events_file = Path(sys.argv[1])
    overall = empty_counts()
    per_scenario = defaultdict(empty_counts)
    for raw in events_file.read_text().splitlines():
        if not raw.strip():
            continue
        event = json.loads(raw)
        verdict = verdict_for(event["label"], event["predicted"])
        overall[verdict] += 1
        per_scenario[event["scenario"]][verdict] += 1

    matrix = {
        "overall": metrics_for(overall),
        "per_scenario": {name: metrics_for(counts) for name, counts in per_scenario.items()},
    }
    out = events_file.with_name("matrix.json")
    out.write_text(json.dumps(matrix, indent=2))
    print(json.dumps(matrix["overall"], indent=2))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
