#!/usr/bin/env python3
"""Aggregate valid SYGMA benchmark trials into machine-readable tables."""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import statistics
import sys
from typing import Any, Iterable, Mapping


PERFORMANCE_FIELDS = (
    "throughput_ops_per_sec",
    "latency_avg_ms",
    "latency_p50_ms",
    "latency_p95_ms",
    "latency_p99_ms",
    "latency_max_ms",
    "error_rate",
)
RESOURCE_FIELDS = (
    "cpu_millicores_mean",
    "cpu_millicores_p95",
    "cpu_millicores_max",
    "memory_bytes_mean",
    "memory_bytes_p95",
    "memory_bytes_max",
)
ROUTE_NAMES = ("conventional_sigkill", "lsm_bpf", "ptrace_notify")


def read_trials(path: Path) -> list[dict[str, Any]]:
    trials_path = path / "trials.jsonl"
    if not trials_path.is_file():
        raise ValueError(f"missing {trials_path}")
    trials: list[dict[str, Any]] = []
    for line_number, line in enumerate(trials_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{trials_path}:{line_number}: trial is not an object")
        trials.append(value)
    return trials


def numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def flatten_trial(trial: Mapping[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "trial": trial.get("trial"),
        "sequence": trial.get("sequence"),
        "workload": trial.get("workload"),
        "mode": trial.get("mode"),
        "repetition": trial.get("repetition"),
        "valid": bool(trial.get("valid")),
        "invalid_reason": trial.get("invalid_reason", ""),
    }
    performance = trial.get("performance") or {}
    for field in PERFORMANCE_FIELDS:
        if field == "error_rate":
            row[field] = trial.get(field)
        else:
            row[field] = performance.get(field)

    scopes = (trial.get("resources") or {}).get("scopes") or {}
    for scope in ("workload", "framework", "node"):
        values = scopes.get(scope) or {}
        for field in RESOURCE_FIELDS:
            # An inactive framework is a measured zero, not missing data.
            default = 0.0 if scope == "framework" else None
            row[f"{scope}_{field}"] = values.get(field, default)

    routes = trial.get("routes") or {}
    route_rates = routes.get("per_second") or {}
    for name in ROUTE_NAMES:
        row[f"route_{name}_count"] = routes.get(name)
        row[f"route_{name}_per_second"] = route_rates.get(name)
    row["route_total_count"] = routes.get("total")
    return row


# Two-sided 95% Student-t critical values for df 1..30.
T95 = (
    0.0, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306,
    2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110,
    2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056,
    2.052, 2.048, 2.045, 2.042,
)


def summarize(values: Iterable[float]) -> dict[str, float | int]:
    data = list(values)
    if not data:
        raise ValueError("cannot summarize an empty metric")
    mean = statistics.mean(data)
    stdev = statistics.stdev(data) if len(data) > 1 else 0.0
    df = len(data) - 1
    critical = T95[df] if 0 < df < len(T95) else 1.96
    half_width = critical * stdev / math.sqrt(len(data)) if len(data) > 1 else 0.0
    return {
        "n": len(data),
        "mean": mean,
        "median": statistics.median(data),
        "stdev": stdev,
        "ci95_low": mean - half_width,
        "ci95_high": mean + half_width,
    }


def aggregate(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for row in rows:
        if not row.get("valid"):
            continue
        key = (str(row["workload"]), str(row["mode"]))
        groups.setdefault(key, []).append(row)

    output: list[dict[str, Any]] = []
    identity = {"trial", "sequence", "workload", "mode", "repetition", "valid", "invalid_reason"}
    for (workload, mode), members in sorted(groups.items()):
        metrics: dict[str, Any] = {}
        names = sorted(set().union(*(member.keys() for member in members)).difference(identity))
        for name in names:
            values = [value for member in members if (value := numeric(member.get(name))) is not None]
            if values:
                metrics[name] = summarize(values)
        output.append(
            {
                "workload": workload,
                "mode": mode,
                "valid_trials": len(members),
                "metrics": metrics,
            }
        )
    return output


def image_consistency(trials: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    observed: dict[str, set[str]] = {}
    for trial in trials:
        if not trial.get("valid"):
            continue
        containers = (trial.get("pod_evidence") or {}).get("containers") or []
        for container in containers:
            image = str(container.get("image") or "")
            image_id = str(container.get("image_id") or "")
            if image and image_id:
                observed.setdefault(image, set()).add(image_id)
    return {image: sorted(image_ids) for image, image_ids in sorted(observed.items())}


def write_csv(path: Path, rows: list[Mapping[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    args = parser.parse_args()
    campaign = args.campaign.resolve()

    trials = read_trials(campaign)
    rows = [flatten_trial(trial) for trial in trials]
    valid = [row for row in rows if row["valid"]]
    invalid = [row for row in rows if not row["valid"]]
    if not valid:
        raise ValueError("campaign contains no valid trials")

    trial_fields = list(rows[0])
    for row in rows[1:]:
        trial_fields.extend(name for name in row if name not in trial_fields)
    write_csv(campaign / "trial-metrics.csv", rows, trial_fields)

    summaries = aggregate(rows)
    images = image_consistency(trials)
    inconsistent_images = {image: ids for image, ids in images.items() if len(ids) != 1}
    if inconsistent_images:
        raise ValueError(
            "one image reference resolved to multiple image IDs: "
            + json.dumps(inconsistent_images, sort_keys=True)
        )
    summary_rows: list[dict[str, Any]] = []
    for group in summaries:
        base = {
            "workload": group["workload"],
            "mode": group["mode"],
            "valid_trials": group["valid_trials"],
        }
        for metric, stats in group["metrics"].items():
            for statistic, value in stats.items():
                base[f"{metric}_{statistic}"] = value
        summary_rows.append(base)
    summary_fields = ["workload", "mode", "valid_trials"]
    for row in summary_rows:
        summary_fields.extend(name for name in row if name not in summary_fields)
    write_csv(campaign / "summary.csv", summary_rows, summary_fields)

    payload = {
        "schema_version": 1,
        "campaign": str(campaign),
        "trial_count": len(rows),
        "valid_trial_count": len(valid),
        "invalid_trial_count": len(invalid),
        "resolved_image_ids": images,
        "groups": summaries,
        "invalid_trials": [
            {"trial": row["trial"], "invalid_reason": row["invalid_reason"]}
            for row in invalid
        ],
    }
    (campaign / "summary.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"analyzed {len(valid)}/{len(rows)} valid trials; "
        f"wrote {campaign / 'summary.csv'} and {campaign / 'summary.json'}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
