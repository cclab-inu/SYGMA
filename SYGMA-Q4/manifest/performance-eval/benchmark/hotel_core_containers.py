#!/usr/bin/env python3
"""Aggregate performance + per-container CPU/memory for the 8 core hotel-reservation
application microservices, split out from supporting containers (consul, jaeger,
mongo, memcached) and reported separately per RPS campaign / mode.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

CAMPAIGNS = (
    ("Hotel 25 RPS", "q3-hotel-c2-rps25-20260818T014310Z"),
    ("Hotel 75 RPS", "q3-hotel-c2-rps75-20260818T014310Z"),
    ("Hotel 100 RPS", "q3-hotel-c2-rps100-20260818T014310Z"),
)

MODE_ORDER = ("default", "tetragon", "sygma", "sygma-all-trace")

CORE_CONTAINERS = (
    "hotel-reserv-frontend",
    "hotel-reserv-geo",
    "hotel-reserv-profile",
    "hotel-reserv-rate",
    "hotel-reserv-recommendation",
    "hotel-reserv-reservation",
    "hotel-reserv-search",
    "hotel-reserv-user",
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def find_trial_dir(campaign_dir: Path, mode: str) -> Path:
    matches = [p for p in (campaign_dir / "raw").iterdir() if p.name.endswith(f"-{mode}")]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one raw dir for mode {mode} in {campaign_dir}, got {matches}")
    return matches[0]


def per_container_stats(metrics_path: Path) -> dict[str, dict[str, float]]:
    samples: dict[str, list[dict[str, float]]] = {c: [] for c in CORE_CONTAINERS}
    for row in read_jsonl(metrics_path):
        container = row.get("container")
        if row.get("scope") != "workload" or container not in samples:
            continue
        samples[container].append(
            {"cpu": float(row["cpu_millicores"]), "mem": float(row["memory_bytes"])}
        )

    stats: dict[str, dict[str, float]] = {}
    for container, points in samples.items():
        if not points:
            stats[container] = {}
            continue
        cpu_vals = sorted(p["cpu"] for p in points)
        mem_vals = sorted(p["mem"] for p in points)
        stats[container] = {
            "cpu_mean": sum(cpu_vals) / len(cpu_vals),
            "cpu_max": cpu_vals[-1],
            "cpu_p95": cpu_vals[max(0, round(0.95 * (len(cpu_vals) - 1)))],
            "mem_mean": sum(mem_vals) / len(mem_vals),
            "mem_max": mem_vals[-1],
            "mem_p95": mem_vals[max(0, round(0.95 * (len(mem_vals) - 1)))],
            "samples": len(points),
        }
    return stats


def main() -> None:
    rows: list[dict[str, Any]] = []
    for label, campaign_name in CAMPAIGNS:
        campaign_dir = RESULTS / campaign_name
        for mode in MODE_ORDER:
            trial_dir = find_trial_dir(campaign_dir, mode)
            trial = read_json(trial_dir / "trial.json")
            performance = trial.get("performance") or {}
            container_stats = per_container_stats(trial_dir / "metrics.jsonl")

            for container in CORE_CONTAINERS:
                cstat = container_stats.get(container) or {}
                rows.append(
                    {
                        "campaign": label,
                        "mode": mode,
                        "container": container,
                        "throughput_ops_per_sec": performance.get("throughput_ops_per_sec"),
                        "latency_avg_ms": performance.get("latency_avg_ms"),
                        "latency_p50_ms": performance.get("latency_p50_ms"),
                        "latency_p99_ms": performance.get("latency_p99_ms"),
                        "error_rate": trial.get("error_rate"),
                        "cpu_millicores_mean": cstat.get("cpu_mean"),
                        "cpu_millicores_p95": cstat.get("cpu_p95"),
                        "cpu_millicores_max": cstat.get("cpu_max"),
                        "memory_bytes_mean": cstat.get("mem_mean"),
                        "memory_bytes_p95": cstat.get("mem_p95"),
                        "memory_bytes_max": cstat.get("mem_max"),
                        "cpu_mem_samples": cstat.get("samples", 0),
                    }
                )

    out_path = HERE / "results" / "hotel-core8-container-metrics.csv"
    fields = list(rows[0].keys())
    with out_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {out_path} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
