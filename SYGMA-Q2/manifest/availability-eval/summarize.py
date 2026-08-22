#!/usr/bin/env python3
"""Summarize only valid initialization-policy evaluation iterations."""

import argparse
from collections import Counter
import csv
import json
from pathlib import Path


def integer(row, field):
    value = row.get(field, "")
    if value == "":
        raise ValueError(f"iteration {row.get('iteration', '?')} has no {field}")
    return int(value)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("--expected-iterations", type=int)
    args = parser.parse_args()
    if args.expected_iterations is not None and args.expected_iterations <= 0:
        parser.error("--expected-iterations must be positive")
    return args


def main():
    args = parse_args()
    with args.csv.open(newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        rows = list(reader)
        fields = set(reader.fieldnames or [])

    required = {
        "iteration",
        "valid",
        "invalid_reason",
        "ready",
        "init_violation",
        "init_events",
        "identity_replaced",
        "heartbeat_delta",
    }
    missing = required.difference(fields)
    if missing:
        raise SystemExit(
            f"{args.csv}: not a strict-runner CSV; missing fields {sorted(missing)}"
        )

    valid_rows = [row for row in rows if integer(row, "valid") == 1]
    invalid_rows = [row for row in rows if integer(row, "valid") == 0]
    unexpected = [
        row for row in rows if integer(row, "valid") not in (0, 1)
    ]
    if unexpected:
        raise SystemExit(f"{args.csv}: valid must be either 0 or 1")

    valid_count = len(valid_rows)
    ready_failures = sum(1 for row in valid_rows if integer(row, "ready") == 0)
    init_failures = sum(integer(row, "init_violation") for row in valid_rows)
    expected = args.expected_iterations
    attempted = len(rows)
    invalid_reasons = Counter(
        row["invalid_reason"] or "unspecified" for row in invalid_rows
    )

    summary = {
        "application": args.csv.name.removesuffix("-iterations.csv"),
        "expected_iterations": expected,
        "attempted_iterations": attempted,
        "valid_iterations": valid_count,
        "invalid_iterations": len(invalid_rows),
        "unattempted_iterations": (
            max(expected - attempted, 0) if expected is not None else None
        ),
        "experiment_complete": (
            attempted == expected and not invalid_rows
            if expected is not None
            else not invalid_rows
        ),
        "invalid_reasons": dict(sorted(invalid_reasons.items())),
        "actual_ready_failures": ready_failures,
        "actual_ready_failure_rate_among_valid": (
            ready_failures / valid_count if valid_count else None
        ),
        "counterfactual_init_policy_failures": init_failures,
        "counterfactual_init_policy_failure_rate_among_valid": (
            init_failures / valid_count if valid_count else None
        ),
        "total_init_violation_events": sum(
            integer(row, "init_events") for row in valid_rows
        ),
        "identity_replacements_verified": sum(
            integer(row, "identity_replaced") for row in valid_rows
        ),
        "total_phase0_transition_checks": sum(
            integer(row, "heartbeat_delta") for row in valid_rows
        ),
    }
    output = args.csv.with_name(
        args.csv.name.replace("-iterations.csv", "-summary.json")
    )
    output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
