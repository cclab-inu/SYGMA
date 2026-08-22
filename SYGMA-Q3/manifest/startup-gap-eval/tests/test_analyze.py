#!/usr/bin/env python3
"""Unit tests for the startup-gap result analyzer."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ANALYZER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "analyze.py"
SPEC = importlib.util.spec_from_file_location("startup_gap_analyze", ANALYZER_PATH)
assert SPEC is not None and SPEC.loader is not None
analyze = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = analyze
SPEC.loader.exec_module(analyze)


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


class ParserTests(unittest.TestCase):
    def test_success_label_cannot_override_errno_or_negative_rc(self) -> None:
        self.assertEqual(
            analyze._attempt_outcome(
                {"outcome": "success", "errno": 22, "rc": -1}
            ),
            "error",
        )
        self.assertEqual(
            analyze._attempt_outcome(
                {"outcome": "success", "errno": 0, "rc": -5}
            ),
            "error",
        )

    def test_probe_counts_successes_before_first_eperm(self) -> None:
        records = [
            {
                "event": "probe_start",
                "realtime_ns": 1_700_000_000_000_000_000,
                "boottime_ns": 100_000_000_000,
                "syscall_nr": 63,
                "syscall_name": "uname",
            },
            {
                "event": "attempt",
                "seq": 0,
                "realtime_ns": 1_700_000_000_000_100_000,
                "boottime_ns": 100_000_100_000,
                "rc": 0,
                "errno": 0,
                "outcome": "success",
            },
            {
                "event": "attempt",
                "seq": 1,
                "realtime_ns": 1_700_000_000_000_200_000,
                "boottime_ns": 100_000_200_000,
                "rc": 0,
                "errno": 0,
                "outcome": "success",
            },
            {
                "event": "attempt",
                "seq": 2,
                "realtime_ns": 1_700_000_000_000_300_000,
                "boottime_ns": 100_000_300_000,
                "rc": -1,
                "errno": 1,
                "outcome": "denied",
            },
            {
                "event": "attempt",
                "seq": 3,
                "realtime_ns": 1_700_000_000_000_400_000,
                "boottime_ns": 100_000_400_000,
                "rc": -1,
                "errno": 1,
                "outcome": "denied",
            },
            {
                "event": "probe_summary",
                "boottime_ns": 100_000_500_000,
                "attempts": 4,
                "successes": 2,
                "denied": 2,
                "errors": 0,
            },
        ]

        facts = analyze.parse_probe_events(records)

        self.assertEqual(facts.attempts, 4)
        self.assertEqual(facts.successful, 2)
        self.assertEqual(facts.eperm, 2)
        self.assertEqual(facts.successful_before_first_eperm, 2)
        self.assertEqual(facts.first_eperm_boottime_ns, 100_000_300_000)
        self.assertFalse(facts.censored)
        self.assertTrue(facts.summary_seen)

    def test_all_success_probe_is_not_censored(self) -> None:
        records = [
            {
                "event": "start",
                "boottime_ns": 10_000,
                "syscall_nr": 63,
                "syscall_name": "uname",
            },
            {
                "event": "attempt",
                "seq": 0,
                "boottime_ns": 10_100,
                "rc": 0,
                "errno": 0,
                "outcome": "success",
            },
            {
                "event": "attempt",
                "seq": 1,
                "boottime_ns": 10_200,
                "rc": 0,
                "errno": 0,
                "outcome": "success",
            },
            {
                "event": "summary",
                "boottime_ns": 10_300,
                "attempts": 2,
                "successes": 2,
                "denied": 0,
                "errors": 0,
            },
        ]

        facts = analyze.parse_probe_events(records)

        self.assertFalse(facts.censored)
        self.assertEqual(facts.successful_before_first_eperm, 2)
        self.assertIsNone(facts.first_eperm_boottime_ns)

    def test_probe_rejects_wrong_target_and_missing_boottime(self) -> None:
        records = [
            {
                "event": "probe_start",
                "realtime_ns": 1_700_000_000_000_000_000,
                "syscall_nr": 110,
                "syscall_name": "getppid",
            },
            {
                "event": "attempt",
                "seq": 0,
                "realtime_ns": 1_700_000_000_000_100_000,
                "rc": -1,
                "errno": 1,
                "outcome": "denied",
            },
            {
                "event": "probe_summary",
                "realtime_ns": 1_700_000_000_000_200_000,
                "attempts": 1,
                "successes": 0,
                "denied": 1,
                "errors": 0,
            },
        ]

        with self.assertRaises(analyze.AnalysisError) as raised:
            analyze.parse_probe_events(records)

        message = str(raised.exception)
        self.assertIn("unexpected_probe_syscall_110", message)
        self.assertIn("unexpected_probe_syscall_name_getppid", message)
        self.assertIn("probe_start_boottime_ns_missing", message)
        self.assertIn("probe_attempt_0_before_boottime_ns_missing", message)

    def test_probe_rejects_sequence_order_and_success_after_denial(self) -> None:
        records = [
            {
                "event": "probe_start",
                "boottime_ns": 1_000,
                "syscall_nr": 63,
                "syscall_name": "uname",
            },
            {
                "event": "attempt",
                "seq": 0,
                "boottime_ns": 1_200,
                "rc": -1,
                "errno": 1,
                "outcome": "denied",
            },
            {
                "event": "attempt",
                "seq": 2,
                "boottime_ns": 1_100,
                "rc": 0,
                "errno": 0,
                "outcome": "success",
            },
            {
                "event": "probe_summary",
                "boottime_ns": 1_300,
                "attempts": 2,
                "successes": 1,
                "denied": 1,
                "errors": 0,
            },
        ]

        with self.assertRaises(analyze.AnalysisError) as raised:
            analyze.parse_probe_events(records)

        message = str(raised.exception)
        self.assertIn("probe_attempt_seq_expected_1_observed_2", message)
        self.assertIn("probe_attempt_1_boottime_not_monotonic", message)
        self.assertIn("success_after_first_denial_count_1", message)

    def test_summary_only_mixed_outcomes_cannot_infer_zero_misses(self) -> None:
        records = [
            {
                "event": "probe_start",
                "boottime_ns": 1_000,
                "syscall_nr": 63,
                "syscall_name": "uname",
            },
            {
                "event": "probe_summary",
                "boottime_ns": 2_000,
                "attempts": 2,
                "successes": 1,
                "denied": 1,
                "errors": 0,
            },
        ]

        with self.assertRaisesRegex(
            analyze.AnalysisError,
            "summary_only_mixed_outcomes_without_ordered_miss_count",
        ):
            analyze.parse_probe_events(records)

    def test_probe_rejects_summary_mismatch_and_error_outcome(self) -> None:
        records = [
            {
                "event": "probe_start",
                "boottime_ns": 1_000,
                "syscall_nr": 63,
                "syscall_name": "uname",
            },
            {
                "event": "attempt",
                "seq": 0,
                "boottime_ns": 1_100,
                "rc": -1,
                "errno": 22,
                "outcome": "error",
            },
            {
                "event": "probe_summary",
                "boottime_ns": 1_200,
                "attempts": 1,
                "successes": 1,
                "denied": 0,
                "errors": 0,
            },
        ]

        with self.assertRaises(analyze.AnalysisError) as raised:
            analyze.parse_probe_events(records)

        message = str(raised.exception)
        self.assertIn("probe_unexpected_error_count_1", message)
        self.assertIn("probe_summary_successes_expected_0_observed_1", message)
        self.assertIn("probe_summary_errors_expected_1_observed_0", message)

    def test_map_insert_interval_and_hook_container_filter(self) -> None:
        insertion = analyze.parse_mapwatch_events(
            [
                {"event": "watch_ready", "boottime_ns": 100},
                {
                    "event": "map_insert",
                    "policy_id": "p1",
                    "cgroup_id": "42",
                    "last_absent_boottime_ns": 1_000_000,
                    "first_present_boottime_ns": 1_125_000,
                    "last_absent_realtime_ns": 2_000_000,
                    "first_present_realtime_ns": 2_125_000,
                },
            ]
        )
        self.assertIsNotNone(insertion)
        assert insertion is not None
        self.assertEqual(insertion.interval_width_ns, 125_000)

        hook = analyze.parse_hook_events(
            [
                {
                    "event": "sygma_direct_policy_ready",
                    "container_id": "containerd://wrong",
                    "boottime_ns": 100,
                },
                {
                    "event": "sygma_direct_policy_ready",
                    "container_id": "containerd://abc123",
                    "boottime_ns": 200,
                    "realtime_ns": 300,
                },
            ],
            "abc123",
        )
        self.assertIsNotNone(hook)
        assert hook is not None
        self.assertEqual(hook.boottime_ns, 200)

        timeline = analyze.parse_hook_timeline(
            [
                {"event": "oci_prestart_enter", "container_id": "abc123", "boottime_ns": 10},
                {
                    "event": "sygma_direct_policy_ready",
                    "container_id": "abc123",
                    "boottime_ns": 20,
                },
                {"event": "oci_prestart_complete", "container_id": "abc123", "boottime_ns": 35},
            ],
            "containerd://abc123",
        )
        self.assertEqual(timeline.prestart_enter_boottime_ns, 10)
        self.assertEqual(timeline.prestart_complete_boottime_ns, 35)
        self.assertIsNotNone(timeline.ready)

    def test_rfc3339_nanoseconds_and_percentiles(self) -> None:
        start = analyze.timestamp_to_ns("2024-01-01T00:00:00.000000001Z")
        end = analyze.timestamp_to_ns("2024-01-01T00:00:00.100000009Z")
        self.assertEqual(end - start, 100_000_008)
        stats = analyze.metric_statistics([0, 1, 2, 3])
        self.assertAlmostEqual(stats["median"], 1.5)
        self.assertAlmostEqual(stats["p95"], 2.85)
        self.assertAlmostEqual(stats["iqr"], 1.5)
        self.assertAlmostEqual(stats["mean"], 1.5)
        self.assertAlmostEqual(stats["sample_stddev"], 1.2909944487358056)
        self.assertEqual(
            (
                stats["bootstrap_median_ci95_lower"],
                stats["bootstrap_median_ci95_upper"],
            ),
            analyze.bootstrap_median_ci95([0, 1, 2, 3]),
        )


class RunAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)
        (self.run_dir / "raw").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _base_trial(self, trial_id: str, backend: str) -> dict:
        trial = {
            "schema_version": 3,
            "trial_id": trial_id,
            "backend": backend,
            "warmup": False,
            "valid": True,
            "invalid_reason": None,
            "api_submit_realtime_ns": 1_704_067_200_000_000_000,
            "api_submit_boottime_ns": 50_000_000_000,
            "api_ack_realtime_ns": 1_704_067_200_010_000_000,
            "api_ack_boottime_ns": 50_010_000_000,
            "pod_creation_time": "2024-01-01T00:00:00.000000000Z",
            "container_started_time": "2024-01-01T00:00:00.100000000Z",
            "container_id": f"container-{trial_id}",
            "pod_uid": f"pod-{trial_id}",
            "pod_name": f"gap-{trial_id}",
            "raw": {
                "probe_jsonl": f"raw/{trial_id}-probe.jsonl",
                "mapwatch_jsonl": f"raw/{trial_id}-map.jsonl",
                "hook_timeline_jsonl": f"raw/{trial_id}-hook.jsonl",
                "sygma_policy_evidence_jsonl": f"raw/{trial_id}-sygma-evidence.jsonl",
                "tetragon_events_jsonl": f"raw/{trial_id}-tetragon-events.jsonl",
            },
        }
        if backend == "tetragon":
            trial.update(
                {
                    "probe_cgroup_id": 42,
                    "tetragon_map_cgroup_id": 42,
                    "tetragon_filter_id": 7,
                }
            )
        return trial

    def _write_probe(
        self,
        trial: dict,
        *,
        start_boot: int,
        outcomes: list[tuple[int, str]],
        cgroup_id: int = 42,
    ) -> None:
        records = [
            {
                "event": "probe_start",
                "boottime_ns": start_boot,
                "syscall_nr": 63,
                "syscall_name": "uname",
            }
        ]
        for seq, (boottime_ns, outcome) in enumerate(outcomes):
            denied = outcome == "denied"
            records.append(
                {
                    "schema_version": 2,
                    "event": "attempt",
                    "seq": seq,
                    "boottime_ns": boottime_ns,
                    "realtime_ns": boottime_ns + 1_000_000,
                    "before_boottime_ns": boottime_ns,
                    "after_boottime_ns": boottime_ns + 1,
                    "before_realtime_ns": boottime_ns + 1_000_000,
                    "after_realtime_ns": boottime_ns + 1_000_001,
                    "rc": -1 if denied else 0,
                    "errno": 1 if denied else 0,
                    "outcome": outcome,
                }
            )
        records.append(
            {
                "event": "probe_summary",
                "boottime_ns": max(time for time, _ in outcomes) + 100,
                "attempts": len(outcomes),
                "successes": sum(outcome == "success" for _, outcome in outcomes),
                "denied": sum(outcome == "denied" for _, outcome in outcomes),
                "errors": 0,
                "cgroup_id": cgroup_id,
                "cgroup_id_errno": 0,
            }
        )
        write_jsonl(self.run_dir / trial["raw"]["probe_jsonl"], records)

    def _valid_sygma_trial(
        self,
        trial_id: str = "m001-sygma",
        *,
        start_boot: int = 10_000,
        ready_boot: int = 9_000,
        outcomes: list[tuple[int, str]] | None = None,
    ) -> dict:
        trial = self._base_trial(trial_id, "sygma")
        self._write_probe(
            trial,
            start_boot=start_boot,
            outcomes=outcomes or [(start_boot + 100, "success")],
        )
        write_jsonl(self.run_dir / trial["raw"]["mapwatch_jsonl"], [])
        container_id = trial["container_id"]
        hook = [
            {
                "schema_version": 2,
                "component": "sygma-oci-hook",
                "mode": "enforcement",
                "hook_role": "policy-and-release",
                "backend": "sygma",
                "trial_id": trial_id,
                "application": "synthetic",
                "pod_uid": trial["pod_uid"],
                "pod_name": trial["pod_name"],
                "container_name": "probe",
                "event": "oci_prestart_enter",
                "container_id": container_id,
                "boottime_ns": ready_boot - 100,
            },
            {
                "event": "sygma_direct_policy_ready",
                "container_id": container_id,
                "boottime_ns": ready_boot,
                "mnt_ns": 100,
                "pid_ns": 101,
                "host_pid": 102,
            },
            {
                "event": "target_release_begin",
                "container_id": container_id,
                "boottime_ns": ready_boot + 10,
            },
            {
                "event": "target_release_signal_sent",
                "container_id": container_id,
                "boottime_ns": ready_boot + 20,
            },
            {
                "schema_version": 2,
                "component": "sygma-oci-hook",
                "mode": "enforcement",
                "hook_role": "policy-and-release",
                "backend": "sygma",
                "trial_id": trial_id,
                "application": "synthetic",
                "pod_uid": trial["pod_uid"],
                "pod_name": trial["pod_name"],
                "container_name": "probe",
                "event": "oci_prestart_complete",
                "container_id": container_id,
                "boottime_ns": ready_boot + 30,
            },
            {
                "event": "sygma_cleanup_complete",
                "container_id": container_id,
                "boottime_ns": start_boot + 1_000,
            },
        ]
        write_jsonl(self.run_dir / trial["raw"]["hook_timeline_jsonl"], hook)
        attempt_count = len(outcomes or [(start_boot + 100, "success")])
        write_jsonl(
            self.run_dir / trial["raw"]["sygma_policy_evidence_jsonl"],
            [
                {
                    "event": "sygma_policy_observed_calls",
                    "syscall_nr": 63,
                    "phase": 1,
                    "count": attempt_count,
                    "other_phase_count": 0,
                    "phase0_count": 0,
                    "mnt_ns": 100,
                    "pid_ns": 101,
                    "host_pid": 102,
                    "tgid": 102,
                }
            ],
        )
        write_jsonl(self.run_dir / trial["raw"]["tetragon_events_jsonl"], [])
        return trial

    def _valid_tetragon_trial(
        self,
        trial_id: str = "m001-tetragon",
        *,
        outcomes: list[tuple[int, str]] | None = None,
        map_cgroup_id: int = 42,
        map_policy_id: int = 7,
        duplicate_insert: bool = False,
    ) -> dict:
        trial = self._base_trial(trial_id, "tetragon")
        self._write_probe(
            trial,
            start_boot=20_000,
            outcomes=outcomes or [(20_100, "success"), (20_400, "success")],
        )
        insertion = {
            "event": "map_insert",
            "policy_id": map_policy_id,
            "cgroup_id": map_cgroup_id,
            "last_absent_boottime_ns": 20_200,
            "first_present_boottime_ns": 20_300,
        }
        map_records = [insertion]
        if duplicate_insert:
            map_records.append(dict(insertion))
        write_jsonl(self.run_dir / trial["raw"]["mapwatch_jsonl"], map_records)
        container_id = trial["container_id"]
        common = {
            "schema_version": 2,
            "component": "sygma-oci-hook",
            "mode": "tetragon-measurement",
            "hook_role": "timestamp-only",
            "backend": "tetragon",
            "trial_id": trial_id,
            "application": "synthetic",
            "pod_uid": trial["pod_uid"],
            "pod_name": trial["pod_name"],
            "container_name": "probe",
            "container_id": container_id,
        }
        write_jsonl(
            self.run_dir / trial["raw"]["hook_timeline_jsonl"],
            [
                {**common, "event": "oci_prestart_enter", "boottime_ns": 19_000},
                {
                    **common,
                    "event": "oci_prestart_complete",
                    "boottime_ns": 19_100,
                },
            ],
        )
        write_jsonl(self.run_dir / trial["raw"]["sygma_policy_evidence_jsonl"], [])
        write_jsonl(self.run_dir / trial["raw"]["tetragon_events_jsonl"], [])
        return trial

    def test_end_to_end_backend_metrics_and_output_files(self) -> None:
        sygma = self._base_trial("s1", "sygma")
        write_jsonl(
            self.run_dir / "raw/s1-probe.jsonl",
            [
                {
                    "event": "probe_start",
                    "boottime_ns": 100_000_000_000,
                    "realtime_ns": 1_704_067_250_000_000_000,
                "syscall_nr": 63,
                "syscall_name": "uname",
                },
                {
                    "schema_version": 2,
                    "event": "attempt",
                    "seq": 0,
                    "boottime_ns": 100_000_100_000,
                    "realtime_ns": 1_704_067_250_000_100_000,
                    "before_boottime_ns": 100_000_100_000,
                    "after_boottime_ns": 100_000_100_001,
                    "before_realtime_ns": 1_704_067_250_000_100_000,
                    "after_realtime_ns": 1_704_067_250_000_100_001,
                    "rc": 0,
                    "errno": 0,
                    "outcome": "success",
                },
                {
                    "event": "probe_summary",
                    "boottime_ns": 100_000_200_000,
                    "attempts": 1,
                    "successes": 1,
                    "denied": 0,
                    "errors": 0,
                    "cgroup_id": 42,
                    "cgroup_id_errno": 0,
                },
            ],
        )
        write_jsonl(self.run_dir / "raw/s1-map.jsonl", [])
        write_jsonl(
            self.run_dir / "raw/s1-hook.jsonl",
            [
                {
                    "schema_version": 2,
                    "component": "sygma-oci-hook",
                    "mode": "enforcement",
                    "hook_role": "policy-and-release",
                    "backend": "sygma",
                    "trial_id": "s1",
                    "application": "synthetic",
                    "pod_uid": sygma["pod_uid"],
                    "pod_name": sygma["pod_name"],
                    "container_name": "probe",
                    "event": "oci_prestart_enter",
                    "container_id": "containerd://container-s1",
                    "boottime_ns": 99_990_000_000,
                    "realtime_ns": 1_704_067_249_990_000_000,
                },
                {
                    "event": "sygma_direct_policy_ready",
                    "container_id": "containerd://container-s1",
                    "boottime_ns": 99_999_500_000,
                    "realtime_ns": 1_704_067_249_999_500_000,
                    "mnt_ns": 100,
                    "pid_ns": 101,
                    "host_pid": 102,
                },
                {
                    "event": "target_release_begin",
                    "container_id": "containerd://container-s1",
                    "boottime_ns": 99_999_600_000,
                },
                {
                    "event": "target_release_signal_sent",
                    "container_id": "containerd://container-s1",
                    "boottime_ns": 99_999_700_000,
                },
                {
                    "schema_version": 2,
                    "component": "sygma-oci-hook",
                    "mode": "enforcement",
                    "hook_role": "policy-and-release",
                    "backend": "sygma",
                    "trial_id": "s1",
                    "application": "synthetic",
                    "pod_uid": sygma["pod_uid"],
                    "pod_name": sygma["pod_name"],
                    "container_name": "probe",
                    "event": "oci_prestart_complete",
                    "container_id": "containerd://container-s1",
                    "boottime_ns": 99_999_800_000,
                    "realtime_ns": 1_704_067_249_999_800_000,
                },
                {
                    "event": "sygma_cleanup_complete",
                    "container_id": "containerd://container-s1",
                    "boottime_ns": 100_001_000_000,
                },
            ],
        )
        write_jsonl(
            self.run_dir / "raw/s1-sygma-evidence.jsonl",
            [
                {
                    "event": "sygma_policy_observed_calls",
                    "syscall_nr": 63,
                    "phase": 1,
                    "count": 1,
                    "other_phase_count": 0,
                    "phase0_count": 0,
                    "mnt_ns": 100,
                    "pid_ns": 101,
                    "tgid": 102,
                }
            ],
        )
        write_jsonl(self.run_dir / "raw/s1-tetragon-events.jsonl", [])

        tetragon = self._base_trial("t1", "tetragon")
        write_jsonl(
            self.run_dir / "raw/t1-probe.jsonl",
            [
                {
                    "event": "start",
                    "boottime_ns": 200_000_000_000,
                "syscall_nr": 63,
                "syscall_name": "uname",
                },
                {"schema_version": 2, "event": "attempt", "seq": 0, "boottime_ns": 200_000_100_000, "before_boottime_ns": 200_000_100_000, "after_boottime_ns": 200_000_100_001, "before_realtime_ns": 300_000_100_000, "after_realtime_ns": 300_000_100_001, "rc": 0, "errno": 0, "outcome": "success"},
                {"schema_version": 2, "event": "attempt", "seq": 1, "boottime_ns": 200_002_500_000, "before_boottime_ns": 200_002_500_000, "after_boottime_ns": 200_002_500_001, "before_realtime_ns": 300_002_500_000, "after_realtime_ns": 300_002_500_001, "rc": 0, "errno": 0, "outcome": "success"},
                {"schema_version": 2, "event": "attempt", "seq": 2, "boottime_ns": 200_003_100_000, "before_boottime_ns": 200_003_100_000, "after_boottime_ns": 200_003_100_001, "before_realtime_ns": 300_003_100_000, "after_realtime_ns": 300_003_100_001, "rc": 0, "errno": 0, "outcome": "success"},
                {
                    "event": "summary",
                    "boottime_ns": 200_003_200_000,
                    "attempts": 3,
                    "successes": 3,
                    "denied": 0,
                    "errors": 0,
                    "cgroup_id": 42,
                    "cgroup_id_errno": 0,
                },
            ],
        )
        write_jsonl(
            self.run_dir / "raw/t1-map.jsonl",
            [
                {
                    "event": "map_insert",
                    "policy_id": 7,
                    "cgroup_id": "42",
                    "last_absent_boottime_ns": 200_002_000_000,
                    "first_present_boottime_ns": 200_003_000_000,
                    "last_absent_realtime_ns": 1_704_067_350_002_000_000,
                    "first_present_realtime_ns": 1_704_067_350_003_000_000,
                }
            ],
        )
        tetragon_common = {
            "schema_version": 2,
            "component": "sygma-oci-hook",
            "mode": "tetragon-measurement",
            "hook_role": "timestamp-only",
            "backend": "tetragon",
            "trial_id": "t1",
            "application": "synthetic",
            "pod_uid": tetragon["pod_uid"],
            "pod_name": tetragon["pod_name"],
            "container_name": "probe",
            "container_id": tetragon["container_id"],
        }
        write_jsonl(
            self.run_dir / "raw/t1-hook.jsonl",
            [
                {
                    **tetragon_common,
                    "event": "oci_prestart_enter",
                    "boottime_ns": 199_990_000_000,
                },
                {
                    **tetragon_common,
                    "event": "oci_prestart_complete",
                    "boottime_ns": 199_990_100_000,
                },
            ],
        )
        write_jsonl(self.run_dir / "raw/t1-sygma-evidence.jsonl", [])
        write_jsonl(self.run_dir / "raw/t1-tetragon-events.jsonl", [])

        write_jsonl(self.run_dir / "trials.jsonl", [sygma, tetragon])
        rows, summary = analyze.analyze_run(self.run_dir)

        by_id = {row["trial_id"]: row for row in rows}
        self.assertEqual(by_id["s1"]["missed_policy_calls"], 0)
        self.assertEqual(by_id["s1"]["controlled_attempts_uncovered_definite"], 0)
        self.assertEqual(by_id["s1"]["controlled_attempts_uncovered_possible"], 0)
        self.assertTrue(by_id["s1"]["sygma_atomicity_order_valid"])
        self.assertEqual(by_id["s1"]["sygma_policy_observed_attempts"], 1)
        self.assertEqual(by_id["s1"]["sygma_controlled_attempts_unobserved"], 0)
        self.assertEqual(by_id["s1"]["sygma_observation_coverage"], 1.0)
        self.assertEqual(
            by_id["s1"]["policy_apply_from_prestart_lower_ns"], 9_500_000
        )
        self.assertEqual(
            by_id["s1"]["sygma_ready_to_prestart_complete_ns"], 300_000
        )
        self.assertEqual(by_id["s1"]["signed_readiness_vs_probe_start_ns"], -500_000)
        self.assertEqual(by_id["s1"]["security_gap_lower_ns"], 0)
        self.assertEqual(by_id["s1"]["security_gap_upper_ns"], 0)
        self.assertEqual(by_id["s1"]["security_gap_ns"], 0)
        self.assertEqual(by_id["s1"]["sygma_prestart_lead_ns"], 500_000)
        self.assertEqual(by_id["s1"]["sygma_hook_cost_ns"], 9_800_000)
        self.assertEqual(by_id["s1"]["startup_latency_ns"], 100_000_000)

        self.assertEqual(by_id["t1"]["missed_policy_calls"], 2)
        self.assertEqual(by_id["t1"]["controlled_attempts_uncovered_definite"], 1)
        self.assertEqual(by_id["t1"]["controlled_attempts_uncovered_possible"], 2)
        self.assertEqual(
            by_id["t1"]["policy_apply_from_prestart_lower_ns"], 12_000_000
        )
        self.assertEqual(
            by_id["t1"]["policy_apply_from_prestart_upper_ns"], 13_000_000
        )
        self.assertEqual(by_id["t1"]["policy_ready_at_prestart"], "unavailable")
        self.assertEqual(
            by_id["t1"]["policy_ready_source"],
            "tetragon_policy_filter_interval",
        )
        self.assertEqual(by_id["t1"]["signed_readiness_vs_probe_start_ns"], 3_000_000)
        self.assertEqual(by_id["t1"]["security_gap_lower_ns"], 2_000_000)
        self.assertEqual(by_id["t1"]["security_gap_upper_ns"], 3_000_000)
        self.assertEqual(by_id["t1"]["security_gap_ns"], 3_000_000)
        self.assertEqual(by_id["t1"]["map_interval_width_ns"], 1_000_000)
        self.assertEqual(
            by_id["t1"]["successful_attempts_definitely_before_map_lower"], 1
        )
        self.assertEqual(
            by_id["t1"]["successful_attempts_ambiguous_in_map_interval"], 1
        )

        self.assertEqual(summary["overall"]["n"], 2)
        self.assertEqual(
            summary["overall"]["metrics"]
            ["controlled_attempts_uncovered_possible"]["median"],
            1.0,
        )
        self.assertEqual(
            summary["by_backend"]["tetragon"]["metrics"]
            ["userland_exposure_lower_ms"]["median"],
            2.0,
        )
        self.assertEqual(
            summary["by_backend"]["sygma"]["metrics"]
            ["prestart_hook_duration_ms"]["median"],
            9.8,
        )
        self.assertEqual(
            summary["by_backend"]["sygma"]["zero_uncovered"]["rate"], 1.0
        )
        self.assertTrue(summary["sygma_atomicity"]["publication_eligible"])
        for filename in ("trials.csv", "summary.json", "summary.csv"):
            self.assertTrue((self.run_dir / filename).is_file(), filename)
        with (self.run_dir / "trials.csv").open(newline="", encoding="utf-8") as handle:
            csv_rows = list(csv.DictReader(handle))
        self.assertEqual(len(csv_rows), 2)
        self.assertEqual(csv_rows[1]["missed_policy_calls"], "2")

    def test_sygma_denial_ready_order_and_hook_cardinality_are_fail_closed(self) -> None:
        denied_trial = self._valid_sygma_trial(
            "m010-sygma",
            outcomes=[(10_100, "success"), (10_200, "denied")],
        )
        denied_row = analyze.analyze_trial(denied_trial, self.run_dir)
        self.assertFalse(denied_row["valid"])
        self.assertIn("observation_mode_requires_all_success", denied_row["invalid_reason"])

        late_trial = self._valid_sygma_trial(
            "m011-sygma",
            start_boot=30_000,
            ready_boot=30_050,
            outcomes=[(30_200, "success")],
        )
        hook_path = self.run_dir / late_trial["raw"]["hook_timeline_jsonl"]
        hook_records = analyze.read_jsonl(hook_path)
        hook_records.append(
            {
                "event": "sygma_direct_policy_ready",
                "container_id": late_trial["container_id"],
                "boottime_ns": 30_051,
            }
        )
        write_jsonl(hook_path, hook_records)

        late_row = analyze.analyze_trial(late_trial, self.run_dir)
        self.assertFalse(late_row["valid"])
        self.assertIn("sygma_direct_policy_ready_count_2", late_row["invalid_reason"])
        self.assertIn("sygma_ready_after_probe_start", late_row["invalid_reason"])
        self.assertLess(late_row["sygma_prestart_lead_ns"], 0)

    def test_sygma_target_evidence_requires_exact_hook_process_identity(self) -> None:
        trial = self._valid_sygma_trial("m012-sygma")
        evidence_path = self.run_dir / trial["raw"]["sygma_policy_evidence_jsonl"]
        evidence = analyze.read_jsonl(evidence_path)
        evidence[0]["pid_ns"] = 999
        write_jsonl(evidence_path, evidence)

        row = analyze.analyze_trial(trial, self.run_dir)
        self.assertFalse(row["valid"])
        self.assertFalse(row["sygma_target_policy_identity_matches_hook"])
        self.assertIn(
            "SYGMA policy-path observation coverage was incomplete",
            row["invalid_reason"],
        )

        trial = self._valid_sygma_trial("m013-sygma")
        evidence_path = self.run_dir / trial["raw"]["sygma_policy_evidence_jsonl"]
        evidence = analyze.read_jsonl(evidence_path)
        evidence[0]["tgid"] = 999
        write_jsonl(evidence_path, evidence)

        row = analyze.analyze_trial(trial, self.run_dir)
        self.assertFalse(row["valid"])
        self.assertFalse(row["sygma_target_policy_identity_matches_hook"])

    def test_sygma_same_process_pre_probe_call_is_reported_not_rejected(self) -> None:
        trial = self._valid_sygma_trial("m013-prefix-sygma")
        evidence_path = self.run_dir / trial["raw"]["sygma_policy_evidence_jsonl"]
        evidence = analyze.read_jsonl(evidence_path)
        evidence[0]["count"] = 2
        write_jsonl(evidence_path, evidence)

        row = analyze.analyze_trial(trial, self.run_dir)
        self.assertTrue(row["valid"], row["invalid_reason"])
        self.assertEqual(row["sygma_target_policy_miss_count"], 2)
        self.assertEqual(row["sygma_policy_observed_attempts"], 1)
        self.assertEqual(row["sygma_non_probe_target_calls_observed"], 1)
        self.assertEqual(row["sygma_controlled_attempts_unobserved"], 0)
        self.assertEqual(row["sygma_observation_coverage"], 1.0)
        self.assertTrue(row["sygma_target_policy_evidence_positive"])

    def test_real_application_lifecycle_is_exported_to_trial_columns(self) -> None:
        trial = self._valid_sygma_trial("m014-sygma")
        trial["application"] = "nginx"
        hook_path = self.run_dir / trial["raw"]["hook_timeline_jsonl"]
        hook_records = analyze.read_jsonl(hook_path)
        for event in hook_records:
            if event.get("event") in {
                "oci_prestart_enter",
                "oci_prestart_complete",
            }:
                event["application"] = "nginx"
        write_jsonl(hook_path, hook_records)
        probe_path = self.run_dir / trial["raw"]["probe_jsonl"]
        records = analyze.read_jsonl(probe_path)
        records[0]["application"] = "nginx"
        records.insert(
            1,
            {
                "event": "app_spawn",
                "application": "nginx",
                "pid": 123,
                "realtime_ns": 1_000_000,
                "boottime_ns": 10_050,
            },
        )
        summary = next(
            record for record in records if record["event"] == "probe_summary"
        )
        summary.update(
            {
                "application": "nginx",
                "app_pid": 123,
                "app_alive_at_summary": True,
                "measurement_interrupted": False,
            }
        )
        records.append(
            {
                "event": "app_exit",
                "application": "nginx",
                "pid": 123,
                "realtime_ns": 2_000_000,
                "boottime_ns": 11_000,
                "phase": "cleanup",
                "exit_code": 0,
                "term_signal": 0,
            }
        )
        write_jsonl(probe_path, records)

        row = analyze.analyze_trial(trial, self.run_dir)
        self.assertTrue(row["valid"], row["invalid_reason"])
        self.assertEqual(row["application"], "nginx")
        self.assertEqual(row["application_pid"], 123)
        self.assertTrue(row["application_alive_at_summary"])
        self.assertEqual(row["application_spawn_boottime_ns"], 10_050)
        self.assertEqual(row["application_exit_phase"], "cleanup")

        summary["app_alive_at_summary"] = False
        write_jsonl(probe_path, records)
        row = analyze.analyze_trial(trial, self.run_dir)
        self.assertFalse(row["valid"])
        self.assertIn(
            "application_not_alive_at_probe_summary", row["invalid_reason"]
        )

    def test_tetragon_requires_exact_ids_and_allows_success_after_map_upper(self) -> None:
        identity_trial = self._valid_tetragon_trial(
            "m020-tetragon",
            map_cgroup_id=99,
            map_policy_id=8,
            duplicate_insert=True,
        )
        identity_row = analyze.analyze_trial(identity_trial, self.run_dir)
        self.assertFalse(identity_row["valid"])
        self.assertIn("tetragon_map_insert_count_2", identity_row["invalid_reason"])

        mismatch_trial = self._valid_tetragon_trial(
            "m021-tetragon",
            map_cgroup_id=99,
            map_policy_id=8,
        )
        mismatch_row = analyze.analyze_trial(mismatch_trial, self.run_dir)
        self.assertFalse(mismatch_row["valid"])
        self.assertIn("tetragon_policy_id_mismatch_trial_7_map_8", mismatch_row["invalid_reason"])
        self.assertIn("tetragon_cgroup_id_mismatch", mismatch_row["invalid_reason"])

        post_upper_trial = self._valid_tetragon_trial(
            "m022-tetragon",
            outcomes=[(20_350, "success"), (20_400, "success")],
        )
        post_upper_row = analyze.analyze_trial(post_upper_trial, self.run_dir)
        self.assertTrue(post_upper_row["valid"])
        self.assertEqual(post_upper_row["missed_policy_calls_definite"], 0)
        self.assertEqual(post_upper_row["missed_policy_calls_possible"], 0)

    def test_tetragon_prestart_readiness_classification_and_call_brackets(self) -> None:
        cases = (
            ("ready", 18_800, 18_900),
            ("ambiguous", 18_950, 19_050),
            ("unavailable", 19_100, 19_200),
        )
        for index, (status, lower, upper) in enumerate(cases):
            trial = self._valid_tetragon_trial(
                f"m03{index}-tetragon",
                outcomes=[(20_100, "success")],
            )
            map_path = self.run_dir / trial["raw"]["mapwatch_jsonl"]
            records = analyze.read_jsonl(map_path)
            records[0]["last_absent_boottime_ns"] = lower
            records[0]["first_present_boottime_ns"] = upper
            write_jsonl(map_path, records)
            row = analyze.analyze_trial(trial, self.run_dir)
            self.assertTrue(row["valid"], row["invalid_reason"])
            self.assertEqual(row["policy_ready_at_prestart"], status)

        boundary = self._valid_tetragon_trial(
            "m034-tetragon",
            outcomes=[(20_199, "success"), (20_200, "success")],
        )
        boundary_row = analyze.analyze_trial(boundary, self.run_dir)
        self.assertTrue(boundary_row["valid"], boundary_row["invalid_reason"])
        self.assertEqual(
            boundary_row["controlled_attempts_uncovered_definite"], 1
        )
        self.assertEqual(
            boundary_row["controlled_attempts_uncovered_possible"], 2
        )

    def test_atomicity_violation_remains_visible_at_campaign_level(self) -> None:
        trial = self._valid_sygma_trial("m040-sygma")
        hook_path = self.run_dir / trial["raw"]["hook_timeline_jsonl"]
        records = analyze.read_jsonl(hook_path)
        release = next(
            record for record in records if record["event"] == "target_release_begin"
        )
        release["boottime_ns"] = 8_900
        write_jsonl(hook_path, records)

        row = analyze.analyze_trial(trial, self.run_dir)
        self.assertFalse(row["valid"])
        self.assertFalse(row["sygma_atomicity_order_valid"])
        audit = analyze.summarize_sygma_atomicity([row])
        self.assertEqual(audit["violation_trials"], 1)
        self.assertFalse(audit["publication_eligible"])

    def test_missing_valid_and_unknown_backend_are_invalid_without_raw(self) -> None:
        missing_valid = self._base_trial("bad-valid", "tetragon")
        del missing_valid["valid"]
        missing_row = analyze.analyze_trial(missing_valid, self.run_dir)
        self.assertFalse(missing_row["valid"])
        self.assertIn("trial.valid is missing or is not boolean", missing_row["invalid_reason"])

        unparseable_valid = self._base_trial("bad-valid-text", "sygma")
        unparseable_valid["valid"] = "true"
        unparseable_row = analyze.analyze_trial(unparseable_valid, self.run_dir)
        self.assertFalse(unparseable_row["valid"])
        self.assertIn(
            "trial.valid is missing or is not boolean",
            unparseable_row["invalid_reason"],
        )

        unknown = self._base_trial("bad-backend", "mystery")
        unknown_row = analyze.analyze_trial(unknown, self.run_dir)
        self.assertFalse(unknown_row["valid"])
        self.assertIn("unknown backend: mystery", unknown_row["invalid_reason"])

    def test_censored_flag_does_not_drop_uncovered_metric(self) -> None:
        rows = [
            {
                "backend": "sygma",
                "warmup": False,
                "valid": True,
                "censored": False,
                "controlled_attempts_uncovered_possible": 0,
                "userland_exposure_upper_ms": 0,
            }
            for _ in range(4)
        ]
        rows.extend(
            [
                {
                    "backend": "sygma",
                    "warmup": True,
                    "valid": True,
                    "censored": False,
                    "controlled_attempts_uncovered_possible": 99,
                    "userland_exposure_upper_ms": 99,
                },
                {
                    "backend": "sygma",
                    "warmup": False,
                    "valid": True,
                    "censored": True,
                    "controlled_attempts_uncovered_possible": 8,
                    "userland_exposure_upper_ms": 8,
                },
                {
                    "backend": "sygma",
                    "warmup": False,
                    "valid": False,
                    "censored": False,
                    "controlled_attempts_uncovered_possible": 100,
                },
            ]
        )

        group = analyze.summarize_trials(rows)["overall"]

        self.assertEqual(group["total"], 6)
        self.assertEqual(group["n"], 5)
        self.assertEqual(group["invalid"], 1)
        self.assertEqual(group["censored"], 1)
        self.assertEqual(group["warmup"], 1)
        metric = group["metrics"]["controlled_attempts_uncovered_possible"]
        self.assertEqual(metric["n"], 5)
        self.assertEqual(metric["median"], 0.0)
        self.assertIsNone(group["zero_uncovered"]["rule_of_three_upper_bound"])

    def test_paired_additional_misses_excludes_bad_pairs(self) -> None:
        def row(
            trial_id: str,
            backend: str,
            definite: int | None,
            possible: int | None = None,
            *,
            valid: bool = True,
            censored: bool = False,
            warmup: bool = False,
        ) -> dict:
            return {
                "trial_id": trial_id,
                "backend": backend,
                "missed_policy_calls": possible if possible is not None else definite,
                "missed_policy_calls_definite": definite,
                "missed_policy_calls_possible": (
                    possible if possible is not None else definite
                ),
                "valid": valid,
                "censored": censored,
                "warmup": warmup,
            }

        rows = [
            row("m001-sygma", "sygma", 0),
            row("m001-tetragon", "tetragon", 3, 4),
            row("m002-sygma", "sygma", 1),
            row("m002-tetragon", "tetragon", 5, valid=False),
            row("m003-tetragon", "tetragon", 3),
            row("m004-sygma", "sygma", 0),
            row("m004-tetragon", "tetragon", 2),
            row("m004-tetragon", "tetragon", 2),
            row("w001-sygma", "sygma", 99, warmup=True),
            row("w001-tetragon", "tetragon", 100, warmup=True),
        ]

        summary = analyze.summarize_trials(rows)
        paired = summary["paired_additional_missed_policy_calls"]

        self.assertEqual(paired["candidate_pairs"], 4)
        self.assertEqual(paired["n"], 1)
        self.assertEqual(paired["excluded"], 3)
        self.assertEqual(paired["excluded_reasons"]["missing_arm"], 1)
        self.assertEqual(paired["excluded_reasons"]["invalid_arm"], 1)
        self.assertEqual(paired["excluded_reasons"]["duplicate_arm"], 1)
        self.assertEqual(paired["warmup_pairs"], 1)
        self.assertEqual(paired["definite_values"], [3])
        self.assertEqual(paired["possible_values"], [4])
        self.assertEqual(paired["values"], [4])
        self.assertEqual(paired["statistics"]["mean"], 4.0)
        self.assertEqual(paired["statistics"]["bootstrap_median_ci95_lower"], 4.0)

        paired_csv = [
            item
            for item in analyze._summary_csv_rows(summary)
            if item["scope"] == "paired"
        ]
        self.assertEqual(len(paired_csv), 2)
        self.assertEqual(
            {item["metric"] for item in paired_csv},
            {
                "additional_uncovered_attempts_definite",
                "additional_uncovered_attempts_possible",
            },
        )
        self.assertEqual(paired_csv[0]["excluded"], 3)

    def test_application_profiles_are_summarized_and_paired_independently(self) -> None:
        rows = []
        for application, tetragon_misses in (("nginx", 4), ("mysql", 9)):
            rows.extend(
                [
                    {
                        "trial_id": "m001-sygma",
                        "backend": "sygma",
                        "application": application,
                        "valid": True,
                        "warmup": False,
                        "censored": False,
                        "missed_policy_calls": 0,
                        "missed_policy_calls_definite": 0,
                        "missed_policy_calls_possible": 0,
                    },
                    {
                        "trial_id": "m001-tetragon",
                        "backend": "tetragon",
                        "application": application,
                        "valid": True,
                        "warmup": False,
                        "censored": False,
                        "missed_policy_calls": tetragon_misses,
                        "missed_policy_calls_definite": tetragon_misses,
                        "missed_policy_calls_possible": tetragon_misses,
                    },
                ]
            )

        summary = analyze.summarize_trials(rows)
        self.assertEqual(
            set(summary["by_application"]), {"mysql", "nginx"}
        )
        self.assertEqual(
            summary["paired_additional_missed_policy_calls"]["possible_values"],
            [9, 4],
        )
        by_application = summary[
            "paired_additional_missed_policy_calls_by_application"
        ]
        self.assertEqual(by_application["nginx"]["possible_values"], [4])
        self.assertEqual(by_application["mysql"]["possible_values"], [9])

        csv_rows = analyze._summary_csv_rows(summary)
        profile_rows = [
            row for row in csv_rows if row["scope"] == "paired_application"
        ]
        self.assertEqual(len(profile_rows), 4)
        self.assertEqual(
            {row["application"] for row in profile_rows}, {"nginx", "mysql"}
        )

    def test_runner_invalid_trial_does_not_require_raw_files(self) -> None:
        trial = {
            "trial_id": "bad-1",
            "backend": "tetragon",
            "valid": False,
            "invalid_reason": "pod did not start",
            "warmup": False,
            "raw": {
                "probe_jsonl": "raw/does-not-exist.jsonl",
                "mapwatch_jsonl": "raw/also-missing.jsonl",
                "hook_timeline_jsonl": "raw/missing.jsonl",
            },
        }

        row = analyze.analyze_trial(trial, self.run_dir)

        self.assertFalse(row["valid"])
        self.assertEqual(row["invalid_reason"], "pod did not start")
        self.assertIsNone(row["missed_policy_calls"])

    def test_incomplete_application_atomicity_is_unevaluable_not_violation(self) -> None:
        trial = {
            "trial_id": "m071-sygma",
            "backend": "sygma",
            "application": "nginx",
            "valid": False,
            "invalid_reason": "pod_phase_Failed",
            "warmup": False,
            "application_syscall_snapshot": None,
            "raw": {},
        }

        row = analyze.analyze_application_trial(trial, self.run_dir)
        self.assertIsNone(row["sygma_atomicity_order_valid"])
        summary = analyze.summarize_application_trials([row])
        self.assertEqual(summary["sygma_atomicity"]["proven_trials"], 0)
        self.assertEqual(summary["sygma_atomicity"]["violation_trials"], 0)
        self.assertEqual(summary["sygma_atomicity"]["unevaluable_trials"], 1)
        self.assertFalse(summary["sygma_atomicity"]["publication_eligible"])


if __name__ == "__main__":
    unittest.main()
