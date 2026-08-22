#!/usr/bin/env python3
"""Unit tests for strict deletion and checkpoint-resume behavior."""

import csv
import json
import stat
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import run as runner


def identity(number):
    return {
        "pod_uid": f"pod-{number}",
        "container_id": f"container-{number}",
        "node_name": "node",
        "restart_count": 0,
    }


def pod(number, deleting=False):
    metadata = {"uid": f"pod-{number}"}
    if deleting:
        metadata["deletionTimestamp"] = "2026-07-30T00:00:00Z"
    return {
        "metadata": metadata,
        "spec": {"nodeName": "node"},
        "status": {
            "containerStatuses": [
                {
                    "name": "nginx",
                    "containerID": f"containerd://container-{number}",
                    "restartCount": 0,
                    "state": {"running": {"startedAt": "now"}},
                }
            ]
        },
    }


def observation(number, previous, blocked_id=101, heartbeat_id=102):
    current = identity(number)
    namespace = {
        "container_id": current["container_id"],
        "host_pid": 1000 + number,
        "mntns": 2000 + number,
        "pidns": 3000 + number,
        "source": "test",
    }
    return {
        "ready": True,
        "ready_error": "ready",
        "identity": current,
        "previous_identity": previous,
        "namespace": namespace,
        "readiness": {
            "container_info": "default/nginx/nginx",
            "host_pid": namespace["host_pid"],
            "namespace": {
                "mntns": namespace["mntns"],
                "pidns": namespace["pidns"],
            },
            "phase0_graph_rows": 7,
            "phase0_start_row": True,
            "pid_mount_value": 99,
            "execution": {"execution_time": 1, "comm": "nginx"},
            "root_process_state": {"image_id": 1},
            "maps": {
                "syscall_graph_map": {"id": 201},
                "process_state_map": {"id": 202},
                "tid_to_namespace": {"id": 203},
                "container_info_map": {"id": 204},
                "pid_mount_ns_map": {"id": 205},
                "execution_time_map": {"id": 206},
            },
        },
        "heartbeat": {
            "before": 0,
            "after": 10,
            "delta": 10,
            "map_id": heartbeat_id,
        },
        "blocked_map_id": blocked_id,
        "violations": [],
        "observed_transitions": [{"from": 500, "to": 0, "count": 10}],
        "observed_event_count": 10,
    }


def write_checkpoint(root, valid_count=2, terminal_invalid=True):
    preflight_identity = identity(0)
    preflight_observation = observation(0, identity(-1))
    (root / "nginx-preflight.json").write_text(
        json.dumps(
            {
                "application": "nginx",
                "valid": True,
                "identity": preflight_identity,
                "instrumentation": preflight_observation["readiness"],
                "heartbeat": preflight_observation["heartbeat"],
            }
        )
        + "\n"
    )
    rows = []
    details = []
    previous = preflight_identity
    for iteration in range(1, valid_count + 1):
        value = observation(iteration, previous)
        rows.append(runner.valid_csv_row(iteration, value))
        details.append(runner.detail_record(iteration, value))
        previous = value["identity"]
    if terminal_invalid:
        error = runner.CommandError("delete client failed")
        rows.append(runner.invalid_csv_row(valid_count + 1, error))
        details.append(
            {
                "iteration": valid_count + 1,
                "valid": False,
                "failure_stage": "delete_previous_pod",
                "pod_created": False,
                "created_pod_uid": None,
                "invalid_reason": str(error),
            }
        )

    csv_path = root / "nginx-iterations.csv"
    with csv_path.open("w", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=runner.CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    detail_path = root / "nginx-violations.jsonl"
    with detail_path.open("w") as target:
        for detail in details:
            target.write(json.dumps(detail) + "\n")
    return csv_path, detail_path


class DeletePodTests(unittest.TestCase):
    def test_nonzero_delete_is_success_when_get_observes_not_found(self):
        failed_client = SimpleNamespace(
            returncode=1, stdout='pod "nginx" deleted\n', stderr="unexpected EOF"
        )
        with mock.patch.object(
            runner, "get_pod", side_effect=[pod(1), None]
        ), mock.patch.object(
            runner, "delete_request", return_value=failed_client
        ) as delete:
            runner.delete_pod(
                "default", "nginx", 1, expected_identity=identity(1)
            )
        delete.assert_called_once_with("default", "nginx")

    def test_different_uid_is_never_deleted(self):
        accepted = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            runner, "get_pod", side_effect=[pod(1), pod(2)]
        ), mock.patch.object(
            runner, "delete_request", return_value=accepted
        ), self.assertRaises(runner.InvalidMeasurement):
            runner.delete_pod(
                "default", "nginx", 1, expected_identity=identity(1)
            )

    def test_terminating_same_uid_is_polled_to_not_found(self):
        accepted = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            runner, "get_pod", side_effect=[pod(1), pod(1, deleting=True), None]
        ), mock.patch.object(
            runner, "delete_request", return_value=accepted
        ), mock.patch.object(runner.time, "sleep"):
            runner.delete_pod(
                "default", "nginx", 1, expected_identity=identity(1)
            )

    def test_permanent_delete_error_preserves_stderr(self):
        forbidden = SimpleNamespace(
            returncode=1, stdout="", stderr="Error from server (Forbidden): denied"
        )
        with mock.patch.object(
            runner, "get_pod", side_effect=[pod(1), pod(1)]
        ), mock.patch.object(
            runner, "delete_request", return_value=forbidden
        ), self.assertRaisesRegex(runner.CommandError, "Forbidden"):
            runner.delete_pod(
                "default", "nginx", 1, expected_identity=identity(1)
            )

    def test_already_terminating_pod_does_not_require_running_status(self):
        terminating = {
            "metadata": {
                "uid": "pod-1",
                "deletionTimestamp": "2026-07-30T00:00:00Z",
            },
            "status": {},
        }
        with mock.patch.object(
            runner, "get_pod", side_effect=[terminating, None]
        ), mock.patch.object(runner, "delete_request") as delete:
            runner.delete_pod(
                "default", "nginx", 1, expected_identity=identity(1)
            )
        delete.assert_not_called()

    def test_same_uid_container_change_is_rejected_before_not_found(self):
        changed = pod(1)
        changed["status"]["containerStatuses"][0][
            "containerID"
        ] = "containerd://different-container"
        accepted = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            runner, "get_pod", side_effect=[pod(1), changed]
        ), mock.patch.object(
            runner, "delete_request", return_value=accepted
        ), self.assertRaisesRegex(runner.InvalidMeasurement, "container changed"):
            runner.delete_pod(
                "default", "nginx", 1, expected_identity=identity(1)
            )

    def test_command_timeout_is_an_operational_error(self):
        expired = runner.subprocess.TimeoutExpired(("kubectl", "get"), 1)
        with mock.patch.object(
            runner.subprocess, "run", side_effect=expired
        ), self.assertRaisesRegex(runner.CommandError, "timed out"):
            runner.command("kubectl", "get", timeout=1)


class ResumeTests(unittest.TestCase):
    @staticmethod
    def args(root, iterations=3, namespace="default"):
        return SimpleNamespace(
            output=root,
            resume=True,
            iterations=iterations,
            namespace=namespace,
            instrumentation_timeout=1,
            delete_timeout=1,
        )

    def test_checkpoint_accepts_valid_prefix_and_one_terminal_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path, detail_path = write_checkpoint(root)
            state = runner.validate_checkpoint(
                "nginx",
                csv_path,
                detail_path,
                root / "nginx-preflight.json",
                3,
            )
            self.assertEqual(state["valid_count"], 2)
            self.assertIsNotNone(state["terminal_invalid"])

    def test_prepare_resume_archives_invalid_and_keeps_valid_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path, detail_path = write_checkpoint(root)
            args = self.args(root)
            counters = {
                "blocked": {
                    "id": 101,
                    "entry_count": 0,
                    "max_entries": 10,
                    "entries": {},
                },
                "heartbeat": {
                    "id": 102,
                    "entry_count": 0,
                    "max_entries": 10,
                    "entries": {},
                },
            }
            with mock.patch.object(
                runner,
                "counter_snapshot",
                side_effect=lambda kind: counters[kind],
            ), mock.patch.object(
                runner,
                "validate_live_map_ids",
                return_value={},
            ), mock.patch.object(
                runner,
                "validate_resume_policy",
                return_value={"image_id": 1},
            ), mock.patch.object(
                runner, "get_pod", return_value=None
            ), mock.patch.object(
                runner, "wait_namespace_cleanup"
            ):
                state = runner.prepare_resume(
                    "nginx",
                    "nginx-sygma-config",
                    root / "config.yaml",
                    root / "workload.yaml",
                    args,
                )

            self.assertEqual(state["valid_count"], 2)
            self.assertTrue(state["skip_first_delete"])
            with csv_path.open(newline="") as source:
                self.assertEqual(len(list(csv.DictReader(source))), 2)
            self.assertEqual(len(runner.read_jsonl(detail_path)), 2)
            self.assertEqual(
                len(list((root / "operational-errors").iterdir())), 1
            )
            self.assertTrue((root / "nginx-operational-errors.jsonl").exists())
            self.assertTrue((root / "nginx-resume.jsonl").exists())

    def test_resume_rejects_namespace_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_checkpoint(root)
            with self.assertRaisesRegex(
                runner.InvalidMeasurement, "checkpoint namespace"
            ):
                runner.prepare_resume(
                    "nginx",
                    "nginx-sygma-config",
                    root / "config.yaml",
                    root / "workload.yaml",
                    self.args(root, namespace="other"),
                )

    def test_resume_rejects_target_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_checkpoint(root)
            (root / "nginx-summary.json").write_text(
                json.dumps(
                    {
                        "application": "nginx",
                        "expected_iterations": 1000,
                    }
                )
                + "\n"
            )
            with self.assertRaisesRegex(
                runner.InvalidMeasurement, "checkpoint target was 1000"
            ):
                runner.prepare_resume(
                    "nginx",
                    "nginx-sygma-config",
                    root / "config.yaml",
                    root / "workload.yaml",
                    self.args(root),
                )

    def test_post_create_invalid_is_not_auto_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _csv_path, detail_path = write_checkpoint(root)
            records = runner.read_jsonl(detail_path)
            records[-1]["failure_stage"] = "observe_deployment"
            records[-1]["pod_created"] = True
            records[-1]["created_pod_uid"] = "unknown-sample"
            with detail_path.open("w") as target:
                for record in records:
                    target.write(json.dumps(record) + "\n")
            with self.assertRaisesRegex(
                runner.InvalidMeasurement, "cannot be automatically retried"
            ):
                runner.prepare_resume(
                    "nginx",
                    "nginx-sygma-config",
                    root / "config.yaml",
                    root / "workload.yaml",
                    self.args(root),
                )

    def test_live_map_replacement_is_rejected(self):
        previous = observation(2, identity(1))
        expected = previous["readiness"]["maps"]
        expected_ids = {
            name: value["id"] for name, value in expected.items()
        }
        changed = {
            "maps": {
                name: {"id": value + (1 if name == "syscall_graph_map" else 0)}
                for name, value in expected_ids.items()
            }
        }
        with mock.patch.object(
            runner, "snapshot", return_value=changed
        ), self.assertRaisesRegex(runner.InvalidMeasurement, "replacement"):
            runner.validate_live_map_ids(previous, expected_ids)

    def test_completed_checkpoint_cleans_only_last_exact_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_checkpoint(root, valid_count=2, terminal_invalid=False)
            args = self.args(root, iterations=2)
            with mock.patch.object(
                runner, "get_pod", return_value=pod(2)
            ), mock.patch.object(
                runner, "delete_pod"
            ) as delete, mock.patch.object(
                runner, "wait_namespace_cleanup"
            ) as cleanup:
                state = runner.prepare_resume(
                    "nginx",
                    "nginx-sygma-config",
                    root / "config.yaml",
                    root / "workload.yaml",
                    args,
                )
            self.assertTrue(state["completed"])
            self.assertEqual(
                delete.call_args.kwargs["expected_identity"], identity(2)
            )
            cleanup.assert_called_once()

    def test_jsonl_ahead_by_one_repairs_derived_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path, detail_path = write_checkpoint(
                root, valid_count=2, terminal_invalid=False
            )
            with csv_path.open(newline="") as source:
                rows = list(csv.DictReader(source))
            runner.atomic_write_checkpoint(
                csv_path,
                detail_path,
                rows[:1],
                runner.read_jsonl(detail_path),
            )
            runner.repair_derived_csv_tail("nginx", root)
            with csv_path.open(newline="") as source:
                repaired = list(csv.DictReader(source))
            self.assertEqual(len(repaired), 2)
            self.assertEqual(repaired[-1]["iteration"], "2")

    def test_atomic_checkpoint_rewrite_preserves_file_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path, detail_path = write_checkpoint(
                root, valid_count=1, terminal_invalid=False
            )
            csv_path.chmod(0o640)
            detail_path.chmod(0o604)
            with csv_path.open(newline="") as source:
                rows = list(csv.DictReader(source))
            records = runner.read_jsonl(detail_path)
            runner.atomic_write_checkpoint(
                csv_path, detail_path, rows, records
            )
            self.assertEqual(stat.S_IMODE(csv_path.stat().st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(detail_path.stat().st_mode), 0o604)


class LockTests(unittest.TestCase):
    def test_output_lock_rejects_second_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = runner.acquire_output_lock(root)
            try:
                with self.assertRaisesRegex(
                    runner.InvalidMeasurement, "another runner holds"
                ):
                    runner.acquire_output_lock(root)
            finally:
                first.close()


if __name__ == "__main__":
    unittest.main()
