#!/usr/bin/env python3
"""Unit tests for experiment-runner schemas and validity gates."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


RUNNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "run_experiment.py"
SPEC = importlib.util.spec_from_file_location("startup_gap_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def inspected_map_stdout(path: str, *, typed: bool = False) -> str:
    contract = {"map_type": 1, "key_size": 4, "value_size": 4}
    if path in runner.SYGMA_COMMON_MAP_ABI:
        contract = runner.SYGMA_COMMON_MAP_ABI[path]
    if path.endswith("/process_state_map"):
        contract = (
            runner.SYGMA_TYPED_MAP_ABI[path]
            if typed
            else runner.SYGMA_LEGACY_PROCESS_STATE_ABI
        )
    if typed and path in runner.SYGMA_TYPED_MAP_ABI:
        contract = runner.SYGMA_TYPED_MAP_ABI[path]
    if path in runner.APPLICATION_SYSCALL_MAP_ABI:
        contract = runner.APPLICATION_SYSCALL_MAP_ABI[path]
    return json.dumps(
        {
            "event": "map_info",
            "map_path": path,
            "map_id": 1,
            "max_entries": 100,
            **contract,
        }
    ) + "\n"


def probe_events(cgroup_id: int = 42) -> list[dict]:
    return [
        {
            "event": "probe_start",
            "schema_version": 3,
            "boottime_ns": 1_000,
            "measurement_mode": "application_lineage_syscalls",
        },
        {
            "event": "probe_summary",
            "schema_version": 3,
            "measurement_mode": "application_lineage_syscalls",
            "cgroup_id": cgroup_id,
            "cgroup_id_errno": 0,
        },
    ]


def prestart_events(backend: str, *, application: str | None = None) -> list[dict]:
    mode = "enforcement" if backend == "sygma" else "tetragon-measurement"
    role = "policy-and-release" if backend == "sygma" else "timestamp-only"
    common = {
        "schema_version": runner.HOOK_TIMELINE_SCHEMA_VERSION,
        "component": "sygma-oci-hook",
        "backend": backend,
        "mode": mode,
        "hook_role": role,
        "container_name": "probe",
    }
    if application is not None:
        common["application"] = application
    return [
        {**common, "event": "oci_prestart_enter", "boottime_ns": 100},
        {**common, "event": "oci_prestart_complete", "boottime_ns": 500},
    ]


class RunnerValidationTests(unittest.TestCase):
    def test_kubernetes_zero_started_time_is_not_application_start(self) -> None:
        self.assertIsNone(
            runner.normalize_container_started_time("1970-01-01T00:00:00Z")
        )
        self.assertIsNone(
            runner.normalize_container_started_time("0001-01-01T00:00:00Z")
        )
        self.assertEqual(
            runner.normalize_container_started_time("2026-08-07T08:00:00Z"),
            "2026-08-07T08:00:00Z",
        )

    def test_only_pre_application_sygma_start_error_is_retryable(self) -> None:
        failure = {
            "backend": "sygma",
            "valid": False,
            "pod_phase": "Failed",
            "container_exit_code": 128,
            "container_termination_reason": "StartError",
            "container_started_time": None,
            "probe_started": False,
            "application_syscall_snapshot": None,
            "hook_prestart_abort": {
                "event": "oci_prestart_abort",
                "failure": "tracer attach timeout: deadline exceeded",
            },
        }
        self.assertEqual(
            runner.retryable_infrastructure_failure(failure),
            "sygma_prestart_start_error_before_application",
        )

        zero_time = dict(
            failure, container_started_time="1970-01-01T00:00:00Z"
        )
        self.assertEqual(
            runner.retryable_infrastructure_failure(zero_time),
            "sygma_prestart_start_error_before_application",
        )

        executed = dict(failure, probe_started=True)
        self.assertIsNone(runner.retryable_infrastructure_failure(executed))
        violation = dict(
            failure,
            pod_phase="Succeeded",
            container_exit_code=0,
            container_termination_reason="Completed",
            probe_started=True,
            application_syscall_snapshot={"total": 10},
        )
        self.assertIsNone(runner.retryable_infrastructure_failure(violation))

    def test_sygma_application_evidence_requires_ready_before_first_call(self) -> None:
        hook = [{"event": "sygma_direct_policy_ready", "boottime_ns": 100}]
        snapshot = {"first_boottime_ns": 101, "total": 42, "before_count": 0}
        evidence = runner.build_sygma_application_evidence(hook, snapshot)
        self.assertTrue(evidence["positive"])
        self.assertEqual(evidence["application_syscalls_uncovered"], 0)
        # before_count is the neutral counter's own measured number of
        # syscalls it saw complete before sygma_direct_policy_ready -- not
        # inferred from comparing first_boottime_ns against ready_ns.
        snapshot["before_count"] = 3
        evidence = runner.build_sygma_application_evidence(hook, snapshot)
        self.assertFalse(evidence["positive"])
        self.assertEqual(evidence["application_syscalls_uncovered"], 3)

    def test_container_status_requires_the_selected_container_name(self) -> None:
        probe_status = {
            "name": "probe",
            "imageID": "sha256:" + "a" * 64,
        }
        observer_status = {
            "name": "observer",
            "imageID": "sha256:" + "b" * 64,
        }
        pod = {
            "status": {
                "containerStatuses": [observer_status, probe_status],
            }
        }

        self.assertIs(
            runner.container_status(pod, container_name="probe"), probe_status
        )
        self.assertIs(
            runner.container_status(pod, container_name="observer"),
            observer_status,
        )
        self.assertEqual(
            runner.container_status(pod, container_name="missing"), {}
        )

    def test_observation_sources_have_no_blocking_action(self) -> None:
        repo = Path(__file__).resolve().parents[3]
        paths = [
            repo / "sygma_eBPF" / "monitoring.c",
            repo / "sygma_eBPF" / "main.go",
            repo / "ocihook" / "ebpf" / "tracer" / "main.go",
            repo / "ocihook" / "ebpf" / "wrapper" / "wrapper.c",
            Path(__file__).resolve().parents[1] / "manifests" / "tetragon-policy.yaml",
        ]
        forbidden = (
            "bpf_send_signal(",
            "bpf_send_signal_thread(",
            "bpf_override_return(",
            "return -EPERM",
            "AttachLSM",
            "PTRACE_POKEUSER",
            "PtraceSetRegs",
            "Override",
            "NoPost",
        )
        for path in paths:
            text = path.read_text(errors="replace")
            for token in forbidden:
                self.assertNotIn(token, text, f"{token} in {path}")

    def test_component_artifacts_must_match_installed_hashes(self) -> None:
        local_paths = {
            "core": runner.EVAL_ROOT / "build" / "sygma-core-current",
            "hook": runner.EVAL_ROOT / "build" / "sygma-hook",
            "tracer": runner.EVAL_ROOT / "build" / "sygma-tracer-current",
            "wrapper": runner.EVAL_ROOT / "build" / "sygma-wrapper-current",
            "nri_plugin": runner.EVAL_ROOT / "build" / "sygma-nri-current",
        }
        installed = {
            name: {"sha256": runner.sha256_file(path)}
            for name, path in local_paths.items()
        }
        args = argparse.Namespace(
            allow_hook_hash_mismatch=False,
            diagnostic_allow_sygma_artifact_mismatch=False,
        )
        result = runner.verify_sygma_component_artifacts(args, installed)
        self.assertTrue(result["verification"]["publication_eligible"])

        installed["tracer"] = {"sha256": "0" * 64}
        with self.assertRaisesRegex(runner.ExperimentError, "tracer hash mismatch"):
            runner.verify_sygma_component_artifacts(args, installed)

    def test_core_discovery_requires_unmodified_entrypoint(self) -> None:
        image_digest = "a" * 64

        class CoreCommands:
            def kubectl_json(self, _: list[str]) -> dict:
                return {
                    "items": [
                        {
                            "metadata": {"name": "core-pod", "namespace": "default"},
                            "spec": {
                                "nodeName": "node",
                                "containers": [
                                    {
                                        "name": "core",
                                        "image": (
                                            "registry/sygma-core-observation"
                                            f"@sha256:{image_digest}"
                                        ),
                                    }
                                ],
                            },
                            "status": {
                                "containerStatuses": [
                                    {
                                        "name": "core",
                                        "ready": True,
                                        "imageID": f"sha256:{image_digest}",
                                    }
                                ]
                            },
                        }
                    ]
                }

        core = runner.find_sygma_core_container(CoreCommands(), "node")
        self.assertEqual(core["pod"], "core-pod")

    def test_tetragon_policy_isolation_rejects_selector_overlap(self) -> None:
        self.assertTrue(
            runner.label_selector_matches(
                {"matchLabels": {"app": "nginx"}}, {"app": "nginx"}
            )
        )
        self.assertFalse(
            runner.label_selector_matches(
                {"matchLabels": {"app": "nginx"}},
                {"app.kubernetes.io/name": "sygma-gap-probe"},
            )
        )

        class Policies:
            def __init__(self, overlap: bool) -> None:
                self.overlap = overlap

            def kubectl_json(self, argv: list[str]) -> dict:
                if "tracingpoliciesnamespaced.cilium.io" in argv:
                    return {"items": []}
                selector = {} if self.overlap else {"matchLabels": {"app": "nginx"}}
                return {
                    "items": [
                        {
                            "metadata": {"name": "user-policy", "resourceVersion": "1"},
                            "spec": {"podSelector": selector},
                        }
                    ]
                }

        result = runner.verify_tetragon_policy_isolation(Policies(False), "eval")
        self.assertTrue(result["valid"])
        self.assertEqual(result["policies"][0]["selected_arms"], [])
        with self.assertRaisesRegex(runner.ExperimentError, "overlap"):
            runner.verify_tetragon_policy_isolation(Policies(True), "eval")

    def test_sygma_barrier_contract_is_valid(self) -> None:
        hook = prestart_events("sygma")
        hook[1:1] = [
            {"event": "sygma_direct_policy_ready", "boottime_ns": 200},
            {"event": "target_release_begin", "boottime_ns": 300},
            {"event": "target_release_signal_sent", "boottime_ns": 400},
        ]
        reasons = runner.validate_trial_raw(
            "sygma", "Succeeded", probe_events(), [], hook
        )
        self.assertEqual(reasons, [])

    def test_controlled_probe_attempt_is_rejected(self) -> None:
        events = probe_events()
        events.insert(1, {"event": "attempt", "errno": 0, "outcome": "success"})
        hook = prestart_events("sygma")
        hook[1:1] = [
            {"event": "sygma_direct_policy_ready", "boottime_ns": 200},
            {"event": "target_release_begin", "boottime_ns": 300},
            {"event": "target_release_signal_sent", "boottime_ns": 400},
        ]
        reasons = runner.validate_trial_raw("sygma", "Succeeded", events, [], hook)
        self.assertIn("unexpected_controlled_attempt_count_1", reasons)

    def test_container_logs_preserve_wrapper_and_extract_probe_json(self) -> None:
        raw = "\n".join(
            [
                "[sygma-wrapper] ========== SYGMA WRAPPER START ==========",
                "[sygma-wrapper] Resumed by attached tracer",
                "[sygma-wrapper] Seccomp filter installed",
                "[sygma-wrapper] Executing: /bin/sh.real",
                '{"event":"probe_start"}',
            ]
        )
        probe_jsonl, wrapper_log, reasons = runner.split_container_logs(
            "sygma", raw
        )
        self.assertEqual(probe_jsonl, '{"event":"probe_start"}\n')
        self.assertIn("SYGMA WRAPPER START", wrapper_log)
        self.assertEqual(reasons, [])

    def test_container_logs_reject_unknown_lines(self) -> None:
        _, _, reasons = runner.split_container_logs(
            "tetragon", "not-json\n{\"event\":\"probe_start\"}\n"
        )
        self.assertEqual(reasons, ["unexpected_container_log_line_1"])

    def test_tetragon_requires_exact_cgroup_correlation(self) -> None:
        map_events = [
            {
                "event": "map_insert",
                "cgroup_id": 99,
                "last_absent_boottime_ns": 900,
                "first_present_boottime_ns": 950,
            }
        ]
        reasons = runner.validate_trial_raw(
            "tetragon", "Succeeded", probe_events(cgroup_id=42), map_events, []
        )
        self.assertIn("cgroup_id_mismatch_probe_42_map_99", reasons)

    def test_tetragon_timing_only_prestart_contract_is_valid(self) -> None:
        map_events = [
            {"event": "watch_ready", "policy_id": 7, "boottime_ns": 600},
            {
                "event": "map_insert",
                "policy_id": 7,
                "cgroup_id": 42,
                "last_absent_boottime_ns": 1_100,
                "first_present_boottime_ns": 1_200,
            },
        ]
        reasons = runner.validate_trial_raw(
            "tetragon",
            "Succeeded",
            probe_events(cgroup_id=42),
            map_events,
            prestart_events("tetragon"),
            expected_policy_id=7,
        )
        self.assertEqual(reasons, [])

        reasons = runner.validate_trial_raw(
            "tetragon",
            "Succeeded",
            probe_events(cgroup_id=42),
            map_events,
            [],
            expected_policy_id=7,
        )
        self.assertIn("oci_prestart_enter_count_0", reasons)
        self.assertIn("oci_prestart_complete_count_0", reasons)

    def test_sygma_release_order_violation_is_explicit(self) -> None:
        hook = prestart_events("sygma")
        hook[1:1] = [
            {"event": "sygma_direct_policy_ready", "boottime_ns": 300},
            {"event": "target_release_begin", "boottime_ns": 200},
            {"event": "target_release_signal_sent", "boottime_ns": 400},
        ]
        reasons = runner.validate_trial_raw(
            "sygma", "Succeeded", probe_events(), [], hook
        )
        self.assertIn("sygma_atomicity_invariant_violation", reasons)

    def test_schedule_has_one_pair_per_block(self) -> None:
        schedule = runner.make_schedule(trials=5, warmups=2, seed=7)
        self.assertEqual(len(schedule), 14)
        for warmup, blocks in ((True, 2), (False, 5)):
            for block in range(1, blocks + 1):
                arms = [
                    backend
                    for backend, is_warmup, index in schedule
                    if is_warmup == warmup and index == block
                ]
                self.assertCountEqual(arms, ["sygma", "tetragon"])

    def test_workload_arms_differ_only_in_selection_metadata(self) -> None:
        args = argparse.Namespace(
            namespace="sygma-gap-eval",
            carrier_image="example.invalid/probe@sha256:deadbeef",
            image_pull_policy="Never",
            duration_ms=1000,
            interval_us=1000,
            evidence_hold_ms=5000,
            application="nginx",
        )
        sygma = runner.workload_pod(args, "sygma", "m001-sygma", "s", "node")
        tetragon = runner.workload_pod(
            args, "tetragon", "m001-tetragon", "t", "node"
        )
        self.assertEqual(sygma["metadata"]["annotations"]["sygma.io/mode"], "enforcement")
        self.assertEqual(
            sygma["metadata"]["annotations"]["sygma.io/image"],
            "sygma-gap-nginx:v1",
        )
        self.assertEqual(
            tetragon["metadata"]["annotations"],
            {runner.TIMELINE_PRESTART_ANNOTATION: "v1"},
        )
        self.assertEqual(
            tetragon["metadata"]["labels"]["gap.sygma.io/backend"], "tetragon"
        )

    def test_real_application_profiles_preserve_image_startup_contract(self) -> None:
        digest = "a" * 64
        for application in ("nginx", "redis", "httpd", "mysql"):
            with self.subTest(application=application):
                args = argparse.Namespace(
                    namespace="sygma-gap-eval",
                    carrier_image=f"example.invalid/{application}@sha256:{digest}",
                    image_pull_policy="Never",
                    duration_ms=1000,
                    interval_us=1000,
                    evidence_hold_ms=5000,
                    application=application,
                )
                pod = runner.workload_pod(
                    args, "sygma", "m001-sygma", "pod", "node"
                )
                container = pod["spec"]["containers"][0]

                self.assertNotIn("command", container)
                self.assertNotIn("args", container)
                self.assertNotIn("volumeMounts", container)
                self.assertNotIn("volumes", pod["spec"])
                self.assertEqual(
                    container["securityContext"],
                    {"allowPrivilegeEscalation": False},
                )
                self.assertEqual(
                    pod["metadata"]["labels"]["gap.sygma.io/application"],
                    application,
                )
                self.assertEqual(
                    pod["metadata"]["annotations"]["sygma.io/image"],
                    f"sygma-gap-{application}:v1",
                )

                environment = {
                    item["name"]: item["value"] for item in container["env"]
                }
                self.assertEqual(environment["APPLICATION"], application)
                if application == "mysql":
                    self.assertEqual(environment["MYSQL_ALLOW_EMPTY_PASSWORD"], "yes")
                    self.assertEqual(environment["MYSQL_DATABASE"], "gap_eval")
                else:
                    self.assertNotIn("MYSQL_ALLOW_EMPTY_PASSWORD", environment)

    def test_application_policy_identity_uses_common_launcher(self) -> None:
        self.assertEqual(runner.policy_binary_for_application("synthetic"), "gap-probe")
        self.assertEqual(
            runner.policy_binary_path_for_application("synthetic"),
            "/opt/eval/gap-probe",
        )
        for application in ("nginx", "redis", "httpd", "mysql"):
            with self.subTest(application=application):
                self.assertEqual(
                    runner.image_alias_for_application(application),
                    f"sygma-gap-{application}:v1",
                )
                self.assertEqual(
                    runner.policy_binary_for_application(application), "gap-launch"
                )
                self.assertEqual(
                    runner.policy_binary_path_for_application(application),
                    "/opt/gap/gap-launch",
                )

    def test_real_application_lifecycle_is_a_validity_gate(self) -> None:
        events = probe_events()
        events[0]["application"] = "nginx"
        events.insert(
            1,
            {
                "event": "app_spawn",
                "application": "nginx",
                "pid": 123,
                "boottime_ns": 1_000,
            },
        )
        events[-1].update(
            {
                "application": "nginx",
                "app_pid": 123,
                "app_alive_at_summary": True,
                "measurement_interrupted": False,
            }
        )
        events.append(
            {
                "event": "app_exit",
                "application": "nginx",
                "pid": 123,
                "phase": "cleanup",
                "boottime_ns": 2_000,
            }
        )
        hook = prestart_events("sygma", application="nginx")
        hook[1:1] = [
            {"event": "sygma_direct_policy_ready", "boottime_ns": 200},
            {"event": "target_release_begin", "boottime_ns": 300},
            {"event": "target_release_signal_sent", "boottime_ns": 400},
        ]

        reasons = runner.validate_trial_raw(
            "sygma",
            "Succeeded",
            events,
            [],
            hook,
            expected_application="nginx",
        )
        self.assertEqual(reasons, [])

        events[-2]["app_alive_at_summary"] = False
        events[-1]["phase"] = "measurement"
        reasons = runner.validate_trial_raw(
            "sygma",
            "Succeeded",
            events,
            [],
            hook,
            expected_application="nginx",
        )
        self.assertIn("application_not_alive_at_probe_summary", reasons)
        self.assertIn("application_exit_phase_measurement", reasons)

    def test_tetragon_policy_posts_rate_limited_without_blocking(self) -> None:
        policy = runner.tetragon_policy_object("ns")
        self.assertEqual(policy["metadata"]["name"], "observe-application-syscalls")
        tracepoint = policy["spec"]["tracepoints"][0]
        self.assertEqual(tracepoint["subsystem"], "raw_syscalls")
        self.assertEqual(tracepoint["event"], "sys_enter")
        actions = tracepoint["selectors"][0]["matchActions"]
        self.assertEqual(
            actions,
            [{"action": "Post", "rateLimit": "10s", "rateLimitScope": "process"}],
        )

    def test_sygma_pinned_map_capability_selects_typed_or_legacy(self) -> None:
        legacy_only = {
            path: True for path in runner.SYGMA_LEGACY_REQUIRED_PINNED_MAPS
        }

        legacy = runner.classify_sygma_pinned_map_capability(legacy_only)
        self.assertEqual(legacy["mode"], "legacy-sequence")
        self.assertTrue(legacy["legacy_required"]["all_present"])
        self.assertTrue(legacy["typed_policy"]["all_absent"])

        all_maps = dict(legacy_only)
        all_maps.update(
            {path: True for path in runner.SYGMA_TYPED_POLICY_PINNED_MAPS}
        )
        typed = runner.classify_sygma_pinned_map_capability(all_maps)
        self.assertEqual(typed["mode"], "typed-sequence")
        self.assertTrue(typed["typed_policy"]["all_present"])

    def test_sygma_required_maps_cover_setup_and_cleanup_contract(self) -> None:
        expected = {
            # prestart setup: graph/namespace gates and initializeProcessState.
            # container_info_map, main_process_map, ns_image_map, and
            # syscall_stats were removed from the audited typed core (see the
            # 2026-08-20 note above SYGMA_LEGACY_REQUIRED_PINNED_MAPS).
            "/sys/fs/bpf/sygma/syscall_graph_map",
            "/sys/fs/bpf/sygma/execution_time_map",
            "/sys/fs/bpf/sygma/pid_mount_ns_map",
            "/sys/fs/bpf/sygma/process_state_map",
            "/sys/fs/bpf/sygma/tid_to_namespace",
            # Non-optional cleanupEBPFMaps pins. Missing any one suppresses
            # sygma_cleanup_complete and invalidates the trial.
            "/sys/fs/bpf/sygma/collection_mode_map",
            "/sys/fs/bpf/sygma/collection_graph_map",
            "/sys/fs/bpf/sygma/transition_check_count",
            "/sys/fs/bpf/sygma/blocked_history",
            # Renamed from observed_misses; see the note above.
            "/sys/fs/bpf/sygma/observed_transition_map",
        }
        self.assertEqual(set(runner.SYGMA_LEGACY_REQUIRED_PINNED_MAPS), expected)

    def test_sygma_pinned_map_capability_rejects_missing_legacy_map(self) -> None:
        present = {
            path: True for path in runner.SYGMA_LEGACY_REQUIRED_PINNED_MAPS
        }
        missing = runner.SYGMA_LEGACY_REQUIRED_PINNED_MAPS[0]
        present[missing] = False

        with self.assertRaisesRegex(
            runner.ExperimentError, "legacy sequence maps.*syscall_graph_map"
        ):
            runner.classify_sygma_pinned_map_capability(present)

    def test_sygma_pinned_map_capability_rejects_partial_typed_set(self) -> None:
        present = {
            path: True for path in runner.SYGMA_LEGACY_REQUIRED_PINNED_MAPS
        }
        present[runner.SYGMA_TYPED_POLICY_PINNED_MAPS[0]] = True

        with self.assertRaisesRegex(runner.ExperimentError, "partial SYGMA typed-policy"):
            runner.classify_sygma_pinned_map_capability(present)

    def test_typed_sygma_preflight_records_checks_and_metadata_mode(self) -> None:
        class PreflightCommands:
            def __init__(self) -> None:
                self.calls: list[list[str]] = []

            def run(self, argv: list[str], **_: object) -> SimpleNamespace:
                self.calls.append(argv)
                path = argv[-1]
                present = (
                    path in runner.SYGMA_LEGACY_REQUIRED_PINNED_MAPS
                    or path in runner.SYGMA_TYPED_POLICY_PINNED_MAPS
                    or path in runner.APPLICATION_SYSCALL_PINNED_MAPS
                )
                return SimpleNamespace(
                    returncode=0 if present else 1,
                    stdout=inspected_map_stdout(path, typed=True) if present else "",
                    stderr="" if present else "not found",
                )

        args = argparse.Namespace(
            kubectl="kubectl",
            namespace="eval",
            diagnostic_skip_sygma_canary=True,
        )
        commands = PreflightCommands()
        capability = runner.preflight_sygma_pinned_maps(commands, args)

        self.assertEqual(capability["mode"], "typed-sequence")
        self.assertTrue(capability["primary_experiment_eligible"])
        self.assertEqual(
            len(commands.calls),
            len(runner.SYGMA_LEGACY_REQUIRED_PINNED_MAPS)
            + len(runner.SYGMA_TYPED_POLICY_PINNED_MAPS)
            + len(runner.APPLICATION_SYSCALL_PINNED_MAPS),
        )
        typed_path = runner.SYGMA_TYPED_POLICY_PINNED_MAPS[0]
        self.assertTrue(capability["checks"][typed_path]["present"])

        class MetadataCommands:
            def kubectl_json(self, argv: list[str]) -> dict:
                if argv[:2] == ["get", "nodes"]:
                    return {
                        "items": [
                            {
                                "metadata": {"name": "node"},
                                "status": {"nodeInfo": {"architecture": "amd64"}},
                            }
                        ]
                    }
                return {"items": []}

            def run(self, _: list[str], **__: object) -> SimpleNamespace:
                return SimpleNamespace(returncode=0, stdout="version", stderr="")

        metadata_args = argparse.Namespace(run_id="run-1")
        with mock.patch.object(runner, "source_snapshot_hash", return_value="hash"):
            metadata = runner.capture_metadata(
                MetadataCommands(),
                metadata_args,
                "node",
                "tetragon-pod",
                {},
                {},
                7,
                {},
                {},
                [],
                sygma_pinned_map_capability=capability,
            )
        self.assertIs(metadata["sygma_pinned_map_capability"], capability)

    def test_primary_preflight_rejects_complete_legacy_sequence_stack(self) -> None:
        class PreflightCommands:
            def run(self, argv: list[str], **_: object) -> SimpleNamespace:
                path = argv[-1]
                present = (
                    path in runner.SYGMA_LEGACY_REQUIRED_PINNED_MAPS
                    or path in runner.APPLICATION_SYSCALL_PINNED_MAPS
                )
                return SimpleNamespace(
                    returncode=0 if present else 1,
                    stdout=inspected_map_stdout(path) if present else "",
                    stderr="" if present else "not found",
                )

        args = argparse.Namespace(
            kubectl="kubectl",
            namespace="eval",
            diagnostic_skip_sygma_canary=False,
        )
        with self.assertRaisesRegex(
            runner.ExperimentError, "requires the typed 28-byte process_state ABI"
        ):
            runner.preflight_sygma_pinned_maps(PreflightCommands(), args)

    def test_typed_map_abi_mismatch_is_fail_closed(self) -> None:
        infos = {
            path: {"event": "map_info", **contract}
            for path, contract in {
                **runner.SYGMA_COMMON_MAP_ABI,
                **runner.SYGMA_TYPED_MAP_ABI,
            }.items()
        }
        infos["/sys/fs/bpf/sygma/policy_state_transition_map"] = {
            **infos["/sys/fs/bpf/sygma/policy_state_transition_map"],
            "value_size": 999,
        }
        with self.assertRaisesRegex(
            runner.ExperimentError, "policy_state_transition_map:value_size=999"
        ):
            runner.validate_sygma_map_abi("typed-sequence", infos)

    def test_primary_carrier_requires_digest_and_never(self) -> None:
        mutable = argparse.Namespace(
            carrier_image="example.invalid/carrier:latest",
            image_pull_policy="Never",
            diagnostic_skip_sygma_canary=False,
        )
        with self.assertRaisesRegex(runner.ExperimentError, "immutable"):
            runner.validate_carrier_image_policy(mutable)

        digest = "a" * 64
        pinned = argparse.Namespace(
            carrier_image=f"example.invalid/carrier@sha256:{digest}",
            image_pull_policy="Never",
            diagnostic_skip_sygma_canary=False,
        )
        policy = runner.validate_carrier_image_policy(pinned)
        self.assertTrue(policy["publication_eligible"])
        self.assertEqual(policy["requested_digest"], f"sha256:{digest}")
        self.assertEqual(policy["observer_digest"], f"sha256:{digest}")

        mutable_observer = argparse.Namespace(
            carrier_image=f"example.invalid/workload@sha256:{digest}",
            observer_image="example.invalid/observer:latest",
            image_pull_policy="Never",
            diagnostic_skip_sygma_canary=False,
        )
        with self.assertRaisesRegex(runner.ExperimentError, "observer image"):
            runner.validate_carrier_image_policy(mutable_observer)

    def test_tetragon_agent_is_selected_on_target_node(self) -> None:
        class AgentCommands:
            def kubectl_json(self, _: list[str]) -> dict:
                return {
                    "items": [
                        {
                            "metadata": {"name": "tet-node-a"},
                            "spec": {"nodeName": "node-a"},
                            "status": {
                                "containerStatuses": [
                                    {"name": "tetragon", "ready": True}
                                ]
                            },
                        },
                        {
                            "metadata": {"name": "tet-node-b"},
                            "spec": {"nodeName": "node-b"},
                            "status": {
                                "containerStatuses": [
                                    {"name": "tetragon", "ready": True}
                                ]
                            },
                        },
                    ]
                }

        self.assertEqual(
            runner.find_tetragon_pod(AgentCommands(), "node-b"), "tet-node-b"
        )

    def test_tetragon_map_bounds_and_policy_id_are_fail_closed(self) -> None:
        events = probe_events()
        events[1].update({"boottime_ns": 1_020})
        map_events = [
            {"event": "watch_ready", "policy_id": 7, "boottime_ns": 900},
            {
                "event": "map_insert",
                "policy_id": 8,
                "cgroup_id": 42,
                "last_absent_boottime_ns": 950,
                "first_present_boottime_ns": 1_000,
            },
        ]
        reasons = runner.validate_trial_raw(
            "tetragon",
            "Succeeded",
            events,
            map_events,
            [],
            expected_policy_id=7,
        )
        self.assertIn("tetragon_map_insert_policy_id_8_expected_7", reasons)


if __name__ == "__main__":
    unittest.main()
