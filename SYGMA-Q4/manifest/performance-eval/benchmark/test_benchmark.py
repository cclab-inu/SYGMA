#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import yaml

from analyze import aggregate, flatten_trial
from benchmark_lib import (
    EvaluationError,
    cpu_to_millicores,
    memory_to_bytes,
    mode_annotations,
    parse_redis_output,
    parse_sysbench_output,
    parse_wrk_output,
    patch_hotel_documents,
    route_delta,
    simple_workload_documents,
    summarize_metric_samples,
    sygma_allow_all_config,
    tetragon_policy,
)
from runner import Campaign, build_parser


HERE = Path(__file__).resolve().parent
HOTEL_CHART = Path("/workspace/git/DeathStarBench/hotelReservation/helm-chart/hotelreservation")


class ManifestTests(unittest.TestCase):
    def test_mode_annotations(self) -> None:
        self.assertEqual(mode_annotations("default"), {})
        self.assertEqual(mode_annotations("tetragon"), {})
        self.assertEqual(mode_annotations("sygma")["sygma.io/seccomp-routing"], "selective")
        self.assertEqual(
            mode_annotations("sygma-all-trace")["sygma.io/seccomp-routing"], "all-trace"
        )
        with self.assertRaises(EvaluationError):
            mode_annotations("unknown")

    def test_simple_manifests_are_unconfined_and_targeted(self) -> None:
        for workload in ("nginx", "httpd", "redis", "mysql"):
            for mode in ("default", "tetragon", "sygma", "sygma-all-trace"):
                deployment, service = simple_workload_documents(
                    workload, mode, "bench", {"disk": "nvme"}, f"example/{workload}:fixed"
                )
                template = deployment["spec"]["template"]
                self.assertEqual(template["spec"]["securityContext"]["seccompProfile"]["type"], "Unconfined")
                self.assertEqual(template["spec"]["nodeSelector"], {"disk": "nvme"})
                self.assertEqual(template["metadata"]["labels"]["perf.sygma.io/target"], "true")
                self.assertEqual(service["spec"]["type"], "NodePort")
                self.assertEqual(service["metadata"]["name"], "perf-endpoint")

    @unittest.skipUnless(HOTEL_CHART.is_dir(), "DeathStarBench Hotel chart is unavailable")
    def test_hotel_patch_targets_only_application(self) -> None:
        rendered = subprocess.run(
            ["helm", "template", "perf", str(HOTEL_CHART), "--namespace", "bench"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        documents, images, count = patch_hotel_documents(
            yaml.safe_load_all(rendered),
            "sygma-all-trace",
            "bench",
            {"kubernetes.io/hostname": "node-a"},
            "deathstarbench/hotel-reservation:fixed",
        )
        self.assertGreaterEqual(count, 8)
        self.assertEqual(images, {"deathstarbench/hotel-reservation:fixed"})
        targets = [
            item for item in documents
            if item.get("kind") == "Deployment"
            and item["spec"]["template"]["metadata"]["labels"].get("perf.sygma.io/target") == "true"
        ]
        self.assertEqual(len(targets), count)
        self.assertTrue(all(
            item["spec"]["template"]["metadata"]["annotations"]["sygma.io/seccomp-routing"] == "all-trace"
            for item in targets
        ))
        commands = {
            tuple(container.get("command") or [])
            for item in targets
            for container in item["spec"]["template"]["spec"]["containers"]
        }
        self.assertTrue(commands)
        self.assertTrue(all(
            command and command[0].startswith("/go/bin/")
            for command in commands
        ))
        target_mounts = [
            mount
            for item in targets
            for container in item["spec"]["template"]["spec"]["containers"]
            for mount in container.get("volumeMounts") or []
            if mount.get("subPath") == "service-config.json"
        ]
        self.assertTrue(target_mounts)
        self.assertTrue(all(
            mount["mountPath"] == "/workspace/config.json"
            for mount in target_mounts
        ))
        endpoint = [
            item for item in documents
            if item.get("kind") == "Service" and item["metadata"]["name"] == "perf-endpoint"
        ]
        self.assertEqual(len(endpoint), 1)

    def test_allow_all_config_supports_a_stable_probe_command(self) -> None:
        config = sygma_allow_all_config(
            "bench",
            "hotel-policy",
            "deathstarbench/hotel-reservation:fixed",
            probe_command=["/bin/sleep", "600"],
        )
        pod = yaml.safe_load(config["spec"]["collection"]["yamlContent"])
        self.assertEqual(
            pod["spec"]["containers"][0]["command"],
            ["/bin/sleep", "600"],
        )

    def test_tetragon_policy_is_namespaced_and_targeted(self) -> None:
        policy = tetragon_policy("bench")
        self.assertEqual(policy["kind"], "TracingPolicyNamespaced")
        self.assertEqual(policy["metadata"]["namespace"], "bench")
        self.assertEqual(policy["spec"]["podSelector"]["matchLabels"], {"perf.sygma.io/target": "true"})
        tracepoint = policy["spec"]["tracepoints"][0]
        self.assertEqual((tracepoint["subsystem"], tracepoint["event"]), ("raw_syscalls", "sys_enter"))

    def test_multi_replica_manifest_has_hostname_spread(self) -> None:
        deployment, _service = simple_workload_documents(
            "nginx",
            "default",
            "bench",
            {"perf-node": "true"},
            "nginx:fixed",
            target_replicas=4,
            spread=True,
        )
        self.assertEqual(deployment["spec"]["replicas"], 4)
        constraint = deployment["spec"]["template"]["spec"]["topologySpreadConstraints"][0]
        self.assertEqual(constraint["topologyKey"], "kubernetes.io/hostname")


class ParserTests(unittest.TestCase):
    def test_mysql_fixed_event_command_and_cli(self) -> None:
        args = build_parser().parse_args(["--mysql-events", "50000"])
        self.assertEqual(args.mysql_events, 50000)

        campaign = Campaign.__new__(Campaign)
        campaign.args = SimpleNamespace(
            mysql_events=50000,
            mysql_tables=4,
            mysql_table_size=10000,
            mysql_threads=4,
        )
        measured = campaign.load_command("mysql", "127.0.0.1", 3306, 45)
        self.assertIn("--time=0", measured)
        self.assertIn("--events=50000", measured)

        warmup = campaign.load_command(
            "mysql", "127.0.0.1", 3306, 5, mysql_events=0
        )
        self.assertIn("--time=5", warmup)
        self.assertIn("--events=0", warmup)

    def test_wrk2_parser(self) -> None:
        output = """
  Latency     1.50ms    1.00ms  10.00ms   80.00%
  50.000%    1.20ms
  95.000%    3.40ms
  99.000%    5.60ms
  300000 requests in 1.00m, 1.00GB read
Requests/sec:   5000.00
Socket errors: connect 0, read 0, write 0, timeout 0
"""
        result = parse_wrk_output(output)
        self.assertEqual(result["requests"], 300000)
        self.assertEqual(result["throughput_ops_per_sec"], 5000.0)
        self.assertEqual(result["latency_p95_ms"], 3.4)
        self.assertEqual(result["errors"], 0)

    def test_redis_parser(self) -> None:
        output = """
====== SET ======
  1000 requests completed in 1.00 seconds
throughput summary: 1000.00 requests per second
latency summary (msec):
    avg       min       p50       p95       p99       max
    0.10      0.02      0.08      0.20      0.30      0.50
====== GET ======
  1000 requests completed in 0.50 seconds
throughput summary: 2000.00 requests per second
latency summary (msec):
    avg       min       p50       p95       p99       max
    0.05      0.01      0.04      0.10      0.15      0.20
"""
        result = parse_redis_output(output)
        self.assertAlmostEqual(result["throughput_ops_per_sec"], 2000 / 1.5)
        self.assertEqual(result["latency_p99_ms"], 0.30)

    def test_sysbench_parser(self) -> None:
        output = """
transactions:                        6000   (100.00 per sec.)
queries:                             120000 (2000.00 per sec.)
Latency (ms):
         min:                                    1.00
         avg:                                    2.00
         max:                                    8.00
         95th percentile:                        4.00
         sum:                                12000.00
total time:                          60.0000s
ignored errors:                      0      (0.00 per sec.)
"""
        result = parse_sysbench_output(output)
        self.assertEqual(result["throughput_ops_per_sec"], 100.0)
        self.assertEqual(result["latency_p95_ms"], 4.0)


class MetricTests(unittest.TestCase):
    def test_quantities_and_resource_aggregation(self) -> None:
        self.assertEqual(cpu_to_millicores("125m"), 125.0)
        self.assertEqual(cpu_to_millicores("2"), 2000.0)
        self.assertEqual(memory_to_bytes("2Mi"), 2 * 1024 * 1024)
        samples = [
            {"scope": "workload", "timestamp_ns": 1, "cpu_millicores": 10, "memory_bytes": 100},
            {"scope": "workload", "timestamp_ns": 1, "cpu_millicores": 20, "memory_bytes": 200},
            {"scope": "workload", "timestamp_ns": 2, "cpu_millicores": 30, "memory_bytes": 400},
        ]
        summary = summarize_metric_samples(samples)["scopes"]["workload"]
        self.assertEqual(summary["samples"], 2)
        self.assertEqual(summary["cpu_millicores_mean"], 30)
        self.assertEqual(summary["memory_bytes_mean"], 350)

    def test_route_delta(self) -> None:
        result = route_delta(
            {"conventional_sigkill": 1, "lsm_bpf": 2, "ptrace_notify": 3},
            {"conventional_sigkill": 11, "lsm_bpf": 22, "ptrace_notify": 33},
        )
        self.assertEqual(result["total"], 60)
        with self.assertRaises(EvaluationError):
            route_delta(
                {"conventional_sigkill": 2, "lsm_bpf": 0, "ptrace_notify": 0},
                {"conventional_sigkill": 1, "lsm_bpf": 0, "ptrace_notify": 0},
            )

    def test_analysis(self) -> None:
        trial = {
            "trial": "nginx-r1-default",
            "sequence": 1,
            "workload": "nginx",
            "mode": "default",
            "repetition": 1,
            "valid": True,
            "performance": {"throughput_ops_per_sec": 1000.0, "latency_p99_ms": 2.0},
            "error_rate": 0.0,
            "resources": {"scopes": {"workload": {"cpu_millicores_mean": 100.0}}},
        }
        row = flatten_trial(trial)
        self.assertEqual(row["framework_cpu_millicores_mean"], 0.0)
        grouped = aggregate([row, dict(row, repetition=2, throughput_ops_per_sec=1100.0)])
        self.assertEqual(grouped[0]["valid_trials"], 2)
        self.assertEqual(grouped[0]["metrics"]["throughput_ops_per_sec"]["mean"], 1050.0)

    def test_analyzer_cli_writes_tables(self) -> None:
        trials = []
        for repetition, throughput in ((1, 1000.0), (2, 1100.0)):
            trials.append(
                {
                    "trial": f"nginx-r{repetition}-default",
                    "sequence": repetition,
                    "workload": "nginx",
                    "mode": "default",
                    "repetition": repetition,
                    "valid": True,
                    "performance": {"throughput_ops_per_sec": throughput},
                    "error_rate": 0.0,
                    "resources": {
                        "scopes": {"workload": {"cpu_millicores_mean": 100.0}}
                    },
                    "pod_evidence": {
                        "containers": [
                            {
                                "image": "nginx:fixed",
                                "image_id": "docker-pullable://nginx@sha256:abc",
                            }
                        ]
                    },
                }
            )
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory)
            (campaign / "trials.jsonl").write_text(
                "".join(json.dumps(item) + "\n" for item in trials), encoding="utf-8"
            )
            subprocess.run(
                ["python3", str(HERE / "analyze.py"), str(campaign)], check=True
            )
            summary = json.loads((campaign / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["valid_trial_count"], 2)
            self.assertEqual(
                summary["groups"][0]["metrics"]["throughput_ops_per_sec"]["mean"],
                1050.0,
            )
            self.assertTrue((campaign / "summary.csv").is_file())
            self.assertTrue((campaign / "trial-metrics.csv").is_file())


if __name__ == "__main__":
    unittest.main()
