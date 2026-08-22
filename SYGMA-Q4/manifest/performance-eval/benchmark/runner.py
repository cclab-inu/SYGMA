#!/usr/bin/env python3
"""Run default/Tetragon/SYGMA performance trials on Kubernetes.

The runner is intentionally strict: it redeploys the workload for every
trial, records exact image IDs and Pod identities, requires resource metrics,
and snapshots SYGMA's monotonic route counters around only the measured load.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from typing import Any, Iterable, Mapping, Sequence

import yaml

from benchmark_lib import (
    DEFAULT_IMAGES,
    MODES,
    WORKLOADS,
    EvaluationError,
    cpu_to_millicores,
    memory_to_bytes,
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


HERE = Path(__file__).resolve().parent
PERFORMANCE_ROOT = HERE.parent
REPO_ROOT = PERFORMANCE_ROOT.parents[1]
DEFAULT_HOTEL_CHART = Path("/workspace/git/DeathStarBench/hotelReservation/helm-chart/hotelreservation")
DEFAULT_WRK2 = Path("/workspace/git/DeathStarBench/wrk2/wrk")
ROUTE_NAMES = ("conventional_sigkill", "lsm_bpf", "ptrace_notify")


def utc_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def json_dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def parse_csv_choice(raw: str, allowed: Sequence[str], label: str) -> list[str]:
    if raw == "all":
        return list(allowed)
    values = [item.strip() for item in raw.split(",") if item.strip()]
    unknown = sorted(set(values).difference(allowed))
    if not values or unknown:
        raise EvaluationError(f"invalid {label}: {raw!r}; unknown={unknown}")
    return values


def parse_key_values(values: Iterable[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            raise EvaluationError(f"{label} must be KEY=VALUE: {raw!r}")
        key, value = raw.split("=", 1)
        if not key or not value:
            raise EvaluationError(f"{label} must be KEY=VALUE: {raw!r}")
        result[key] = value
    return result


class CommandRunner:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _record(self, record: Mapping[str, Any]) -> None:
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(json_dump(record) + "\n")

    def run(
        self,
        args: Sequence[str | os.PathLike[str]],
        *,
        input_text: str | None = None,
        check: bool = True,
        timeout: float | None = None,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(item) for item in args]
        started = time.time_ns()
        try:
            result = subprocess.run(
                command,
                input=input_text,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                env=dict(env) if env else None,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            self._record(
                {
                    "started_ns": started,
                    "finished_ns": time.time_ns(),
                    "args": command,
                    "timeout": timeout,
                    "error": "timeout",
                }
            )
            raise EvaluationError(f"command timed out after {timeout}s: {' '.join(command)}") from error
        self._record(
            {
                "started_ns": started,
                "finished_ns": time.time_ns(),
                "args": command,
                "returncode": result.returncode,
                "stdout_bytes": len(result.stdout.encode()),
                "stderr_bytes": len(result.stderr.encode()),
            }
        )
        if check and result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise EvaluationError(
                f"command failed ({result.returncode}): {' '.join(command)}"
                + (f"\n{detail}" if detail else "")
            )
        return result


class Kubectl:
    def __init__(self, commands: CommandRunner, context: str | None):
        self.commands = commands
        self.base = ["kubectl"]
        if context:
            self.base.extend(["--context", context])

    def run(self, args: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return self.commands.run([*self.base, *args], **kwargs)

    def get_json(self, resource: str, namespace: str | None = None) -> dict[str, Any]:
        args = ["get", resource]
        if namespace:
            args.extend(["-n", namespace])
        args.extend(["-o", "json", "--request-timeout=15s"])
        result = self.run(args, timeout=20)
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise EvaluationError(f"kubectl returned invalid JSON for {resource}: {error}") from error
        if not isinstance(value, dict):
            raise EvaluationError(f"kubectl returned non-object JSON for {resource}")
        return value

    def apply_documents(self, documents: Iterable[Mapping[str, Any]]) -> None:
        content = yaml.safe_dump_all(list(documents), sort_keys=False)
        self.run(["apply", "-f", "-"], input_text=content, timeout=60)

    def delete_documents(self, documents: Iterable[Mapping[str, Any]], timeout: int) -> None:
        content = yaml.safe_dump_all(list(documents), sort_keys=False)
        self.run(
            [
                "delete", "-f", "-", "--ignore-not-found=true", "--wait=true",
                f"--timeout={timeout}s",
            ],
            input_text=content,
            check=False,
            timeout=timeout + 15,
        )

    def delete(self, resource: str, namespace: str, timeout: int = 60) -> None:
        self.run(
            [
                "delete", resource, "-n", namespace, "--ignore-not-found=true",
                "--wait=true", f"--timeout={timeout}s",
            ],
            check=False,
            timeout=timeout + 15,
        )


def node_is_ready(node: Mapping[str, Any]) -> bool:
    conditions = (node.get("status") or {}).get("conditions") or []
    return any(item.get("type") == "Ready" and item.get("status") == "True" for item in conditions)


def labels_match(labels: Mapping[str, str], selector: Mapping[str, str]) -> bool:
    return all(labels.get(key) == value for key, value in selector.items())


def internal_ip(node: Mapping[str, Any]) -> str:
    addresses = (node.get("status") or {}).get("addresses") or []
    for address in addresses:
        if address.get("type") == "InternalIP" and address.get("address"):
            return str(address["address"])
    raise EvaluationError(f"node {node.get('metadata', {}).get('name')} has no InternalIP")


class StackManager:
    """Temporarily deactivate the competing data-plane DaemonSet.

    This does not remove the already-installed idle SYGMA NRI process. The NRI
    process is outside the steady-state request path for unannotated Pods; a
    pristine default baseline still requires a clean cluster/image.
    """

    disable_key = "perf.sygma.io/disabled"

    def __init__(self, kubectl: Kubectl, args: argparse.Namespace, output: Path):
        self.kubectl = kubectl
        self.args = args
        self.output = output
        self.resources: dict[str, dict[str, Any]] = {}
        self.disabled_value = f"campaign-{output.name.lower()}"

    @staticmethod
    def split(reference: str) -> tuple[str, str]:
        if "/" not in reference:
            raise EvaluationError(f"resource reference must be NAMESPACE/NAME: {reference}")
        return tuple(reference.split("/", 1))  # type: ignore[return-value]

    def snapshot(self) -> None:
        references = {
            "tetragon_ds": ("daemonset", self.args.tetragon_daemonset),
            "tetragon_operator": ("deployment", self.args.tetragon_operator_deployment),
            "sygma_core_ds": ("daemonset", self.args.sygma_core_daemonset),
            "sygma_operator": ("deployment", self.args.sygma_operator_deployment),
            "sygma_redis": ("deployment", self.args.sygma_redis_deployment),
        }
        for label, (kind, reference) in references.items():
            namespace, name = self.split(reference)
            value = self.kubectl.get_json(f"{kind}/{name}", namespace)
            if kind == "daemonset":
                saved = {
                    "kind": kind,
                    "namespace": namespace,
                    "name": name,
                    "nodeSelector": ((value.get("spec") or {}).get("template") or {}).get("spec", {}).get("nodeSelector"),
                }
                selector = saved["nodeSelector"] or {}
                if self.disable_key in selector:
                    raise EvaluationError(f"{reference} already contains reserved selector {self.disable_key}")
            else:
                saved = {
                    "kind": kind,
                    "namespace": namespace,
                    "name": name,
                    "replicas": int((value.get("spec") or {}).get("replicas", 1)),
                }
                if saved["replicas"] < 1:
                    raise EvaluationError(f"{reference} must have a nonzero original replica count")
            self.resources[label] = saved
        (self.output / "stack-before.json").write_text(
            json.dumps(self.resources, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _patch_selector(self, label: str, enabled: bool) -> None:
        saved = self.resources[label]
        namespace, name = saved["namespace"], saved["name"]
        selector = dict(saved.get("nodeSelector") or {})
        if not enabled:
            selector[self.disable_key] = self.disabled_value
        current = self.kubectl.get_json(f"daemonset/{name}", namespace)
        current_selector = ((current.get("spec") or {}).get("template") or {}).get("spec", {}).get("nodeSelector")
        operation = "replace" if current_selector is not None else "add"
        patch = [{"op": operation, "path": "/spec/template/spec/nodeSelector", "value": selector}]
        self.kubectl.run(
            ["patch", f"daemonset/{name}", "-n", namespace, "--type=json", "-p", json.dumps(patch)],
            timeout=30,
        )
        if enabled:
            self.kubectl.run(
                ["rollout", "status", f"daemonset/{name}", "-n", namespace, f"--timeout={self.args.rollout_timeout}s"],
                timeout=self.args.rollout_timeout + 15,
            )
        else:
            deadline = time.monotonic() + self.args.rollout_timeout
            while time.monotonic() < deadline:
                status = self.kubectl.get_json(f"daemonset/{name}", namespace).get("status") or {}
                if int(status.get("currentNumberScheduled", 0)) == 0 and int(status.get("numberReady", 0)) == 0:
                    return
                time.sleep(2)
            raise EvaluationError(f"daemonset/{name} did not become inactive")

    def _scale(self, label: str, enabled: bool) -> None:
        saved = self.resources[label]
        replicas = saved["replicas"] if enabled else 0
        namespace, name = saved["namespace"], saved["name"]
        self.kubectl.run(
            ["scale", f"deployment/{name}", "-n", namespace, f"--replicas={replicas}"], timeout=30
        )
        if enabled:
            self.kubectl.run(
                ["rollout", "status", f"deployment/{name}", "-n", namespace, f"--timeout={self.args.rollout_timeout}s"],
                timeout=self.args.rollout_timeout + 15,
            )
        else:
            deadline = time.monotonic() + self.args.rollout_timeout
            while time.monotonic() < deadline:
                status = self.kubectl.get_json(f"deployment/{name}", namespace).get("status") or {}
                if int(status.get("replicas", 0)) == 0:
                    return
                time.sleep(2)
            raise EvaluationError(f"deployment/{name} did not scale to zero")

    def enter(self, mode: str) -> None:
        if self.args.stack_management == "external":
            return
        sygma = mode in ("sygma", "sygma-all-trace")
        tetragon = mode == "tetragon"
        if not sygma:
            self._scale("sygma_operator", False)
            self._patch_selector("sygma_core_ds", False)
            self._scale("sygma_redis", False)
        if not tetragon:
            self._scale("tetragon_operator", False)
            self._patch_selector("tetragon_ds", False)
        if tetragon:
            self._scale("tetragon_operator", True)
            self._patch_selector("tetragon_ds", True)
        if sygma:
            self._scale("sygma_redis", True)
            self._patch_selector("sygma_core_ds", True)
            self._scale("sygma_operator", True)

    def restore(self) -> None:
        if self.args.stack_management == "external" or not self.resources:
            return
        errors: list[str] = []
        # The config operator opens pinned BPF maps during process startup, so
        # core must be Ready before the operator is restored. Tetragon's
        # operator similarly comes up before its node agent.
        restore_steps = (
            ("sygma_redis", "scale"),
            ("sygma_core_ds", "selector"),
            ("sygma_operator", "scale"),
            ("tetragon_operator", "scale"),
            ("tetragon_ds", "selector"),
        )
        for label, operation in restore_steps:
            try:
                if operation == "scale":
                    self._scale(label, True)
                else:
                    self._patch_selector(label, True)
            except Exception as error:
                errors.append(f"{label}: {error}")
        if errors:
            raise EvaluationError("stack restoration failed: " + "; ".join(errors))


class MetricsSampler:
    def __init__(
        self,
        kubectl: Kubectl,
        namespace: str,
        interval: float,
        output: Path,
    ):
        self.kubectl = kubectl
        self.namespace = namespace
        self.interval = interval
        self.output = output
        self.samples: list[dict[str, Any]] = []
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="metrics-sampler", daemon=True)

    def scope(self, namespace: str, pod: str) -> str:
        if namespace == self.namespace:
            return "workload"
        if namespace == "kube-system" and "tetragon" in pod:
            return "framework"
        if namespace == "default" and pod.startswith(
            ("core-", "sygma-config-operator-", "sygma-policy-redis-")
        ):
            return "framework"
        return "infrastructure"

    def _append(self, sample: dict[str, Any]) -> None:
        self.samples.append(sample)
        with self.output.open("a", encoding="utf-8") as stream:
            stream.write(json_dump(sample) + "\n")

    def sample_once(self) -> None:
        timestamp = time.time_ns()
        result = subprocess.run(
            [*self.kubectl.base, "top", "pods", "-A", "--containers", "--no-headers"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
        if result.returncode:
            self._append({"timestamp_ns": timestamp, "scope": "sampler", "error": result.stderr.strip()})
        else:
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) != 5:
                    continue
                namespace, pod, container, cpu, memory = fields
                try:
                    sample = {
                        "timestamp_ns": timestamp,
                        "scope": self.scope(namespace, pod),
                        "namespace": namespace,
                        "pod": pod,
                        "container": container,
                        "cpu_millicores": cpu_to_millicores(cpu),
                        "memory_bytes": memory_to_bytes(memory),
                    }
                except EvaluationError as error:
                    sample = {"timestamp_ns": timestamp, "scope": "sampler", "error": str(error)}
                self._append(sample)

        node_result = subprocess.run(
            [*self.kubectl.base, "top", "nodes", "--no-headers"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
        if node_result.returncode:
            self._append({"timestamp_ns": timestamp, "scope": "node", "error": node_result.stderr.strip()})
        else:
            for line in node_result.stdout.splitlines():
                fields = line.split()
                if len(fields) < 5:
                    continue
                try:
                    self._append(
                        {
                            "timestamp_ns": timestamp,
                            "scope": "node",
                            "node": fields[0],
                            "cpu_millicores": cpu_to_millicores(fields[1]),
                            "memory_bytes": memory_to_bytes(fields[3]),
                        }
                    )
                except EvaluationError as error:
                    self._append({"timestamp_ns": timestamp, "scope": "node", "error": str(error)})

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                self.sample_once()
            except Exception as error:
                self._append({"timestamp_ns": time.time_ns(), "scope": "sampler", "error": str(error)})
            self.stop_event.wait(max(0.0, self.interval - (time.monotonic() - started)))

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=max(30.0, self.interval + 20.0))
        if self.thread.is_alive():
            raise EvaluationError("metrics sampler did not stop")


class Campaign:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.campaign_id = args.campaign_id or f"perf-{utc_id()}"
        self.output = Path(args.output_dir).resolve() / self.campaign_id
        if self.output.exists():
            raise EvaluationError(f"output directory already exists: {self.output}")
        self.output.mkdir(parents=True)
        self.commands = CommandRunner(self.output / "commands.jsonl")
        self.kubectl = Kubectl(self.commands, args.context)
        self.stack = StackManager(self.kubectl, args, self.output)
        self.images = dict(DEFAULT_IMAGES)
        self.images.update(parse_key_values(args.image, "--image"))
        unknown_images = sorted(set(self.images).difference(WORKLOADS))
        if unknown_images:
            raise EvaluationError(f"unknown image overrides: {unknown_images}")
        self.workloads = parse_csv_choice(args.workloads, WORKLOADS, "workloads")
        self.modes = parse_csv_choice(args.modes, MODES, "modes")
        self.node_selector = parse_key_values(args.node_selector, "--node-selector")
        self.nodes: list[dict[str, Any]] = []
        self.trial_records: list[dict[str, Any]] = []
        self._interrupted = False

    def write_json(self, path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    def append_trial(self, value: Mapping[str, Any]) -> None:
        with (self.output / "trials.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json_dump(value) + "\n")
        self.trial_records.append(dict(value))

    def select_nodes(self) -> None:
        node_list = self.kubectl.get_json("nodes")
        candidates = []
        for node in node_list.get("items") or []:
            labels = (node.get("metadata") or {}).get("labels") or {}
            if node_is_ready(node) and not (node.get("spec") or {}).get("unschedulable") and labels_match(labels, self.node_selector):
                candidates.append(node)
        if not candidates:
            raise EvaluationError("no Ready schedulable node matches --node-selector")
        if self.args.topology == "single":
            if len(candidates) != 1 and not self.args.workload_node:
                names = [item.get("metadata", {}).get("name") for item in candidates]
                raise EvaluationError(
                    f"single topology found {len(candidates)} matching nodes {names}; set --workload-node"
                )
            if self.args.workload_node:
                candidates = [item for item in candidates if item.get("metadata", {}).get("name") == self.args.workload_node]
                if len(candidates) != 1:
                    raise EvaluationError(f"workload node {self.args.workload_node!r} is not Ready/matching")
            selected = candidates[:1]
            hostname = selected[0].get("metadata", {}).get("labels", {}).get("kubernetes.io/hostname")
            if not hostname:
                raise EvaluationError("single workload node lacks kubernetes.io/hostname")
            self.node_selector["kubernetes.io/hostname"] = hostname
            self.nodes = selected
        else:
            if not self.node_selector:
                raise EvaluationError("multi topology requires at least one --node-selector")
            self.nodes = candidates

    def ensure_namespace(self) -> None:
        self.kubectl.apply_documents(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": self.args.namespace,
                        "labels": {"perf.sygma.io/campaign": self.campaign_id},
                    },
                }
            ]
        )

    def preflight(self) -> None:
        required = ["kubectl", "helm", "redis-benchmark", "sysbench"]
        required.append(str(self.args.wrk2 if self.args.http_rate > 0 or self.args.hotel_rate > 0 else self.args.wrk))
        missing = [name for name in required if shutil.which(name) is None and not Path(name).is_file()]
        if missing:
            raise EvaluationError(f"missing load/deployment tools: {missing}")
        if not Path(self.args.hotel_chart).is_dir():
            raise EvaluationError(f"Hotel chart is missing: {self.args.hotel_chart}")
        if self.args.stack_management == "managed" and not self.args.confirm_dedicated_cluster:
            raise EvaluationError("managed stack switching requires --confirm-dedicated-cluster")

        self.select_nodes()
        self.ensure_namespace()
        metrics = self.kubectl.run(["top", "pods", "-A", "--containers", "--no-headers"], check=False, timeout=30)
        if metrics.returncode:
            raise EvaluationError("resource metrics API is required: " + metrics.stderr.strip())
        if "tetragon" in self.modes:
            self.kubectl.get_json("crd/tracingpoliciesnamespaced.cilium.io")
        if any(mode.startswith("sygma") for mode in self.modes):
            self.kubectl.get_json("crd/sygmaconfigs.security.security.io")
        if self.args.stack_management == "managed":
            self.stack.snapshot()

        metadata = {
            "schema_version": 1,
            "campaign_id": self.campaign_id,
            "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "arguments": vars(self.args),
            "images": self.images,
            "workloads": self.workloads,
            "modes": self.modes,
            "node_selector": self.node_selector,
            "nodes": [
                {
                    "name": item.get("metadata", {}).get("name"),
                    "uid": item.get("metadata", {}).get("uid"),
                    "internal_ip": internal_ip(item),
                    "kernel": item.get("status", {}).get("nodeInfo", {}).get("kernelVersion"),
                    "runtime": item.get("status", {}).get("nodeInfo", {}).get("containerRuntimeVersion"),
                }
                for item in self.nodes
            ],
        }
        self.write_json(self.output / "metadata.json", metadata)

    def render_hotel(self, mode: str) -> tuple[list[dict[str, Any]], str]:
        result = self.commands.run(
            [
                "helm", "template", "perf", str(self.args.hotel_chart),
                "--namespace", self.args.namespace,
            ],
            timeout=60,
        )
        try:
            documents = list(yaml.safe_load_all(result.stdout))
        except yaml.YAMLError as error:
            raise EvaluationError(f"Hotel Helm render is invalid YAML: {error}") from error
        patched, images, _count = patch_hotel_documents(
            documents,
            mode,
            self.args.namespace,
            self.node_selector,
            self.images["hotel"],
            target_replicas=self.args.target_replicas,
            spread=self.args.topology == "multi",
        )
        return patched, next(iter(images))

    def render_workload(self, workload: str, mode: str) -> tuple[list[dict[str, Any]], str]:
        if workload == "hotel":
            return self.render_hotel(mode)
        return (
            simple_workload_documents(
                workload,
                mode,
                self.args.namespace,
                self.node_selector,
                self.images[workload],
                target_replicas=self.args.target_replicas,
                spread=self.args.topology == "multi",
            ),
            self.images[workload],
        )

    def configure_mode_policy(self, mode: str, workload: str, trial_name: str, image: str) -> dict[str, Any] | None:
        self.kubectl.delete(
            "tracingpoliciesnamespaced.cilium.io/perf-syscall-route",
            self.args.namespace,
            timeout=30,
        )
        if mode == "tetragon":
            self.kubectl.apply_documents([tetragon_policy(self.args.namespace)])

        if not mode.startswith("sygma"):
            return None
        self.assert_no_other_sygma_workloads()
        config_name = re.sub(r"[^a-z0-9-]", "-", f"cfg-{trial_name}".lower())[:63].rstrip("-")
        # The Hotel Reservation image is a multi-binary image without a
        # usable default command.  Keep the operator's image-discovery Pod
        # alive long enough to publish the evaluation allow-all policy.  The
        # real application Pods carry explicit /go/bin/<service> commands,
        # which the NRI hook uses in preference to this probe binary.
        probe_command = (
            ["/bin/sleep", "600"]
            if workload in ("hotel", "mysql")
            else None
        )
        config = sygma_allow_all_config(
            self.args.namespace,
            config_name,
            image,
            probe_command=probe_command,
        )
        self.kubectl.apply_documents([config])
        try:
            deadline = time.monotonic() + self.args.policy_timeout
            last = ""
            while time.monotonic() < deadline:
                observed = self.kubectl.get_json(f"sygmaconfig/{config_name}", self.args.namespace)
                status = observed.get("status") or {}
                last = json_dump(status)
                generation = int(observed.get("metadata", {}).get("generation", 0))
                if status.get("collectionComplete") is True and int(status.get("observedGeneration", 0)) == generation:
                    return config
                if str(status.get("phase", "")).lower() in ("failed", "error"):
                    raise EvaluationError(f"SYGMAConfig failed: {last}")
                time.sleep(2)
            raise EvaluationError(f"SYGMAConfig did not complete: {last}")
        except Exception:
            self.kubectl.delete(
                f"sygmaconfig/{config_name}", self.args.namespace, self.args.rollout_timeout
            )
            raise

    def assert_no_other_sygma_workloads(self) -> None:
        result = self.kubectl.run(
            ["get", "pods", "-A", "-o", "json", "--request-timeout=15s"], timeout=20
        )
        pods = json.loads(result.stdout)
        offenders = []
        for pod in pods.get("items") or []:
            metadata = pod.get("metadata") or {}
            annotations = metadata.get("annotations") or {}
            if annotations.get("sygma.io/mode") and metadata.get("namespace") != self.args.namespace:
                offenders.append(f"{metadata.get('namespace')}/{metadata.get('name')}")
        if offenders and not self.args.allow_shared_sygma:
            raise EvaluationError(
                "route counters would include other SYGMA workloads: " + ", ".join(offenders)
            )

    def wait_workload(self, workload: str) -> None:
        if workload == "hotel":
            self.kubectl.run(
                [
                    "wait", "deployment", "--all", "-n", self.args.namespace,
                    "--for=condition=Available", f"--timeout={self.args.rollout_timeout}s",
                ],
                timeout=self.args.rollout_timeout + 15,
            )
        else:
            self.kubectl.run(
                [
                    "rollout", "status", f"deployment/perf-{workload}", "-n", self.args.namespace,
                    f"--timeout={self.args.rollout_timeout}s",
                ],
                timeout=self.args.rollout_timeout + 15,
            )
        self.kubectl.run(
            [
                "wait", "pod", "-n", self.args.namespace,
                "-l", f"perf.sygma.io/workload={workload}",
                "--for=condition=Ready", f"--timeout={self.args.rollout_timeout}s",
            ],
            timeout=self.args.rollout_timeout + 15,
        )

    def workload_pods(self, target_only: bool = False) -> list[dict[str, Any]]:
        selector = "perf.sygma.io/target=true" if target_only else "perf.sygma.io/workload"
        result = self.kubectl.run(
            ["get", "pods", "-n", self.args.namespace, "-l", selector, "-o", "json"], timeout=30
        )
        value = json.loads(result.stdout)
        return list(value.get("items") or [])

    def endpoint(self) -> tuple[str, int]:
        service = self.kubectl.get_json("service/perf-endpoint", self.args.namespace)
        ports = (service.get("spec") or {}).get("ports") or []
        if len(ports) != 1 or not ports[0].get("nodePort"):
            raise EvaluationError("perf-endpoint does not expose one NodePort")
        if self.args.endpoint_host:
            host = self.args.endpoint_host
        else:
            pods = self.workload_pods(target_only=True)
            if not pods:
                raise EvaluationError("no target Pod exists for endpoint selection")
            node_name = pods[0].get("spec", {}).get("nodeName")
            node = self.kubectl.get_json(f"node/{node_name}")
            host = internal_ip(node)
        return host, int(ports[0]["nodePort"])

    def wait_endpoint(self, host: str, port: int) -> None:
        """Wait for the NodePort data path, not only Pod readiness.

        EndpointSlice and kube-proxy/CNI programming can lag a Ready Pod by a
        short interval. Starting wrk in that window incorrectly rejects an
        otherwise healthy trial with ECONNREFUSED.
        """
        deadline = time.monotonic() + self.args.endpoint_timeout
        last_error = "not attempted"
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=2):
                    return
            except OSError as error:
                last_error = str(error)
                time.sleep(1)
        raise EvaluationError(
            f"endpoint {host}:{port} was not reachable within "
            f"{self.args.endpoint_timeout}s: {last_error}"
        )

    def pod_evidence(self) -> dict[str, Any]:
        pods = self.workload_pods(target_only=False)
        targets = []
        containers = []
        restarts = 0
        for pod in pods:
            metadata = pod.get("metadata") or {}
            for status in (pod.get("status") or {}).get("containerStatuses") or []:
                restarts += int(status.get("restartCount", 0))
                evidence = {
                    "pod": metadata.get("name"),
                    "uid": metadata.get("uid"),
                    "node": (pod.get("spec") or {}).get("nodeName"),
                    "container": status.get("name"),
                    "container_id": status.get("containerID"),
                    "image": status.get("image"),
                    "image_id": status.get("imageID"),
                    "restart_count": status.get("restartCount", 0),
                }
                containers.append(evidence)
                if (metadata.get("labels") or {}).get("perf.sygma.io/target") == "true":
                    targets.append(evidence)
        if not targets:
            raise EvaluationError("no target container evidence")
        return {
            "targets": targets,
            "containers": containers,
            "total_restarts": restarts,
            "pod_count": len(pods),
        }

    def wait_metrics_ready(self, evidence: Mapping[str, Any]) -> None:
        """Wait until Metrics Server publishes every workload container.

        A newly Ready Pod commonly needs one Metrics Server scrape interval
        before it appears in ``kubectl top``.  Starting a short benchmark
        immediately made fast Redis arms invalid while the slower all-trace
        arm happened to collect enough samples.
        """
        expected = {
            (str(item.get("pod")), str(item.get("container")))
            for item in evidence.get("containers") or []
        }
        deadline = time.monotonic() + 90
        observed: set[tuple[str, str]] = set()
        last_error = "metrics not queried"
        while time.monotonic() < deadline:
            result = self.kubectl.run(
                ["top", "pods", "-A", "--containers", "--no-headers"],
                check=False,
                timeout=30,
            )
            if result.returncode:
                last_error = result.stderr.strip()
            else:
                observed = {
                    (fields[1], fields[2])
                    for line in result.stdout.splitlines()
                    if len(fields := line.split()) == 5 and fields[0] == self.args.namespace
                }
                if expected.issubset(observed):
                    return
                missing = sorted(expected.difference(observed))
                last_error = f"missing {len(missing)} container metric(s): {missing[:5]}"
            time.sleep(2)
        raise EvaluationError(f"workload metrics did not become ready within 90s: {last_error}")

    def route_snapshot(self) -> dict[str, Any]:
        target_nodes = sorted(
            {str((pod.get("spec") or {}).get("nodeName")) for pod in self.workload_pods(target_only=True)}
        )
        core_result = self.kubectl.run(
            ["get", "pods", "-n", "default", "-l", "container=core", "-o", "json"], timeout=30
        )
        core_pods = json.loads(core_result.stdout).get("items") or []
        by_node = {
            str((pod.get("spec") or {}).get("nodeName")): str((pod.get("metadata") or {}).get("name"))
            for pod in core_pods
            if any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in (pod.get("status") or {}).get("conditions") or []
            )
        }
        aggregate = {name: 0 for name in ROUTE_NAMES}
        per_node: dict[str, Any] = {}
        for node in target_nodes:
            pod = by_node.get(node)
            if not pod:
                raise EvaluationError(f"no Ready core Pod on target node {node}")
            result = self.kubectl.run(
                ["exec", "-n", "default", pod, "-c", "core", "--", "/usr/daemon/route-snapshot"],
                timeout=30,
            )
            try:
                value = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise EvaluationError(f"route snapshot from {node} is invalid JSON: {error}") from error
            counters = value.get("counters") or {}
            if set(counters) != set(ROUTE_NAMES):
                raise EvaluationError(f"route snapshot from {node} has keys {sorted(counters)}")
            per_node[node] = counters
            for name in ROUTE_NAMES:
                aggregate[name] += int(counters[name])
        return {"counters": aggregate, "per_node": per_node}

    def load_command(
        self,
        workload: str,
        host: str,
        port: int,
        duration: int,
        *,
        mysql_events: int | None = None,
    ) -> list[str]:
        if workload in ("nginx", "httpd", "hotel"):
            rate = self.args.hotel_rate if workload == "hotel" else self.args.http_rate
            script_args: list[str] = []
            if workload == "hotel":
                script_args = ["-s", str(HERE / "hotel.lua")]
            if rate > 0:
                return [
                    str(self.args.wrk2), "-D", "exp", "-t", str(self.args.http_threads),
                    "-c", str(self.args.http_connections), "-d", f"{duration}s", "-L",
                    "-R", str(rate), *script_args, f"http://{host}:{port}/",
                ]
            return [
                str(self.args.wrk), "-t", str(self.args.http_threads),
                "-c", str(self.args.http_connections), "-d", f"{duration}s",
                "--latency", *script_args, f"http://{host}:{port}/",
            ]
        if workload == "redis":
            return [
                "redis-benchmark", "-h", host, "-p", str(port),
                "-c", str(self.args.redis_clients), "-n", str(self.args.redis_requests),
                "-r", str(self.args.redis_keyspace), "-t", "get,set", "-e",
                "--precision", "3",
            ]
        if workload == "mysql":
            events = self.args.mysql_events if mysql_events is None else mysql_events
            time_limit = 0 if events > 0 else duration
            return [
                "sysbench", "oltp_read_write", "--db-driver=mysql",
                f"--mysql-host={host}", f"--mysql-port={port}", "--mysql-user=root",
                "--mysql-password=sygma-perf-root", "--mysql-db=sbtest",
                f"--tables={self.args.mysql_tables}", f"--table-size={self.args.mysql_table_size}",
                f"--threads={self.args.mysql_threads}", f"--time={time_limit}",
                f"--events={events}", "--report-interval=1", "run",
            ]
        raise EvaluationError(f"unsupported workload: {workload}")

    def prepare_and_warmup(self, workload: str, host: str, port: int, trial_dir: Path) -> None:
        if workload == "mysql":
            # Preparation and warm-up remain time-bounded even when the
            # measured run uses a fixed transaction count.
            command = self.load_command(
                workload, host, port, self.args.duration, mysql_events=0
            )
            prepare = [item for item in command if item != "run" and not item.startswith("--time=") and not item.startswith("--threads=") and not item.startswith("--events=") and item != "--report-interval=1"]
            prepare.append("prepare")
            result = self.commands.run(prepare, timeout=self.args.rollout_timeout)
            (trial_dir / "prepare.stdout.log").write_text(result.stdout, encoding="utf-8")
            (trial_dir / "prepare.stderr.log").write_text(result.stderr, encoding="utf-8")
            warmup = self.load_command(
                workload, host, port, self.args.warmup, mysql_events=0
            )
        elif workload == "redis":
            warmup = [
                "redis-benchmark", "-h", host, "-p", str(port), "-c", "16",
                "-n", str(self.args.redis_keyspace), "-r", str(self.args.redis_keyspace),
                "-t", "set", "-q",
            ]
        else:
            warmup = self.load_command(workload, host, port, self.args.warmup)
        result = self.commands.run(warmup, timeout=max(self.args.rollout_timeout, self.args.warmup + 60))
        (trial_dir / "warmup.stdout.log").write_text(result.stdout, encoding="utf-8")
        (trial_dir / "warmup.stderr.log").write_text(result.stderr, encoding="utf-8")
        if workload not in ("redis", "mysql"):
            parsed = parse_wrk_output(result.stdout + "\n" + result.stderr)
            if parsed.get("requests", 0) == 0:
                raise EvaluationError("warm-up completed no requests")

    @staticmethod
    def parse_load(workload: str, stdout: str, stderr: str) -> dict[str, Any]:
        text = stdout + "\n" + stderr
        if workload in ("nginx", "httpd", "hotel"):
            return parse_wrk_output(text)
        if workload == "redis":
            return parse_redis_output(text)
        if workload == "mysql":
            return parse_sysbench_output(text)
        raise EvaluationError(f"unsupported workload: {workload}")

    def teardown(
        self,
        documents: list[dict[str, Any]],
        config: dict[str, Any] | None,
    ) -> None:
        if documents:
            self.kubectl.delete_documents(documents, self.args.rollout_timeout)
        if config:
            name = config.get("metadata", {}).get("name")
            if name:
                self.kubectl.delete(f"sygmaconfig/{name}", self.args.namespace, self.args.rollout_timeout)
        self.kubectl.delete(
            "tracingpoliciesnamespaced.cilium.io/perf-syscall-route",
            self.args.namespace,
            timeout=30,
        )

    def run_trial(self, workload: str, mode: str, repetition: int, sequence: int) -> None:
        trial_name = f"{workload}-r{repetition:02d}-{mode}"
        trial_dir = self.output / "raw" / f"{sequence:04d}-{trial_name}"
        trial_dir.mkdir(parents=True)
        record: dict[str, Any] = {
            "schema_version": 1,
            "trial": trial_name,
            "sequence": sequence,
            "workload": workload,
            "mode": mode,
            "repetition": repetition,
            "valid": False,
            "started_ns": time.time_ns(),
        }
        documents: list[dict[str, Any]] = []
        config: dict[str, Any] | None = None
        try:
            print(f"  switching stack to {mode}", flush=True)
            self.stack.enter(mode)
            documents, policy_image = self.render_workload(workload, mode)
            (trial_dir / "rendered.yaml").write_text(
                yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8"
            )
            config = self.configure_mode_policy(mode, workload, trial_name, policy_image)
            print(f"  deploying {workload}", flush=True)
            self.kubectl.apply_documents(documents)
            self.wait_workload(workload)
            evidence_before = self.pod_evidence()
            self.write_json(trial_dir / "pods-before.json", evidence_before)

            host, port = self.endpoint()
            record["endpoint"] = {"host": host, "node_port": port}
            print(f"  waiting for endpoint {host}:{port}", flush=True)
            self.wait_endpoint(host, port)
            print("  waiting for workload metrics", flush=True)
            self.wait_metrics_ready(evidence_before)
            print(f"  warming up {workload}", flush=True)
            self.prepare_and_warmup(workload, host, port, trial_dir)
            route_before = self.route_snapshot() if mode.startswith("sygma") else None
            if route_before:
                self.write_json(trial_dir / "routes-before.json", route_before)

            sampler = MetricsSampler(
                self.kubectl,
                self.args.namespace,
                self.args.metrics_interval,
                trial_dir / "metrics.jsonl",
            )
            command = self.load_command(workload, host, port, self.args.duration)
            record["load_command"] = command
            if workload == "mysql" and self.args.mysql_events > 0:
                measurement = f"{self.args.mysql_events} transactions"
            else:
                measurement = f"{self.args.duration}s"
            print(f"  measuring {workload} for {measurement}", flush=True)
            sampler.start()
            try:
                load_started = time.time_ns()
                load = self.commands.run(
                    command,
                    timeout=max(self.args.rollout_timeout, self.args.duration + 120),
                    cwd=trial_dir,
                )
                load_finished = time.time_ns()
            finally:
                sampler.stop()
            (trial_dir / "load.stdout.log").write_text(load.stdout, encoding="utf-8")
            (trial_dir / "load.stderr.log").write_text(load.stderr, encoding="utf-8")
            load_result = self.parse_load(workload, load.stdout, load.stderr)
            load_result["wall_seconds"] = (load_finished - load_started) / 1e9
            record["performance"] = load_result

            resources = summarize_metric_samples(sampler.samples)
            record["resources"] = resources
            workload_samples = resources.get("scopes", {}).get("workload", {}).get("samples", 0)
            if workload_samples < self.args.minimum_metric_samples:
                raise EvaluationError(
                    f"only {workload_samples} workload metric samples; want {self.args.minimum_metric_samples}"
                )

            if route_before:
                route_after = self.route_snapshot()
                self.write_json(trial_dir / "routes-after.json", route_after)
                record["routes"] = route_delta(
                    route_before["counters"], route_after["counters"]
                )
                record["routes"]["per_second"] = {
                    name: record["routes"][name] / load_result["wall_seconds"]
                    for name in ROUTE_NAMES
                }
                if record["routes"]["total"] == 0:
                    raise EvaluationError("SYGMA route counters did not advance")

            evidence_after = self.pod_evidence()
            self.write_json(trial_dir / "pods-after.json", evidence_after)
            before_restarts = {
                (item["uid"], item["container"]): int(item["restart_count"])
                for item in evidence_before["containers"]
            }
            after_restarts = {
                (item["uid"], item["container"]): int(item["restart_count"])
                for item in evidence_after["containers"]
            }
            if before_restarts != after_restarts:
                raise EvaluationError("a workload container restarted during measurement")
            before_ids = {
                (item["uid"], item["container"], item["container_id"])
                for item in evidence_before["containers"]
            }
            after_ids = {
                (item["uid"], item["container"], item["container_id"])
                for item in evidence_after["containers"]
            }
            if before_ids != after_ids:
                raise EvaluationError("workload Pod/container identity changed during measurement")
            record["pod_evidence"] = evidence_after

            requests = int(load_result.get("requests", load_result.get("transactions", 0)))
            errors = int(load_result.get("errors", 0))
            error_rate = errors / requests if requests else 1.0
            record["error_rate"] = error_rate
            if error_rate > self.args.max_error_rate:
                raise EvaluationError(
                    f"error rate {error_rate:.6f} exceeds {self.args.max_error_rate:.6f}"
                )
            record["valid"] = True
        except Exception as error:
            record["invalid_reason"] = str(error)
            record["traceback"] = traceback.format_exc()
        finally:
            record["finished_ns"] = time.time_ns()
            try:
                self.teardown(documents, config)
            except Exception as cleanup_error:
                record["cleanup_error"] = str(cleanup_error)
                record["valid"] = False
            self.write_json(trial_dir / "trial.json", record)
            self.append_trial(record)

        if not record["valid"] and not self.args.continue_on_error:
            raise EvaluationError(f"trial {trial_name} invalid: {record.get('invalid_reason')}")
        if self.args.cooldown:
            time.sleep(self.args.cooldown)

    def trial_plan(self) -> list[tuple[str, str, int]]:
        plan: list[tuple[str, str, int]] = []
        for workload in self.workloads:
            for repetition in range(1, self.args.repetitions + 1):
                offset = (repetition - 1) % len(self.modes)
                order = self.modes[offset:] + self.modes[:offset]
                if self.args.randomize:
                    order = list(order)
                    random.Random(self.args.seed + repetition + WORKLOADS.index(workload) * 1000).shuffle(order)
                plan.extend((workload, mode, repetition) for mode in order)
        return plan

    def run(self) -> None:
        self.preflight()
        plan = self.trial_plan()
        self.write_json(
            self.output / "plan.json",
            [
                {"sequence": index, "workload": workload, "mode": mode, "repetition": repetition}
                for index, (workload, mode, repetition) in enumerate(plan, 1)
            ],
        )
        try:
            for sequence, (workload, mode, repetition) in enumerate(plan, 1):
                if self._interrupted:
                    raise EvaluationError("campaign interrupted")
                print(
                    f"[{sequence}/{len(plan)}] workload={workload} mode={mode} repetition={repetition}",
                    flush=True,
                )
                self.run_trial(workload, mode, repetition, sequence)
        finally:
            restore_error = None
            try:
                self.stack.restore()
            except Exception as error:
                restore_error = str(error)
                (self.output / "RESTORE_FAILED.txt").write_text(restore_error + "\n", encoding="utf-8")
            if restore_error:
                raise EvaluationError(restore_error)

        analysis = self.commands.run(
            [sys.executable, str(HERE / "analyze.py"), str(self.output)], timeout=60
        )
        print(analysis.stdout, end="")


def render_only(args: argparse.Namespace) -> int:
    commands = CommandRunner(Path(args.output_dir).resolve() / "render-commands.jsonl")
    images = dict(DEFAULT_IMAGES)
    images.update(parse_key_values(args.image, "--image"))
    selector = parse_key_values(args.node_selector, "--node-selector")
    for workload in parse_csv_choice(args.workloads, WORKLOADS, "workloads"):
        for mode in parse_csv_choice(args.modes, MODES, "modes"):
            if workload == "hotel":
                result = commands.run(
                    [
                        "helm", "template", "perf", str(args.hotel_chart),
                        "--namespace", args.namespace,
                    ],
                    timeout=60,
                )
                documents = list(yaml.safe_load_all(result.stdout))
                documents, _images, _count = patch_hotel_documents(
                    documents,
                    mode,
                    args.namespace,
                    selector,
                    images[workload],
                    target_replicas=args.target_replicas,
                    spread=args.topology == "multi",
                )
            else:
                documents = simple_workload_documents(
                    workload,
                    mode,
                    args.namespace,
                    selector,
                    images[workload],
                    target_replicas=args.target_replicas,
                    spread=args.topology == "multi",
                )
            output = yaml.safe_dump_all(documents, sort_keys=False)
            validation = commands.run(
                ["kubectl", "create", "--dry-run=client", "--validate=false", "-f", "-", "-o", "name"],
                input_text=output,
                timeout=60,
            )
            print(f"{workload}/{mode}: {len(documents)} objects")
            print(validation.stdout, end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workloads", default="all")
    parser.add_argument("--modes", default="all")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--cooldown", type=int, default=10)
    parser.add_argument("--namespace", default="sygma-perf-eval")
    parser.add_argument("--campaign-id")
    parser.add_argument("--output-dir", default=str(HERE / "results"))
    parser.add_argument("--context")
    parser.add_argument("--topology", choices=("single", "multi"), default="single")
    parser.add_argument("--workload-node")
    parser.add_argument("--node-selector", action="append", default=[])
    parser.add_argument("--target-replicas", type=int, default=1)
    parser.add_argument("--endpoint-host")
    parser.add_argument("--endpoint-timeout", type=int, default=60)
    parser.add_argument("--image", action="append", default=[])
    parser.add_argument("--hotel-chart", type=Path, default=DEFAULT_HOTEL_CHART)
    parser.add_argument("--wrk", type=Path, default=Path(shutil.which("wrk") or "/usr/local/bin/wrk"))
    parser.add_argument("--wrk2", type=Path, default=DEFAULT_WRK2)
    parser.add_argument("--http-rate", type=int, default=5000)
    parser.add_argument("--hotel-rate", type=int, default=500)
    parser.add_argument("--http-threads", type=int, default=4)
    parser.add_argument("--http-connections", type=int, default=64)
    parser.add_argument("--redis-clients", type=int, default=64)
    parser.add_argument("--redis-requests", type=int, default=5000000)
    parser.add_argument("--redis-keyspace", type=int, default=100000)
    parser.add_argument("--mysql-threads", type=int, default=16)
    parser.add_argument("--mysql-tables", type=int, default=4)
    parser.add_argument("--mysql-table-size", type=int, default=10000)
    parser.add_argument(
        "--mysql-events",
        type=int,
        default=0,
        help="fixed MySQL transaction count; zero keeps the duration-bounded run",
    )
    parser.add_argument("--metrics-interval", type=float, default=5.0)
    parser.add_argument("--minimum-metric-samples", type=int, default=3)
    parser.add_argument("--max-error-rate", type=float, default=0.0)
    parser.add_argument("--policy-timeout", type=int, default=180)
    parser.add_argument("--rollout-timeout", type=int, default=300)
    parser.add_argument("--stack-management", choices=("external", "managed"), default="external")
    parser.add_argument("--confirm-dedicated-cluster", action="store_true")
    parser.add_argument("--tetragon-daemonset", default="kube-system/tetragon")
    parser.add_argument("--tetragon-operator-deployment", default="kube-system/tetragon-operator")
    parser.add_argument("--sygma-core-daemonset", default="default/core")
    parser.add_argument("--sygma-operator-deployment", default="default/sygma-config-operator")
    parser.add_argument("--sygma-redis-deployment", default="default/sygma-policy-redis")
    parser.add_argument("--allow-shared-sygma", action="store_true")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--randomize", action="store_true")
    parser.add_argument("--seed", type=int, default=20260817)
    parser.add_argument("--render-only", action="store_true")
    return parser


def positive(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    for name in (
        "repetitions", "duration", "warmup", "redis_requests", "redis_keyspace",
        "mysql_threads", "mysql_tables", "mysql_table_size", "policy_timeout", "rollout_timeout",
        "target_replicas", "endpoint_timeout",
    ):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if args.metrics_interval <= 0 or args.minimum_metric_samples <= 0:
        parser.error("metrics interval/sample count must be positive")
    if args.mysql_events < 0:
        parser.error("--mysql-events must be zero or positive")
    if args.max_error_rate < 0 or args.max_error_rate > 1:
        parser.error("--max-error-rate must be between 0 and 1")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    positive(parser, args)
    if args.render_only:
        return render_only(args)
    campaign = Campaign(args)

    def interrupt(_signum: int, _frame: Any) -> None:
        campaign._interrupted = True

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    campaign.run()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvaluationError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
