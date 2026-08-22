#!/usr/bin/env python3
"""Pure helpers for the SYGMA performance campaign."""

from __future__ import annotations

import math
import re
import statistics
from typing import Any, Iterable, Mapping


MODES = ("default", "tetragon", "sygma", "sygma-all-trace")
WORKLOADS = ("nginx", "httpd", "redis", "mysql", "hotel")

DEFAULT_IMAGES = {
    "nginx": "nginx:1.24.0",
    "httpd": "httpd:2.4.39",
    "redis": "redis:4.0.2",
    "mysql": "mysql:8.3.0",
    "hotel": "docker.io/deathstarbench/hotel-reservation:latest",
}

DEFAULT_PORTS = {
    "nginx": 80,
    "httpd": 80,
    "redis": 6379,
    "mysql": 3306,
    "hotel": 5000,
}

HOTEL_APPLICATION_BINARIES = frozenset({
    "frontend",
    "geo",
    "profile",
    "rate",
    "recommendation",
    "reservation",
    "search",
    "user",
})


class EvaluationError(RuntimeError):
    pass


def mode_annotations(mode: str) -> dict[str, str]:
    if mode == "sygma":
        return {
            "sygma.io/mode": "enforcement",
            "sygma.io/seccomp-routing": "selective",
        }
    if mode == "sygma-all-trace":
        return {
            "sygma.io/mode": "enforcement",
            "sygma.io/seccomp-routing": "all-trace",
        }
    if mode in ("default", "tetragon"):
        return {}
    raise EvaluationError(f"unsupported mode: {mode}")


def target_labels(workload: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/name": f"sygma-perf-{workload}",
        "app.kubernetes.io/instance": "sygma-perf",
        "perf.sygma.io/target": "true",
        "perf.sygma.io/workload": workload,
    }


def simple_workload_documents(
    workload: str,
    mode: str,
    namespace: str,
    node_selector: Mapping[str, str],
    image: str,
    target_replicas: int = 1,
    spread: bool = False,
) -> list[dict[str, Any]]:
    if workload not in ("nginx", "httpd", "redis", "mysql"):
        raise EvaluationError(f"not a simple workload: {workload}")

    port = DEFAULT_PORTS[workload]
    labels = target_labels(workload)
    container: dict[str, Any] = {
        "name": workload,
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "ports": [{"name": "service", "containerPort": port}],
    }
    if workload in ("nginx", "httpd"):
        container["readinessProbe"] = {
            "httpGet": {"path": "/", "port": "service"},
            "initialDelaySeconds": 1,
            "periodSeconds": 2,
            "failureThreshold": 30,
        }
    elif workload == "redis":
        container["readinessProbe"] = {
            "exec": {"command": ["redis-cli", "ping"]},
            "initialDelaySeconds": 1,
            "periodSeconds": 2,
            "failureThreshold": 30,
        }
    else:
        container["env"] = [
            {"name": "MYSQL_ROOT_PASSWORD", "value": "sygma-perf-root"},
            {"name": "MYSQL_DATABASE", "value": "sbtest"},
        ]
        container["readinessProbe"] = {
            "exec": {
                "command": [
                    "mysqladmin",
                    "ping",
                    "-h",
                    "127.0.0.1",
                    "-uroot",
                    "-psygma-perf-root",
                    "--silent",
                ]
            },
            "initialDelaySeconds": 5,
            "periodSeconds": 3,
            "failureThreshold": 60,
        }
        container["volumeMounts"] = [{"name": "mysql-data", "mountPath": "/var/lib/mysql"}]

    pod_spec: dict[str, Any] = {
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 10,
        "securityContext": {"seccompProfile": {"type": "Unconfined"}},
        "containers": [container],
    }
    if node_selector:
        pod_spec["nodeSelector"] = dict(node_selector)
    if spread and target_replicas > 1:
        pod_spec["topologySpreadConstraints"] = [
            {
                "maxSkew": 1,
                "topologyKey": "kubernetes.io/hostname",
                "whenUnsatisfiable": "ScheduleAnyway",
                "labelSelector": {"matchLabels": labels},
            }
        ]
    if workload == "mysql":
        pod_spec["volumes"] = [{"name": "mysql-data", "emptyDir": {}}]

    template_metadata: dict[str, Any] = {"labels": labels}
    annotations = mode_annotations(mode)
    if annotations:
        template_metadata["annotations"] = annotations

    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": f"perf-{workload}",
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "replicas": target_replicas,
            "selector": {"matchLabels": labels},
            "strategy": {"type": "Recreate"},
            "template": {"metadata": template_metadata, "spec": pod_spec},
        },
    }
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "perf-endpoint",
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "type": "NodePort",
            "selector": labels,
            "ports": [{"name": "service", "port": port, "targetPort": "service"}],
        },
    }
    return [deployment, service]


def patch_hotel_documents(
    documents: Iterable[dict[str, Any]],
    mode: str,
    namespace: str,
    node_selector: Mapping[str, str],
    application_image: str,
    target_replicas: int = 1,
    spread: bool = False,
) -> tuple[list[dict[str, Any]], set[str], int]:
    """Patch a local DeathStarBench Helm render for a fair campaign.

    All Hotel Reservation pods are included in resource accounting. Only the
    eight application microservices using deathstarbench/hotel-reservation are
    tagged as syscall-policy targets; backing stores and tracing are not.
    """

    output: list[dict[str, Any]] = []
    target_images: set[str] = set()
    target_deployments = 0
    annotations = mode_annotations(mode)

    for original in documents:
        if not isinstance(original, dict) or not original:
            continue
        document = original
        metadata = document.setdefault("metadata", {})
        metadata["namespace"] = namespace
        kind = document.get("kind")

        if kind == "Deployment":
            template = document.setdefault("spec", {}).setdefault("template", {})
            pod_metadata = template.setdefault("metadata", {})
            pod_labels = pod_metadata.setdefault("labels", {})
            pod_labels["perf.sygma.io/workload"] = "hotel"
            pod_spec = template.setdefault("spec", {})
            pod_spec.setdefault("securityContext", {})["seccompProfile"] = {
                "type": "Unconfined"
            }
            if node_selector:
                merged = dict(pod_spec.get("nodeSelector") or {})
                merged.update(node_selector)
                pod_spec["nodeSelector"] = merged

            is_target = False
            for container in pod_spec.get("containers") or []:
                current_image = str(container.get("image") or "")
                if "deathstarbench/hotel-reservation:" in current_image or \
                        "deathstarbench/hotel-reservation@" in current_image:
                    container["image"] = application_image
                    current_image = application_image
                    is_target = True
                    target_images.add(current_image)
                    # The current Helm chart still emits paths such as
                    # ``./frontend``, while the published multi-service image
                    # installs the binaries below /go/bin.  Keep the rewrite
                    # restricted to the eight application containers so the
                    # backing stores retain their original entrypoints.
                    command = container.get("command")
                    if isinstance(command, list) and command:
                        match = re.fullmatch(r"\./([a-z-]+)", str(command[0]))
                        if match and match.group(1) in HOTEL_APPLICATION_BINARIES:
                            command[0] = f"/go/bin/{match.group(1)}"
                    # The image WORKDIR is /workspace and every service opens
                    # "config.json" relative to that directory.  A relative
                    # Kubernetes mountPath is materialized as /config.json,
                    # leaving the stale image-baked /workspace/config.json in
                    # use.  Mount the rendered Helm configuration where the
                    # application actually reads it.
                    for mount in container.get("volumeMounts") or []:
                        if mount.get("mountPath") == "config.json":
                            mount["mountPath"] = "/workspace/config.json"
                container["imagePullPolicy"] = "IfNotPresent"

            if is_target:
                target_deployments += 1
                document["spec"]["replicas"] = target_replicas
                pod_labels["perf.sygma.io/target"] = "true"
                if annotations:
                    pod_metadata.setdefault("annotations", {}).update(annotations)
                if spread and target_replicas > 1:
                    pod_spec["topologySpreadConstraints"] = [
                        {
                            "maxSkew": 1,
                            "topologyKey": "kubernetes.io/hostname",
                            "whenUnsatisfiable": "ScheduleAnyway",
                            "labelSelector": {
                                "matchLabels": {
                                    "perf.sygma.io/target": "true",
                                    "perf.sygma.io/workload": "hotel",
                                }
                            },
                        }
                    ]

        elif kind == "Service" and str(metadata.get("name", "")).startswith("frontend-"):
            document.setdefault("spec", {})["type"] = "NodePort"
            metadata["name"] = "perf-endpoint"

        output.append(document)

    if target_deployments < 8:
        raise EvaluationError(
            f"Hotel render exposed only {target_deployments} application deployments; want at least 8"
        )
    if target_images != {application_image}:
        raise EvaluationError(f"Hotel target image mismatch: {sorted(target_images)}")
    if sum(1 for item in output if item.get("kind") == "Service" and
           item.get("metadata", {}).get("name") == "perf-endpoint") != 1:
        raise EvaluationError("Hotel render did not contain exactly one frontend endpoint")
    return output, target_images, target_deployments


def tetragon_policy(namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicyNamespaced",
        "metadata": {"name": "perf-syscall-route", "namespace": namespace},
        "spec": {
            "podSelector": {"matchLabels": {"perf.sygma.io/target": "true"}},
            "tracepoints": [
                {
                    "subsystem": "raw_syscalls",
                    "event": "sys_enter",
                    "args": [{"index": 4, "type": "int64"}],
                    "selectors": [
                        {
                            "matchActions": [
                                {
                                    "action": "Post",
                                    "rateLimit": "1m",
                                    "rateLimitScope": "process",
                                }
                            ]
                        }
                    ],
                }
            ],
        },
    }


def sygma_allow_all_config(
    namespace: str,
    name: str,
    image: str,
    probe_command: Iterable[str] | None = None,
) -> dict[str, Any]:
    # The embedded Pod is configuration input only; the operator does not
    # create it in evaluation allowAll mode.
    command_yaml = ""
    if probe_command:
        command_yaml = "    command:\n" + "".join(
            f"    - {json_scalar}\n"
            for json_scalar in (repr(str(item)) for item in probe_command)
        )
    yaml_content = (
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        f"  name: {name}-image-input\n"
        "spec:\n"
        "  containers:\n"
        "  - name: target\n"
        f"    image: {image}\n"
        f"{command_yaml}"
    )
    return {
        "apiVersion": "security.security.io/v1",
        "kind": "SYGMAConfig",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "collection": {"yamlContent": yaml_content},
            "policy": {"allowAll": True},
        },
    }


_QUANTITY = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([a-zA-Z]*)$")


def cpu_to_millicores(value: str) -> float:
    match = _QUANTITY.fullmatch(value.strip())
    if not match:
        raise EvaluationError(f"invalid CPU quantity: {value!r}")
    number = float(match.group(1))
    suffix = match.group(2)
    factors = {"": 1000.0, "m": 1.0, "u": 0.001, "n": 0.000001}
    if suffix not in factors:
        raise EvaluationError(f"unsupported CPU quantity suffix: {value!r}")
    return number * factors[suffix]


def memory_to_bytes(value: str) -> float:
    match = _QUANTITY.fullmatch(value.strip())
    if not match:
        raise EvaluationError(f"invalid memory quantity: {value!r}")
    number = float(match.group(1))
    suffix = match.group(2)
    factors = {
        "": 1.0,
        "Ki": 1024.0,
        "Mi": 1024.0 ** 2,
        "Gi": 1024.0 ** 3,
        "Ti": 1024.0 ** 4,
        "K": 1000.0,
        "M": 1000.0 ** 2,
        "G": 1000.0 ** 3,
        "T": 1000.0 ** 4,
    }
    if suffix not in factors:
        raise EvaluationError(f"unsupported memory quantity suffix: {value!r}")
    return number * factors[suffix]


def latency_to_ms(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s)", value.strip())
    if not match:
        raise EvaluationError(f"invalid latency: {value!r}")
    number = float(match.group(1))
    factors = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "ms": 1.0, "s": 1000.0}
    return number * factors[match.group(2)]


def duration_to_seconds(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(us|µs|ms|s|m|h)", value.strip())
    if not match:
        raise EvaluationError(f"invalid duration: {value!r}")
    number = float(match.group(1))
    factors = {"us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0}
    return number * factors[match.group(2)]


def parse_wrk_output(text: str) -> dict[str, Any]:
    throughput = re.search(r"Requests/sec:\s*([0-9.]+)", text)
    completed = re.search(r"([0-9]+) requests in ([0-9.]+)([a-zµ]+)", text)
    if not throughput or not completed:
        raise EvaluationError("wrk output lacks throughput or completed-request summary")
    duration_seconds = duration_to_seconds(completed.group(2) + completed.group(3))
    result: dict[str, Any] = {
        "throughput_ops_per_sec": float(throughput.group(1)),
        "requests": int(completed.group(1)),
        "duration_seconds": duration_seconds,
    }

    latency_line = re.search(r"^\s*Latency\s+([^\s]+)", text, re.MULTILINE)
    if latency_line:
        result["latency_avg_ms"] = latency_to_ms(latency_line.group(1))
    for percentile, key in (("50", "p50"), ("75", "p75"), ("90", "p90"),
                            ("95", "p95"), ("99", "p99")):
        # wrk prints 50%, while wrk2's corrected-coordinated-omission table
        # prints 50.000%. Accept both without accidentally matching 99.900%.
        match = re.search(
            rf"^\s*{percentile}(?:\.0+)?%\s+([^\s]+)", text, re.MULTILINE
        )
        if match:
            result[f"latency_{key}_ms"] = latency_to_ms(match.group(1))

    errors = 0
    socket_errors = re.search(
        r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", text
    )
    if socket_errors:
        errors += sum(int(value) for value in socket_errors.groups())
    non_2xx = re.search(r"Non-2xx or 3xx responses: (\d+)", text)
    if non_2xx:
        errors += int(non_2xx.group(1))
    result["errors"] = errors
    return result


def parse_sysbench_output(text: str) -> dict[str, Any]:
    transactions = re.search(r"transactions:\s+(\d+)\s+\(([0-9.]+) per sec\.\)", text)
    queries = re.search(r"queries:\s+(\d+)\s+\(([0-9.]+) per sec\.\)", text)
    total_time = re.search(r"total time:\s+([0-9.]+)s", text)
    if not transactions or not total_time:
        raise EvaluationError("sysbench output lacks transaction summary")
    result: dict[str, Any] = {
        "throughput_ops_per_sec": float(transactions.group(2)),
        "transactions": int(transactions.group(1)),
        "duration_seconds": float(total_time.group(1)),
        "errors": 0,
    }
    if queries:
        result["queries"] = int(queries.group(1))
        result["queries_per_sec"] = float(queries.group(2))
    latency_block = re.search(
        r"Latency \(ms\):\s+min:\s+([0-9.]+)\s+avg:\s+([0-9.]+)\s+max:\s+([0-9.]+)\s+95th percentile:\s+([0-9.]+)",
        text,
        re.MULTILINE,
    )
    if latency_block:
        result.update(
            {
                "latency_min_ms": float(latency_block.group(1)),
                "latency_avg_ms": float(latency_block.group(2)),
                "latency_max_ms": float(latency_block.group(3)),
                "latency_p95_ms": float(latency_block.group(4)),
            }
        )
    ignored = re.search(r"ignored errors:\s+(\d+)", text)
    if ignored:
        result["errors"] = int(ignored.group(1))
    return result


def parse_redis_output(text: str) -> dict[str, Any]:
    sections = re.split(r"^======\s+([^=]+?)\s+======\s*$", text, flags=re.MULTILINE)
    operations: dict[str, dict[str, Any]] = {}
    for index in range(1, len(sections), 2):
        name = sections[index].strip().lower()
        body = sections[index + 1]
        completed = re.search(r"(\d+) requests completed in ([0-9.]+) seconds", body)
        throughput = re.search(r"throughput summary:\s*([0-9.]+) requests per second", body)
        if not throughput:
            throughput = re.search(r"([0-9.]+) requests per second", body)
        if not completed or not throughput:
            continue
        operation: dict[str, Any] = {
            "requests": int(completed.group(1)),
            "duration_seconds": float(completed.group(2)),
            "throughput_ops_per_sec": float(throughput.group(1)),
        }
        header = re.search(r"avg\s+min\s+p50\s+p95\s+p99\s+max\s*\n\s*([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)", body)
        if header:
            for key, value in zip(("avg", "min", "p50", "p95", "p99", "max"), header.groups()):
                operation[f"latency_{key}_ms"] = float(value)
        operations[name] = operation

    if not operations:
        raise EvaluationError("redis-benchmark output lacks parsed operation sections")
    total_requests = sum(item["requests"] for item in operations.values())
    total_duration = sum(item["duration_seconds"] for item in operations.values())
    result: dict[str, Any] = {
        "throughput_ops_per_sec": total_requests / total_duration,
        "requests": total_requests,
        "duration_seconds": total_duration,
        # With redis-benchmark -e, any printed server error invalidates the
        # default zero-error trial even though the tool rate-limits messages.
        "errors": len(re.findall(r"(?:error from server|server error)", text, re.IGNORECASE)),
        "operations": operations,
    }
    for key in ("avg", "p50", "p95", "p99", "max"):
        values = [item[f"latency_{key}_ms"] for item in operations.values()
                  if f"latency_{key}_ms" in item]
        if values:
            result[f"latency_{key}_ms"] = max(values) if key in ("p95", "p99", "max") else statistics.mean(values)
    return result


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(quantile * len(ordered)) - 1))
    return ordered[index]


def summarize_metric_samples(samples: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    per_timestamp: dict[tuple[str, int], dict[str, float]] = {}
    failures = 0
    for sample in samples:
        if sample.get("error"):
            failures += 1
            continue
        scope = str(sample["scope"])
        timestamp = int(sample["timestamp_ns"])
        aggregate = per_timestamp.setdefault((scope, timestamp), {"cpu": 0.0, "memory": 0.0})
        aggregate["cpu"] += float(sample.get("cpu_millicores", 0.0))
        aggregate["memory"] += float(sample.get("memory_bytes", 0.0))

    scopes: dict[str, Any] = {}
    names = sorted({scope for scope, _timestamp in per_timestamp})
    for scope in names:
        rows = [value for (row_scope, _), value in per_timestamp.items() if row_scope == scope]
        cpu = [row["cpu"] for row in rows]
        memory = [row["memory"] for row in rows]
        scopes[scope] = {
            "samples": len(rows),
            "cpu_millicores_mean": statistics.mean(cpu),
            "cpu_millicores_p95": percentile(cpu, 0.95),
            "cpu_millicores_max": max(cpu),
            "memory_bytes_mean": statistics.mean(memory),
            "memory_bytes_p95": percentile(memory, 0.95),
            "memory_bytes_max": max(memory),
        }
    return {"sample_failures": failures, "scopes": scopes}


def route_delta(before: Mapping[str, int], after: Mapping[str, int]) -> dict[str, int]:
    expected = {"conventional_sigkill", "lsm_bpf", "ptrace_notify"}
    if set(before) != expected or set(after) != expected:
        raise EvaluationError("route snapshot has unexpected keys")
    result: dict[str, int] = {}
    for name in sorted(expected):
        delta = int(after[name]) - int(before[name])
        if delta < 0:
            raise EvaluationError(f"route counter {name} decreased")
        result[name] = delta
    result["total"] = sum(result.values())
    return result
