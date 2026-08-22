#!/usr/bin/env python3
"""Run the SYGMA prestart-barrier vs Tetragon async-enrollment experiment.

The policy is installed before any measured Pod. Tetragon readiness is the
target cgroup's insertion into the policy-filter inner map, observed from the
same node with CLOCK_BOOTTIME. Both arms are observation-only. A neutral eBPF
counter records every syscall made by the real application executable and its
descendants; the launcher and image entrypoint are excluded.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import random
import re
import select
import shutil
import subprocess
import sys
import threading
import time
import traceback
from typing import Any, Iterable, Mapping, Sequence


EVAL_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = EVAL_ROOT.parents[1]
DEFAULT_NAMESPACE = "sygma-gap-eval"
POLICY_NAME = "observe-application-syscalls"
IMAGE_ALIAS = "sygma-gap-probe:v1"
APPLICATIONS = (
    "nginx",
    "redis",
    "httpd",
    "mysql",
    # DeathStarBench Hotel Reservation core application microservices.
    "hotel-frontend",
    "hotel-geo",
    "hotel-profile",
    "hotel-rate",
    "hotel-recommendation",
    "hotel-reservation",
    "hotel-search",
    "hotel-user",
    # Google Online Boutique (microservices-demo) services.
    "boutique-ad",
    "boutique-cart",
    "boutique-checkout",
    "boutique-currency",
    "boutique-email",
    "boutique-frontend",
    "boutique-payment",
    "boutique-productcatalog",
    "boutique-recommendation",
    "boutique-shipping",
    # DeathStarBench Hotel Reservation supporting infrastructure and Online
    # Boutique's redis-cart -- every remaining container in either
    # benchmark, not only the ones carrying custom application code.
    "hotel-consul",
    "hotel-jaeger",
    "hotel-mongo-geo",
    "hotel-mongo-profile",
    "hotel-mongo-rate",
    "hotel-mongo-recommendation",
    "hotel-mongo-reservation",
    "hotel-mongo-user",
    "hotel-memcached-profile",
    "hotel-memcached-rate",
    "hotel-memcached-reserve",
    "boutique-redis-cart",
)
APPLICATION_LAUNCHER = "gap-launch"
OBSERVER_NAME = "startup-gap-observer"
CLOCK_BOOTTIME = getattr(time, "CLOCK_BOOTTIME", 7)
EXPERIMENT_PART_OF_LABEL = "sygma-startup-gap-eval"
PROTOCOL_SCHEMA_VERSION = 4
HOOK_TIMELINE_SCHEMA_VERSION = 3
TIMELINE_PRESTART_ANNOTATION = "gap.sygma.io/prestart-timeline"
SHA256_DIGEST_RE = re.compile(r"sha256:([0-9a-fA-F]{64})(?:$|[^0-9a-fA-F])")
PINNED_IMAGE_RE = re.compile(r"@sha256:([0-9a-fA-F]{64})$")


def image_alias_for_application(application: str) -> str:
    if application == "synthetic":
        return IMAGE_ALIAS
    if application not in APPLICATIONS:
        raise ExperimentError(f"unsupported application profile: {application}")
    return f"sygma-gap-{application}:v1"


def policy_binary_for_application(application: str) -> str:
    return "gap-probe" if application == "synthetic" else APPLICATION_LAUNCHER


def policy_binary_path_for_application(application: str) -> str:
    return (
        "/opt/eval/gap-probe"
        if application == "synthetic"
        else "/opt/gap/gap-launch"
    )

# Maps shared by the historical legacy sequence engine and the current typed
# observation engine. The hook synchronously opens each of these while setting
# up policy observation, so a missing pin cannot produce a valid trial.
# Kept in sync with the maps sygma_eBPF/monitoring.c actually declares
# SEC(".maps") plus the subset ocihook/ebpf/hook's cleanupEBPFMaps touches.
# Corrected 2026-08-20: container_info_map, main_process_map, ns_image_map,
# and syscall_stats no longer exist in the audited typed core -- they were
# names from an earlier generation and are actively unpinned as legacy debris
# by main.go's migratePinnedState/legacyPinnedMapNames on startup, not
# recreated. observed_misses was renamed to observed_transition_map (same
# struct observed_transition_key: 5x u32 = 20-byte key, u32 = 4-byte value;
# see MATCHED_STACK_ROLLOUT.md's description of the phase-1 miss-count proof,
# which this map is what actually implements today).
SYGMA_LEGACY_REQUIRED_PINNED_MAPS = (
    "/sys/fs/bpf/sygma/syscall_graph_map",
    "/sys/fs/bpf/sygma/execution_time_map",
    "/sys/fs/bpf/sygma/pid_mount_ns_map",
    "/sys/fs/bpf/sygma/process_state_map",
    "/sys/fs/bpf/sygma/tid_to_namespace",
    # cleanupEBPFMaps treats these as required for policy-observation trials;
    # omitting one prevents the poststop cleanup-complete validity gate.
    "/sys/fs/bpf/sygma/collection_mode_map",
    "/sys/fs/bpf/sygma/collection_graph_map",
    "/sys/fs/bpf/sygma/transition_check_count",
    "/sys/fs/bpf/sygma/blocked_history",
    "/sys/fs/bpf/sygma/observed_transition_map",
)

# installTypedMainPolicy can safely fall back for a sequence policy only when
# this entire capability is absent. A partially deployed set is a broken ABI,
# not a legacy installation.
# Corrected 2026-08-20: policy_location_transition_map and policy_decision_map
# do not exist in the audited typed core or in the hook's typed-policy write
# path (installTypedMainPolicy in ocihook/ebpf/hook/main.go only opens
# policy_config_map, policy_state_rule_map, and policy_state_transition_map);
# they were speculative/removed map names, never a deployed capability.
SYGMA_TYPED_POLICY_PINNED_MAPS = (
    "/sys/fs/bpf/sygma/policy_config_map",
    "/sys/fs/bpf/sygma/policy_state_rule_map",
    "/sys/fs/bpf/sygma/policy_state_transition_map",
)

# Critical layout contracts shared by the current hook and BPF core.  Map IDs
# and capacity are recorded for provenance but are intentionally not fixed;
# key/value sizes and type are the ABI that userspace serializes directly.
SYGMA_COMMON_MAP_ABI = {
    "/sys/fs/bpf/sygma/syscall_graph_map": {
        "map_type": 1,  # BPF_MAP_TYPE_HASH
        "key_size": 16,
        "value_size": 45,
    },
    "/sys/fs/bpf/sygma/blocked_history": {
        "map_type": 1,
        "key_size": 20,
        "value_size": 4,
    },
    "/sys/fs/bpf/sygma/observed_transition_map": {
        "map_type": 1,
        "key_size": 20,
        "value_size": 4,
    },
}
SYGMA_TYPED_MAP_ABI = {
    "/sys/fs/bpf/sygma/process_state_map": {
        "map_type": 1,
        "key_size": 4,
        # struct process_state in sygma_eBPF/monitoring.c is 7 x __u32 = 28
        # bytes (prev_syscall, current_syscall, image_id, saved_prev_syscall,
        # in_signal_handler, policy_state, policy_initialized). Corrected
        # 2026-08-20 from a stale 32-byte expectation; see the note above
        # SYGMA_LEGACY_REQUIRED_PINNED_MAPS for the broader map-ABI audit.
        "value_size": 28,
    },
    "/sys/fs/bpf/sygma/policy_config_map": {
        "map_type": 1,
        "key_size": 8,
        "value_size": 8,
    },
    "/sys/fs/bpf/sygma/policy_state_rule_map": {
        "map_type": 1,
        "key_size": 12,
        "value_size": 45,
    },
    "/sys/fs/bpf/sygma/policy_state_transition_map": {
        "map_type": 1,
        "key_size": 16,
        "value_size": 4,
    },
}
SYGMA_LEGACY_PROCESS_STATE_ABI = {
    "map_type": 1,
    "key_size": 4,
    "value_size": 20,
}

# The neutral, third-party application-syscall observer (see the note above
# SYGMA_LEGACY_REQUIRED_PINNED_MAPS). Added 2026-08-20 alongside
# sygma_eBPF/monitoring.c's app_cgroups/app_tids/app_sc_bins/app_sc_counts/
# app_sc_meta maps and the handle_app_syscall_enter raw_tracepoint/sys_enter
# program that populates them.
APPLICATION_SYSCALL_PINNED_MAPS = (
    "/sys/fs/bpf/sygma/app_cgroups",
    "/sys/fs/bpf/sygma/app_tids",
    "/sys/fs/bpf/sygma/app_sc_bins",
    "/sys/fs/bpf/sygma/app_sc_counts",
    "/sys/fs/bpf/sygma/app_sc_first_seen",
    "/sys/fs/bpf/sygma/app_sc_meta",
)
APPLICATION_SYSCALL_MAP_ABI = {
    "/sys/fs/bpf/sygma/app_cgroups": {
        "map_type": 1,
        "key_size": 8,
        "value_size": 4,
    },
    "/sys/fs/bpf/sygma/app_tids": {
        "map_type": 1,
        "key_size": 4,
        "value_size": 8,
    },
    "/sys/fs/bpf/sygma/app_sc_bins": {
        "map_type": 1,
        "key_size": 16,
        "value_size": 8,
    },
    "/sys/fs/bpf/sygma/app_sc_counts": {
        "map_type": 1,
        "key_size": 16,
        "value_size": 8,
    },
    "/sys/fs/bpf/sygma/app_sc_first_seen": {
        "map_type": 1,
        "key_size": 16,
        "value_size": 8,
    },
    "/sys/fs/bpf/sygma/app_sc_meta": {
        "map_type": 1,
        "key_size": 8,
        "value_size": 32,
    },
}

# Online Boutique services that check a peer address env var for presence
# (not connectivity) at startup and exit immediately if it is absent. Values
# copied verbatim from microservices-demo's release/kubernetes-manifests.yaml
# so service:port pairs match the real peer Deployments/Services applied
# once to the sygma-gap-eval namespace (see README.md). ENABLE_TRACING is
# left unset, so COLLECTOR_SERVICE_ADDR (checkoutservice, frontend) is never
# read; SHOPPING_ASSISTANT_SERVICE_ADDR (frontend) is read but never dialed
# outside that service's dedicated request path, so it is not deployed here.
BOUTIQUE_PEER_ADDRESS_ENV: dict[str, dict[str, str]] = {
    "boutique-checkout": {
        "PRODUCT_CATALOG_SERVICE_ADDR": "productcatalogservice:3550",
        "SHIPPING_SERVICE_ADDR": "shippingservice:50051",
        "PAYMENT_SERVICE_ADDR": "paymentservice:50051",
        "EMAIL_SERVICE_ADDR": "emailservice:5000",
        "CURRENCY_SERVICE_ADDR": "currencyservice:7000",
        "CART_SERVICE_ADDR": "cartservice:7070",
    },
    "boutique-recommendation": {
        "PRODUCT_CATALOG_SERVICE_ADDR": "productcatalogservice:3550",
    },
    "boutique-frontend": {
        "PRODUCT_CATALOG_SERVICE_ADDR": "productcatalogservice:3550",
        "CURRENCY_SERVICE_ADDR": "currencyservice:7000",
        "CART_SERVICE_ADDR": "cartservice:7070",
        "RECOMMENDATION_SERVICE_ADDR": "recommendationservice:8080",
        "SHIPPING_SERVICE_ADDR": "shippingservice:50051",
        "CHECKOUT_SERVICE_ADDR": "checkoutservice:5050",
        "AD_SERVICE_ADDR": "adservice:9555",
        "SHOPPING_ASSISTANT_SERVICE_ADDR": "shoppingassistantservice:80",
    },
    "boutique-payment": {
        "PORT": "50051",
    },
    "boutique-currency": {
        "PORT": "7000",
    },
}


class ExperimentError(RuntimeError):
    pass


def clock_pair() -> dict[str, int]:
    return {
        "realtime_ns": time.time_ns(),
        "boottime_ns": time.clock_gettime_ns(CLOCK_BOOTTIME),
    }


def utc_run_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def json_line(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n"


def read_json_lines(path: pathlib.Path) -> list[dict[str, Any]]:
    ret: list[dict[str, Any]] = []
    if not path.exists():
        return ret
    for raw in path.read_text(errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            ret.append(value)
    return ret


def read_json_lines_checked(
    path: pathlib.Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    if not path.exists():
        return events, [f"missing_jsonl_{path.name}"]
    for line_number, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            errors.append(f"malformed_json_{path.name}_line_{line_number}")
            continue
        if not isinstance(value, dict):
            errors.append(f"non_object_json_{path.name}_line_{line_number}")
            continue
        events.append(value)
    return events, errors


def strip_runtime_prefix(container_id: str) -> str:
    return container_id.split("://", 1)[-1] if container_id else ""


def normalize_container_started_time(value: Any) -> str | None:
    """Return None for Kubernetes' serialized zero-time sentinels."""

    if value is None:
        return None
    text = str(value).strip()
    if not text or text.startswith(("1970-01-01T00:00:00", "0001-01-01T00:00:00")):
        return None
    return text


def image_sha256_digest(image_reference: str) -> str | None:
    """Return a canonical sha256 digest from an image reference or imageID."""

    match = SHA256_DIGEST_RE.search(str(image_reference).strip())
    return f"sha256:{match.group(1).lower()}" if match else None


def pinned_image_reference_digest(image_reference: str) -> str | None:
    match = PINNED_IMAGE_RE.search(str(image_reference).strip())
    return f"sha256:{match.group(1).lower()}" if match else None


def validate_carrier_image_policy(args: argparse.Namespace) -> dict[str, Any]:
    """Make workload and observer images immutable and pull-free."""

    digest = pinned_image_reference_digest(args.carrier_image)
    observer_image = str(
        getattr(args, "observer_image", None) or args.carrier_image
    )
    observer_digest = pinned_image_reference_digest(observer_image)
    diagnostic = bool(getattr(args, "diagnostic_skip_sygma_canary", False))
    problems: list[str] = []
    if digest is None:
        problems.append("workload image is not pinned by sha256 digest")
    if observer_digest is None:
        problems.append("observer image is not pinned by sha256 digest")
    if args.image_pull_policy != "Never":
        problems.append("imagePullPolicy is not Never")
    if problems and not diagnostic:
        raise ExperimentError(
            "primary startup-gap experiment requires an immutable "
            "IMAGE@sha256 digest already cached on the node and "
            "--image-pull-policy Never: " + "; ".join(problems)
        )
    return {
        "requested_reference": args.carrier_image,
        "requested_digest": digest,
        "application": getattr(args, "application", "synthetic"),
        "observer_reference": observer_image,
        "observer_digest": observer_digest,
        "image_pull_policy": args.image_pull_policy,
        "publication_eligible": not problems,
        "diagnostic_override": diagnostic and bool(problems),
        "problems": problems,
    }


class Commands:
    def __init__(self, result_dir: pathlib.Path, kubectl: str) -> None:
        self.result_dir = result_dir
        self.kubectl = kubectl
        self.log_path = result_dir / "commands.jsonl"

    def run(
        self,
        argv: Iterable[str],
        *,
        input_text: str | None = None,
        timeout: float = 60,
        check: bool = True,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        args = [str(x) for x in argv]
        started = clock_pair()
        try:
            cp = subprocess.run(
                args,
                input=input_text,
                text=True,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            ended = clock_pair()
            self._log(args, started, ended, None, "timeout")
            raise ExperimentError(f"command timed out after {timeout}s: {args}") from exc
        ended = clock_pair()
        self._log(args, started, ended, cp.returncode, None)
        if check and cp.returncode != 0:
            stderr = (cp.stderr or "").strip()
            stdout = (cp.stdout or "").strip()
            raise ExperimentError(
                f"command failed ({cp.returncode}): {' '.join(args)}\n"
                f"stdout: {stdout[-2000:]}\nstderr: {stderr[-4000:]}"
            )
        return cp

    def _log(
        self,
        args: list[str],
        started: dict[str, int],
        ended: dict[str, int],
        returncode: int | None,
        error: str | None,
    ) -> None:
        record = {
            "argv": args,
            "start_realtime_ns": started["realtime_ns"],
            "start_boottime_ns": started["boottime_ns"],
            "end_realtime_ns": ended["realtime_ns"],
            "end_boottime_ns": ended["boottime_ns"],
            "returncode": returncode,
            "error": error,
        }
        with self.log_path.open("a") as stream:
            stream.write(json_line(record))

    def kubectl_run(
        self,
        args: Iterable[str],
        *,
        obj: dict[str, Any] | None = None,
        timeout: float = 60,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            [self.kubectl, *args],
            input_text=json.dumps(obj) if obj is not None else None,
            timeout=timeout,
            check=check,
        )

    def kubectl_json(
        self,
        args: Iterable[str],
        *,
        obj: dict[str, Any] | None = None,
        timeout: float = 60,
    ) -> Any:
        cp = self.kubectl_run(args, obj=obj, timeout=timeout)
        try:
            return json.loads(cp.stdout)
        except json.JSONDecodeError as exc:
            raise ExperimentError(
                f"kubectl did not return JSON: {(cp.stdout or '')[-3000:]}"
            ) from exc

    def apply_object(self, obj: dict[str, Any], timeout: float = 60) -> Any:
        return self.kubectl_json(
            ["apply", "-f", "-", "-o", "json"], obj=obj, timeout=timeout
        )


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def source_snapshot_hash() -> str:
    digest = hashlib.sha256()
    roots = [
        EVAL_ROOT,
        REPO_ROOT / "ocihook" / "ebpf" / "hook" / "main.go",
        REPO_ROOT / "ocihook" / "ebpf" / "tracer" / "main.go",
        REPO_ROOT / "ocihook" / "ebpf" / "wrapper" / "wrapper.c",
        REPO_ROOT / "sygma_eBPF" / "main.go",
        REPO_ROOT / "sygma_eBPF" / "main_test.go",
        REPO_ROOT / "sygma_eBPF" / "monitoring.c",
        REPO_ROOT / "sygma_eBPF" / "Dockerfile.observation-eval",
    ]
    files: list[pathlib.Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in {"results", "build", "__pycache__"} for part in path.parts):
                continue
            files.append(path)
    for path in sorted(set(files)):
        rel = str(path.relative_to(REPO_ROOT))
        digest.update(rel.encode() + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def ensure_tools(args: argparse.Namespace) -> None:
    missing = [tool for tool in (args.kubectl, "gcc") if shutil.which(tool) is None]
    if missing:
        raise ExperimentError(f"missing required tools: {', '.join(missing)}")


def ensure_namespace(cmd: Commands, namespace: str) -> None:
    cmd.apply_object(
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {"app.kubernetes.io/part-of": EXPERIMENT_PART_OF_LABEL},
            },
        }
    )


def apply_binary_configmap(
    cmd: Commands, namespace: str, name: str, key: str, path: pathlib.Path
) -> None:
    if not path.is_file():
        raise ExperimentError(f"measurement binary is missing: {path}")
    if path.stat().st_size > 1024 * 1024:
        raise ExperimentError(f"binary exceeds the ConfigMap 1 MiB limit: {path}")
    generated = cmd.run(
        [
            cmd.kubectl,
            "create",
            "configmap",
            name,
            "-n",
            namespace,
            f"--from-file={key}={path}",
            "--dry-run=client",
            "-o",
            "json",
        ],
        timeout=30,
    )
    try:
        obj = json.loads(generated.stdout)
    except json.JSONDecodeError as exc:
        raise ExperimentError(f"failed to generate ConfigMap {name}") from exc
    # Client-side apply copies the entire binaryData field into the
    # last-applied annotation, which exceeds Kubernetes' 256 KiB annotation
    # limit. Use optimistic create/replace without that annotation instead.
    existing = cmd.kubectl_run(
        ["get", "configmap", name, "-n", namespace, "-o", "json"],
        timeout=20,
        check=False,
    )
    if existing.returncode == 0:
        try:
            current = json.loads(existing.stdout)
            obj.setdefault("metadata", {})["resourceVersion"] = current["metadata"][
                "resourceVersion"
            ]
        except (json.JSONDecodeError, KeyError) as exc:
            raise ExperimentError(f"could not replace ConfigMap {name}") from exc
        cmd.kubectl_json(["replace", "-f", "-", "-o", "json"], obj=obj)
    else:
        cmd.kubectl_json(["create", "-f", "-", "-o", "json"], obj=obj)


def observer_object(args: argparse.Namespace, node_name: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": OBSERVER_NAME,
            "namespace": args.namespace,
            "labels": {
                "app.kubernetes.io/name": "startup-gap-observer",
                "app.kubernetes.io/part-of": EXPERIMENT_PART_OF_LABEL,
            },
        },
        "spec": {
            "nodeName": node_name,
            "hostPID": True,
            "hostNetwork": True,
            "dnsPolicy": "ClusterFirstWithHostNet",
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 1,
            "containers": [
                {
                    "name": "observer",
                    "image": getattr(args, "observer_image", None) or args.carrier_image,
                    "imagePullPolicy": args.image_pull_policy,
                    "command": ["/bin/sh", "-c"],
                    "args": ["trap 'exit 0' TERM INT; while :; do sleep 3600; done"],
                    "securityContext": {
                        "privileged": True,
                        "runAsUser": 0,
                        "allowPrivilegeEscalation": True,
                    },
                    "volumeMounts": [
                        {"name": "mapwatch", "mountPath": "/opt/eval", "readOnly": True},
                        {"name": "host-bpf", "mountPath": "/sys/fs/bpf"},
                        {"name": "host-log", "mountPath": "/host-var-log", "readOnly": True},
                        {
                            "name": "host-bin",
                            "mountPath": "/host-usr-local-bin",
                            "readOnly": True,
                        },
                        {
                            "name": "host-opt",
                            "mountPath": "/host-opt",
                            "readOnly": True,
                        },
                    ],
                }
            ],
            "volumes": [
                {
                    "name": "mapwatch",
                    "configMap": {
                        "name": "startup-gap-mapwatch-bin",
                        "defaultMode": 365,
                    },
                },
                {
                    "name": "host-bpf",
                    "hostPath": {"path": "/sys/fs/bpf", "type": "Directory"},
                },
                {
                    "name": "host-log",
                    "hostPath": {"path": "/var/log", "type": "Directory"},
                },
                {
                    "name": "host-bin",
                    "hostPath": {"path": "/usr/local/bin", "type": "Directory"},
                },
                {
                    "name": "host-opt",
                    "hostPath": {"path": "/opt", "type": "Directory"},
                },
            ],
        },
    }


def delete_pod(cmd: Commands, namespace: str, name: str, timeout: float = 45) -> None:
    cmd.kubectl_run(
        [
            "delete",
            "pod",
            name,
            "-n",
            namespace,
            "--ignore-not-found=true",
            "--wait=true",
            f"--timeout={int(timeout)}s",
        ],
        timeout=timeout + 10,
        check=False,
    )


def wait_pod_condition(
    cmd: Commands,
    namespace: str,
    name: str,
    *,
    ready: bool = False,
    terminal: bool = False,
    timeout: float = 60,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        cp = cmd.kubectl_run(
            ["get", "pod", name, "-n", namespace, "-o", "json"],
            timeout=10,
            check=False,
        )
        if cp.returncode == 0:
            try:
                last = json.loads(cp.stdout)
            except json.JSONDecodeError:
                last = None
            if last:
                phase = last.get("status", {}).get("phase", "")
                if terminal and phase in {"Succeeded", "Failed"}:
                    return last
                if ready:
                    conditions = last.get("status", {}).get("conditions", [])
                    if any(
                        c.get("type") == "Ready" and c.get("status") == "True"
                        for c in conditions
                    ):
                        return last
        time.sleep(0.1)
    detail = last.get("status", {}) if last else "not found"
    raise ExperimentError(f"pod {namespace}/{name} did not reach requested state: {detail}")


def find_tetragon_pod(cmd: Commands, node_name: str) -> str:
    data = cmd.kubectl_json(
        [
            "get",
            "pods",
            "-n",
            "kube-system",
            "-l",
            "app.kubernetes.io/name=tetragon",
            "--field-selector=status.phase=Running",
            "-o",
            "json",
        ]
    )
    candidates = []
    for pod in data.get("items", []):
        if pod.get("metadata", {}).get("deletionTimestamp"):
            continue
        if pod.get("spec", {}).get("nodeName") != node_name:
            continue
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if any(s.get("name") == "tetragon" and s.get("ready") for s in statuses):
            candidates.append(pod["metadata"]["name"])
    if len(candidates) != 1:
        raise ExperimentError(
            f"expected one ready Tetragon agent on node {node_name}, "
            f"found {candidates}"
        )
    return candidates[0]


def find_sygma_core_container(
    cmd: Commands, node_name: str
) -> dict[str, str]:
    """Find the single ready SYGMA core container on the target node."""

    data = cmd.kubectl_json(["get", "pods", "-A", "-o", "json"])
    candidates: list[dict[str, str]] = []
    for pod in data.get("items", []):
        if pod.get("metadata", {}).get("deletionTimestamp"):
            continue
        if pod.get("spec", {}).get("nodeName") != node_name:
            continue
        statuses = {
            status.get("name"): status
            for status in pod.get("status", {}).get("containerStatuses", [])
        }
        for container in pod.get("spec", {}).get("containers", []):
            if container.get("name") != "core":
                continue
            image = str(container.get("image", ""))
            requested_digest = pinned_image_reference_digest(image)
            if requested_digest is None:
                continue
            if container.get("command") or container.get("args"):
                # The audited image contract is ENTRYPOINT=/usr/daemon/core.
                # An override makes the running executable ambiguous.
                continue
            status = statuses.get(container.get("name"), {})
            if not status.get("ready"):
                continue
            observed_digest = image_sha256_digest(str(status.get("imageID", "")))
            if observed_digest != requested_digest:
                continue
            candidates.append(
                {
                    "namespace": str(pod.get("metadata", {}).get("namespace", "")),
                    "pod": str(pod.get("metadata", {}).get("name", "")),
                    "container": str(container.get("name", "")),
                    "image": image,
                    "image_id": str(status.get("imageID", "")),
                    "image_digest": requested_digest,
                }
            )
    if len(candidates) != 1:
        raise ExperimentError(
            f"expected one ready SYGMA core container on node {node_name}, "
            f"found {candidates}"
        )
    return candidates[0]


def hash_running_sygma_core(
    cmd: Commands, core: dict[str, str]
) -> dict[str, Any]:
    cp = cmd.kubectl_run(
        [
            "exec",
            "-n",
            core["namespace"],
            core["pod"],
            "-c",
            core["container"],
            "--",
            "sha256sum",
            "/usr/daemon/core",
        ],
        timeout=30,
        check=False,
    )
    fields = (cp.stdout or "").strip().split()
    digest = fields[0].lower() if fields else ""
    valid = cp.returncode == 0 and bool(re.fullmatch(r"[0-9a-f]{64}", digest))
    return {
        **core,
        "present": valid,
        "sha256": digest if valid else None,
        "returncode": cp.returncode,
        "stderr_tail": (cp.stderr or "").strip()[-1000:],
        "path": "/usr/daemon/core",
    }


def tetragon_policy_object(namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicyNamespaced",
        "metadata": {"name": POLICY_NAME, "namespace": namespace},
        "spec": {
            "podSelector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "sygma-gap-probe",
                    "gap.sygma.io/backend": "tetragon",
                }
            },
            "containerSelector": {
                "matchExpressions": [
                    {"key": "name", "operator": "In", "values": ["probe"]}
                ]
            },
            "tracepoints": [
                {
                    "subsystem": "raw_syscalls",
                    "event": "sys_enter",
                    "args": [{"index": 4, "type": "int64"}],
                    "selectors": [
                        {
                            "matchActions": [
                                # Rate-limited Post is observation-only; the
                                # hook still covers every application syscall.
                                {
                                    "action": "Post",
                                    "rateLimit": "10s",
                                    "rateLimitScope": "process",
                                },
                            ]
                        }
                    ],
                }
            ],
        },
    }


def label_selector_matches(
    selector: dict[str, Any] | None, labels: dict[str, str]
) -> bool:
    """Evaluate the Kubernetes LabelSelector subset used by Tetragon."""

    selector = selector or {}
    for key, wanted in (selector.get("matchLabels") or {}).items():
        if labels.get(str(key)) != str(wanted):
            return False
    for expression in selector.get("matchExpressions") or []:
        key = str(expression.get("key", ""))
        operator = str(expression.get("operator", ""))
        values = {str(value) for value in expression.get("values") or []}
        present = key in labels
        if operator == "In" and (not present or labels[key] not in values):
            return False
        if operator == "NotIn" and present and labels[key] in values:
            return False
        if operator == "Exists" and not present:
            return False
        if operator == "DoesNotExist" and present:
            return False
        if operator not in {"In", "NotIn", "Exists", "DoesNotExist"}:
            return False
    return True


def verify_tetragon_policy_isolation(
    cmd: Commands, namespace: str, application: str = "synthetic"
) -> dict[str, Any]:
    """Reject pre-existing policies that select either experiment arm."""

    cluster = cmd.kubectl_json(
        ["get", "tracingpolicies.cilium.io", "-o", "json"]
    )
    namespaced = cmd.kubectl_json(
        ["get", "tracingpoliciesnamespaced.cilium.io", "-A", "-o", "json"]
    )
    policies: list[dict[str, Any]] = []
    for scope, data in (("cluster", cluster), ("namespaced", namespaced)):
        for policy in data.get("items", []):
            metadata = policy.get("metadata", {})
            if scope == "namespaced" and metadata.get("namespace") != namespace:
                continue
            if (
                scope == "namespaced"
                and metadata.get("namespace") == namespace
                and metadata.get("name") == POLICY_NAME
            ):
                continue
            policies.append({"scope": scope, "object": policy})

    matches: list[dict[str, Any]] = []
    recorded: list[dict[str, Any]] = []
    for item in policies:
        policy = item["object"]
        metadata = policy.get("metadata", {})
        spec = policy.get("spec", {})
        identity = {
            "scope": item["scope"],
            "namespace": metadata.get("namespace"),
            "name": metadata.get("name"),
            "resource_version": metadata.get("resourceVersion"),
        }
        selected_arms = []
        for backend in ("sygma", "tetragon"):
            pod_labels = {
                "app.kubernetes.io/name": "sygma-gap-probe",
                "app.kubernetes.io/part-of": EXPERIMENT_PART_OF_LABEL,
                "gap.sygma.io/backend": backend,
                "gap.sygma.io/application": application,
            }
            pod_match = label_selector_matches(spec.get("podSelector"), pod_labels)
            container_match = label_selector_matches(
                spec.get("containerSelector"), {"name": "probe"}
            )
            if pod_match and container_match:
                selected_arms.append(backend)
        record = {**identity, "selected_arms": selected_arms}
        recorded.append(record)
        if selected_arms:
            matches.append(record)
    result = {
        "application": application,
        "policies": recorded,
        "overlaps": matches,
        "valid": not matches,
    }
    if matches:
        raise ExperimentError(
            "pre-existing Tetragon policies overlap experiment Pods: "
            + json.dumps(matches, sort_keys=True, separators=(",", ":"))
        )
    return result


def parse_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        # Defensive fallback for clients that print a non-JSON banner to stdout.
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ExperimentError(f"no JSON object in output: {text[-2000:]}") from exc
        value = json.loads(text[start : end + 1])
    if not isinstance(value, dict):
        raise ExperimentError("expected a JSON object")
    return value


def list_tetragon_policies(cmd: Commands, tetragon_pod: str) -> dict[str, Any]:
    cp = cmd.kubectl_run(
        [
            "exec",
            "-n",
            "kube-system",
            tetragon_pod,
            "-c",
            "tetragon",
            "--",
            "tetra",
            "tracingpolicy",
            "list",
            "-o",
            "json",
        ],
        timeout=30,
    )
    return parse_json_object(cp.stdout)


def wait_tetragon_policy(
    cmd: Commands, tetragon_pod: str, namespace: str, timeout: float = 90
) -> tuple[int, dict[str, Any]]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = list_tetragon_policies(cmd, tetragon_pod)
        for policy in last.get("policies", []):
            if policy.get("name") != POLICY_NAME:
                continue
            pol_ns = policy.get("namespace", namespace)
            if pol_ns not in {"", namespace}:
                continue
            state = str(policy.get("state", ""))
            enabled = policy.get("enabled") is True or state.endswith("ENABLED")
            if not enabled:
                continue
            filter_id = policy.get("filter_id") or policy.get("id")
            try:
                numeric_id = int(filter_id)
            except (TypeError, ValueError):
                continue
            if numeric_id > 0:
                return numeric_id, last
        time.sleep(0.25)
    raise ExperimentError(f"Tetragon policy did not become enabled: {last}")


def verify_tetragon_mode(cmd: Commands, allow_unexpected: bool) -> dict[str, Any]:
    config = cmd.kubectl_json(
        ["get", "configmap", "tetragon-config", "-n", "kube-system", "-o", "json"]
    )
    data = config.get("data", {})
    observed = {
        "enable-policy-filter": data.get("enable-policy-filter"),
        "enable-cri": data.get("enable-cri"),
        "enable-cgidmap": data.get("enable-cgidmap"),
        "runtime-hook-config": {
            key: value for key, value in data.items() if "hook" in key.lower()
        },
    }
    daemonsets = cmd.kubectl_json(["get", "daemonsets", "-A", "-o", "json"])
    runtime_hook_daemonsets = []
    for daemonset in daemonsets.get("items", []):
        metadata = daemonset.get("metadata", {})
        labels = metadata.get("labels", {})
        identity = " ".join(
            [
                str(metadata.get("name", "")),
                str(labels.get("app.kubernetes.io/name", "")),
                str(labels.get("app.kubernetes.io/component", "")),
            ]
        ).lower()
        if "tetragon" in identity and ("rthook" in identity or "runtime-hook" in identity):
            runtime_hook_daemonsets.append(
                f"{metadata.get('namespace', '')}/{metadata.get('name', '')}"
            )
    observed["runtime-hook-daemonsets"] = runtime_hook_daemonsets
    runtime_hook_values = [
        str(value).strip().lower()
        for value in observed["runtime-hook-config"].values()
    ]
    runtime_hook_enabled = any(
        value in {"1", "true", "yes", "enabled"} or "nri-hook" in value
        for value in runtime_hook_values
    )
    expected = (
        observed["enable-policy-filter"] == "true"
        and observed["enable-cri"] == "false"
        and observed["enable-cgidmap"] == "false"
        and not runtime_hook_daemonsets
        and not runtime_hook_enabled
    )
    if not expected and not allow_unexpected:
        raise ExperimentError(
            "Tetragon is not the intended async K8s-informer arm; "
            f"observed configuration: {observed}"
        )
    return observed


def installed_host_file_hash(
    cmd: Commands, namespace: str, observer_path: str
) -> dict[str, Any]:
    cp = cmd.kubectl_run(
        [
            "exec",
            "-n",
            namespace,
            OBSERVER_NAME,
            "-c",
            "observer",
            "--",
            "sha256sum",
            observer_path,
        ],
        timeout=20,
        check=False,
    )
    fields = cp.stdout.strip().split()
    digest = fields[0].lower() if cp.returncode == 0 and fields else ""
    valid_digest = bool(re.fullmatch(r"[0-9a-f]{64}", digest))
    return {
        "observer_path": observer_path,
        "present": cp.returncode == 0 and valid_digest,
        "sha256": digest if valid_digest else None,
        "returncode": cp.returncode,
        "stderr_tail": (cp.stderr or "").strip()[-1000:],
    }


def installed_sygma_component_hashes(
    cmd: Commands, args: argparse.Namespace
) -> dict[str, dict[str, Any]]:
    paths = {
        "hook": "/host-usr-local-bin/sygma-hook",
        "tracer": "/host-usr-local-bin/sygma-tracer",
        "wrapper": "/host-opt/sygma/wrapper",
        # The NRI plugin supplies both the SYGMA policy hook and the Tetragon
        # timing-only marker, so it is part of the publication trust base.
        "nri_plugin": "/host-opt/nri/plugins/00-sygma",
    }
    observed = {
        name: installed_host_file_hash(cmd, args.namespace, path)
        for name, path in paths.items()
    }
    missing_required = [
        name for name in ("hook", "tracer", "wrapper", "nri_plugin")
        if not observed[name]["present"]
    ]
    if missing_required:
        raise ExperimentError(
            "required SYGMA host components are missing or unreadable: "
            + ", ".join(missing_required)
        )
    return observed


def verify_hook_instrumentation(
    cmd: Commands,
    args: argparse.Namespace,
    component_hashes: dict[str, dict[str, Any]],
) -> dict[str, str]:
    local_hook = EVAL_ROOT / "build" / "sygma-hook"
    if not local_hook.is_file():
        raise ExperimentError(
            f"instrumented hook build is missing: {local_hook}; "
            "run scripts/install_instrumented_hook.sh first"
        )
    local_hash = sha256_file(local_hook)
    host_hash = str(component_hashes["hook"].get("sha256") or "")
    if local_hash != host_hash and not args.allow_hook_hash_mismatch:
        raise ExperimentError(
            "the node is not running the locally built instrumented hook "
            f"(local={local_hash}, installed={host_hash}); run "
            "scripts/install_instrumented_hook.sh or pass --allow-hook-hash-mismatch"
        )
    return {"local_sha256": local_hash, "installed_sha256": host_hash}


def verify_sygma_component_artifacts(
    args: argparse.Namespace,
    installed: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Require every running observation component to match audited artifacts."""

    local_paths = {
        "core": EVAL_ROOT / "build" / "sygma-core-current",
        "hook": EVAL_ROOT / "build" / "sygma-hook",
        "tracer": EVAL_ROOT / "build" / "sygma-tracer-current",
        "wrapper": EVAL_ROOT / "build" / "sygma-wrapper-current",
        "nri_plugin": EVAL_ROOT / "build" / "sygma-nri-current",
    }
    result: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    for name, path in local_paths.items():
        local_hash = sha256_file(path) if path.is_file() else None
        installed_hash = str(installed.get(name, {}).get("sha256") or "") or None
        matches = local_hash is not None and installed_hash == local_hash
        result[name] = {
            "local_path": str(path),
            "local_sha256": local_hash,
            "installed_sha256": installed_hash,
            "matches": matches,
        }
        if local_hash is None:
            problems.append(f"{name} audited artifact missing: {path}")
        elif installed_hash is None:
            problems.append(f"{name} installed/running hash unavailable")
        elif not matches:
            problems.append(
                f"{name} hash mismatch local={local_hash} installed={installed_hash}"
            )
    hook_only_override = bool(getattr(args, "allow_hook_hash_mismatch", False))
    fatal_problems = [
        problem for problem in problems
        if not (hook_only_override and problem.startswith("hook "))
    ]
    full_override = bool(
        getattr(args, "diagnostic_allow_sygma_artifact_mismatch", False)
    )
    if fatal_problems and not full_override:
        raise ExperimentError(
            "SYGMA components do not match the audited observation artifacts: "
            + "; ".join(fatal_problems)
        )
    result["verification"] = {
        "valid": not problems,
        "publication_eligible": not problems,
        "diagnostic_override": bool(problems) and (hook_only_override or full_override),
        "hook_only_override": hook_only_override,
        "full_override": full_override,
        "problems": problems,
    }
    return result


def discover_redis_addr(cmd: Commands, explicit: str | None) -> str:
    if explicit:
        return explicit
    config = cmd.kubectl_json(
        ["get", "configmap", "sygma-config", "-n", "default", "-o", "json"]
    )
    value = config.get("data", {}).get("redis-addr", "")
    if not value:
        raise ExperimentError("could not discover Redis address from default/sygma-config")
    return value


def prepare_sygma_policy(
    cmd: Commands, redis_addr: str, application: str = "synthetic"
) -> dict[str, Any]:
    script = EVAL_ROOT / "scripts" / "prepare_sygma_policy.py"
    cp = cmd.run(
        [
            sys.executable,
            str(script),
            "--redis-addr",
            redis_addr,
            "--image-name",
            image_alias_for_application(application),
            "--binary-name",
            policy_binary_for_application(application),
            "--binary-path",
            policy_binary_path_for_application(application),
        ],
        timeout=45,
    )
    return parse_json_object(cp.stdout)


def observer_exec_prefix(args: argparse.Namespace) -> list[str]:
    return [
        args.kubectl,
        "exec",
        "-n",
        args.namespace,
        OBSERVER_NAME,
        "-c",
        "observer",
        "--",
    ]


def classify_sygma_pinned_map_capability(
    present_by_path: dict[str, bool],
) -> dict[str, Any]:
    """Validate the pinned-map ABI and select typed or legacy-sequence mode."""

    legacy_present = [
        path for path in SYGMA_LEGACY_REQUIRED_PINNED_MAPS if present_by_path.get(path, False)
    ]
    legacy_missing = [
        path for path in SYGMA_LEGACY_REQUIRED_PINNED_MAPS if not present_by_path.get(path, False)
    ]
    if legacy_missing:
        raise ExperimentError(
            "required SYGMA legacy sequence maps are missing or inaccessible: "
            + ", ".join(legacy_missing)
        )

    typed_present = [
        path for path in SYGMA_TYPED_POLICY_PINNED_MAPS if present_by_path.get(path, False)
    ]
    typed_missing = [
        path for path in SYGMA_TYPED_POLICY_PINNED_MAPS if not present_by_path.get(path, False)
    ]
    if typed_present and typed_missing:
        raise ExperimentError(
            "partial SYGMA typed-policy pinned-map set; "
            f"present={typed_present}, missing={typed_missing}"
        )

    mode = "typed-sequence" if not typed_missing else "legacy-sequence"
    return {
        "mode": mode,
        "legacy_required": {
            "all_present": True,
            "required": list(SYGMA_LEGACY_REQUIRED_PINNED_MAPS),
            "present": legacy_present,
            "missing": legacy_missing,
        },
        "typed_policy": {
            "all_present": not typed_missing,
            "all_absent": not typed_present,
            "required": list(SYGMA_TYPED_POLICY_PINNED_MAPS),
            "present": typed_present,
            "missing": typed_missing,
        },
    }


def validate_sygma_map_abi(
    mode: str, map_info_by_path: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    expected = dict(SYGMA_COMMON_MAP_ABI)
    expected["/sys/fs/bpf/sygma/process_state_map"] = (
        SYGMA_TYPED_MAP_ABI["/sys/fs/bpf/sygma/process_state_map"]
        if mode == "typed-sequence"
        else SYGMA_LEGACY_PROCESS_STATE_ABI
    )
    if mode == "typed-sequence":
        expected.update(SYGMA_TYPED_MAP_ABI)

    mismatches: list[dict[str, Any]] = []
    for path, contract in expected.items():
        observed = map_info_by_path.get(path, {})
        for field, wanted in contract.items():
            try:
                actual = int(observed.get(field, -1))
            except (TypeError, ValueError):
                actual = -1
            if actual != wanted:
                mismatches.append(
                    {
                        "path": path,
                        "field": field,
                        "expected": wanted,
                        "observed": None if actual == -1 else actual,
                    }
                )
    result = {
        "mode": mode,
        "expected": expected,
        "mismatches": mismatches,
        "valid": not mismatches,
    }
    if mismatches:
        rendered = ", ".join(
            f"{item['path']}:{item['field']}="
            f"{item['observed']} (expected {item['expected']})"
            for item in mismatches
        )
        raise ExperimentError(f"SYGMA pinned-map ABI mismatch: {rendered}")
    return result


def preflight_sygma_pinned_maps(
    cmd: Commands, args: argparse.Namespace
) -> dict[str, Any]:
    """Probe the node's host bpffs through the already-privileged observer."""

    paths = (
        *SYGMA_LEGACY_REQUIRED_PINNED_MAPS,
        *SYGMA_TYPED_POLICY_PINNED_MAPS,
        *APPLICATION_SYSCALL_PINNED_MAPS,
    )
    present_by_path: dict[str, bool] = {}
    map_info_by_path: dict[str, dict[str, Any]] = {}
    checks: dict[str, dict[str, Any]] = {}
    for path in paths:
        cp = cmd.run(
            [
                *observer_exec_prefix(args),
                "/opt/eval/policy-map-watch",
                "--inspect-map",
                path,
            ],
            timeout=20,
            check=False,
        )
        records: list[dict[str, Any]] = []
        for raw in (cp.stdout or "").splitlines():
            with contextlib.suppress(json.JSONDecodeError):
                record = json.loads(raw)
                if isinstance(record, dict):
                    records.append(record)
        infos = [record for record in records if record.get("event") == "map_info"]
        present = cp.returncode == 0 and len(infos) == 1
        present_by_path[path] = present
        if present:
            map_info_by_path[path] = infos[0]
        # Some kubectl builds emit verbose transport diagnostics on stderr
        # even when exec succeeds.  commands.jsonl already preserves the full
        # invocation record; keep campaign metadata compact and retain only a
        # bounded failure tail here.
        failure_stderr = (cp.stderr or "").strip() if not present else ""
        checks[path] = {
            "present": present,
            "returncode": cp.returncode,
            "stderr_tail": failure_stderr[-1000:],
            "records": records,
        }

    capability = classify_sygma_pinned_map_capability(present_by_path)
    map_abi = validate_sygma_map_abi(capability["mode"], map_info_by_path)
    application_map_mismatches = []
    for path, contract in APPLICATION_SYSCALL_MAP_ABI.items():
        observed = map_info_by_path.get(path, {})
        for field, wanted in contract.items():
            try:
                actual = int(observed.get(field, -1))
            except (TypeError, ValueError):
                actual = -1
            if actual != wanted:
                application_map_mismatches.append(
                    f"{path}:{field}={actual} expected={wanted}"
                )
    if application_map_mismatches:
        raise ExperimentError(
            "application syscall observer map ABI mismatch: "
            + ", ".join(application_map_mismatches)
        )
    typed_campaign = capability["mode"] == "typed-sequence"
    capability.update(
        {
            "checked_via": f"{args.namespace}/{OBSERVER_NAME} host bpffs mount",
            "checks": checks,
            "map_info_by_path": map_info_by_path,
            "map_abi": map_abi,
            "primary_experiment_eligible": typed_campaign,
        }
    )
    if not typed_campaign:
        raise ExperimentError(
            "the audited observation-only core artifact requires the typed "
            "28-byte process_state ABI; the detected legacy 20-byte stack is "
            "historical compatibility only and cannot be used for this campaign"
        )
    return capability


def map_snapshot(cmd: Commands, args: argparse.Namespace, policy_id: int) -> dict[str, Any]:
    cp = cmd.run(
        [
            *observer_exec_prefix(args),
            "/opt/eval/policy-map-watch",
            "--policy-id",
            str(policy_id),
            "--once",
        ],
        timeout=20,
    )
    events = []
    for line in cp.stdout.splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            value = json.loads(line)
            if isinstance(value, dict):
                events.append(value)
    if not events:
        raise ExperimentError(f"map watcher returned no snapshot: {cp.stdout}")
    return events[-1]


def fetch_application_syscalls(
    cmd: Commands,
    args: argparse.Namespace,
    cgroup_id: int,
    *,
    cleanup: bool,
    before_boottime_ns: int | None = None,
) -> dict[str, Any]:
    """Read the neutral application-lineage counters for one Pod cgroup.

    ``before_boottime_ns``, when given, asks the neutral counter for how many
    of the application's syscalls it observed strictly before that boottime
    -- e.g. the SYGMA arm's ``sygma_direct_policy_ready`` timestamp -- so the
    gap metric is an absolute count of syscalls that ran before the policy
    was applied, not a percentage of a fixed observation window.
    """

    argv = [
        *observer_exec_prefix(args),
        "/opt/eval/policy-map-watch",
        "--lookup-app-syscalls",
        "--cgroup-id",
        str(cgroup_id),
    ]
    if before_boottime_ns is not None:
        argv.extend(["--before-boottime-ns", str(before_boottime_ns)])
    if cleanup:
        argv.append("--cleanup")
    cp = cmd.run(argv, timeout=30, check=False)
    records: list[dict[str, Any]] = []
    for raw in (cp.stdout or "").splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            record = json.loads(raw)
            if isinstance(record, dict):
                records.append(record)
    matches = [
        record
        for record in records
        if record.get("event") == "application_syscall_snapshot"
        and int(record.get("cgroup_id", 0)) == cgroup_id
    ]
    return {
        "available": cp.returncode == 0 and len(matches) == 1,
        "snapshot": matches[0] if len(matches) == 1 else None,
        "records": records,
        "returncode": cp.returncode,
        "stderr_tail": (cp.stderr or "").strip()[-1000:],
    }


def build_sygma_application_evidence(
    hook_events: list[dict[str, Any]],
    snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    ready = [
        event
        for event in hook_events
        if event.get("event") == "sygma_direct_policy_ready"
    ]
    if len(ready) != 1 or not snapshot:
        return {
            "available": False,
            "positive": False,
            "reason": f"ready_count_{len(ready)}_or_snapshot_missing",
        }
    try:
        ready_ns = int(ready[0]["boottime_ns"])
        first_ns = int(snapshot["first_boottime_ns"])
        total = int(snapshot["total"])
        uncovered = int(snapshot["before_count"])
    except (KeyError, TypeError, ValueError):
        return {
            "available": False,
            "positive": False,
            "reason": "invalid_ready_or_application_counter_timestamp",
        }
    # uncovered is the neutral counter's own definite-before-ready count (see
    # count_bins_before in mapwatch/policy_map_watch.c), not an inference
    # from comparing two single timestamps: it is the actual number of
    # syscalls the independent observer saw complete before
    # sygma_direct_policy_ready, from OCI prestart hook entry onward.
    positive = total > 0 and uncovered == 0
    return {
        "available": True,
        "positive": positive,
        "policy_ready_boottime_ns": ready_ns,
        "first_application_syscall_boottime_ns": first_ns,
        "ready_lead_ns": first_ns - ready_ns,
        "application_syscalls_total": total,
        "application_syscalls_uncovered": uncovered,
        "reason": None if positive else "syscalls_observed_before_policy_ready",
    }


def snapshot_count(snapshot: dict[str, Any]) -> int:
    for key in ("count", "cgroup_count", "existing_count"):
        if key in snapshot:
            return int(snapshot[key])
    for key in ("cgroup_ids", "keys"):
        if isinstance(snapshot.get(key), list):
            return len(snapshot[key])
    return 0


def wait_policy_map_empty(
    cmd: Commands, args: argparse.Namespace, policy_id: int, timeout: float = 20
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = map_snapshot(cmd, args, policy_id)
        if snapshot_count(last) == 0:
            return last
        time.sleep(0.1)
    raise ExperimentError(f"Tetragon experiment policy map did not drain: {last}")


class MapWatchProcess:
    def __init__(
        self,
        args: argparse.Namespace,
        policy_id: int,
        stdout_path: pathlib.Path,
        stderr_path: pathlib.Path,
    ) -> None:
        self.stdout_path = stdout_path
        self.stderr_stream = stderr_path.open("w")
        self.stdout_stream = stdout_path.open("w")
        try:
            self.proc = subprocess.Popen(
                [
                    *observer_exec_prefix(args),
                    "/opt/eval/policy-map-watch",
                    "--policy-id",
                    str(policy_id),
                    "--timeout-ms",
                    str(args.duration_ms + getattr(args, "evidence_hold_ms", 5000) + 20000),
                    "--poll-us",
                    str(args.map_poll_us),
                    "--exit-after-insert",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=self.stderr_stream,
                bufsize=1,
            )
        except Exception:
            self.stdout_stream.close()
            self.stderr_stream.close()
            raise
        self._thread: threading.Thread | None = None
        self._closed = False

    def wait_ready(self, timeout: float = 15) -> dict[str, Any]:
        assert self.proc.stdout is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise ExperimentError(
                    f"map watcher exited before ready (rc={self.proc.returncode})"
                )
            readable, _, _ = select.select([self.proc.stdout], [], [], 0.2)
            if not readable:
                continue
            line = self.proc.stdout.readline()
            if not line:
                continue
            self.stdout_stream.write(line)
            self.stdout_stream.flush()
            with contextlib.suppress(json.JSONDecodeError):
                value = json.loads(line)
                if value.get("event") == "watch_ready":
                    self._thread = threading.Thread(target=self._drain, daemon=True)
                    self._thread.start()
                    return value
        raise ExperimentError("map watcher did not report watch_ready")

    def _drain(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.stdout_stream.write(line)
            self.stdout_stream.flush()

    def finish(self, timeout: float = 15) -> None:
        if self._closed:
            return
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.proc.wait(timeout=3)
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait(timeout=3)
        if self._thread is not None:
            self._thread.join(timeout=2)
        elif self.proc.stdout is not None:
            for line in self.proc.stdout:
                self.stdout_stream.write(line)
        if self.proc.stdout is not None:
            self.proc.stdout.close()
        self.stdout_stream.flush()
        self.stdout_stream.close()
        self.stderr_stream.close()
        self._closed = True


def workload_pod(
    args: argparse.Namespace, backend: str, trial_id: str, pod_name: str, node_name: str
) -> dict[str, Any]:
    application = str(getattr(args, "application", "synthetic"))
    if application not in APPLICATIONS:
        raise ExperimentError(f"unsupported application profile: {application}")
    labels = {
        "app.kubernetes.io/name": "sygma-gap-probe",
        "app.kubernetes.io/part-of": EXPERIMENT_PART_OF_LABEL,
        "gap.sygma.io/backend": backend,
        "gap.sygma.io/application": application,
        "gap.sygma.io/trial": trial_id.lower()[:63],
    }
    annotations: dict[str, str] = {}
    if backend == "sygma":
        annotations = {
            "sygma.io/mode": "enforcement",
            # This isolates the Redis template from the immutable workload
            # image and gives every application its own policy ownership key.
            "sygma.io/image": image_alias_for_application(application),
            "sygma.io/experiment-id": trial_id,
        }
    elif backend == "tetragon":
        # Measurement instrumentation only. The NRI plugin validates the
        # experiment labels and adds one timestamp-only prestart hook; it does
        # not add policy state, mounts, wrapper injection, signals, or poststop.
        annotations = {TIMELINE_PRESTART_ANNOTATION: "v1"}
    environment = [
        {"name": "TRIAL_ID", "value": trial_id},
        {"name": "BACKEND", "value": backend},
        {"name": "APPLICATION", "value": application},
        {"name": "DURATION_MS", "value": str(args.duration_ms)},
        {"name": "INTERVAL_US", "value": str(args.interval_us)},
        {
            "name": "EVIDENCE_HOLD_MS",
            "value": str(getattr(args, "evidence_hold_ms", 5000)),
        },
    ]
    if application == "mysql":
        # A fresh writable layer is used for every trial. Avoid a reused PVC,
        # which would make one randomized arm inherit the other's data state.
        environment.extend(
            [
                {"name": "MYSQL_ALLOW_EMPTY_PASSWORD", "value": "yes"},
                {"name": "MYSQL_DATABASE", "value": "gap_eval"},
            ]
        )
    if application in BOUTIQUE_PEER_ADDRESS_ENV:
        # Online Boutique services check these env vars for *presence* at
        # startup (mustMapEnv-style) and fail closed if missing, independent
        # of whether the peer is ever actually called during the trial. The
        # addresses point at the real peer Deployments/Services applied once
        # to this namespace (see the "Online Boutique peer dependencies"
        # note in README.md) -- not placeholders, since a wrong/unreachable
        # address would only defer the failure to the first real RPC.
        # Values are copied verbatim from the upstream release manifest
        # (release/kubernetes-manifests.yaml) so service:port pairs always
        # match the real container ports.
        environment.extend(
            {"name": name, "value": value}
            for name, value in BOUTIQUE_PEER_ADDRESS_ENV[application].items()
        )

    container: dict[str, Any] = {
        "name": "probe",
        "image": args.carrier_image,
        "imagePullPolicy": args.image_pull_policy,
        "env": environment,
        # Match the no-new-privileges property installed by the SYGMA wrapper
        # without forcing a UID/capability set that would break nginx:80 or
        # first-run MySQL initialization.
        "securityContext": {"allowPrivilegeEscalation": False},
    }
    volumes: list[dict[str, Any]] = []
    if application == "synthetic":
        # The synthetic baseline retains the original ConfigMap-mounted probe.
        # Real application profiles instead require gap-launch to be baked
        # into the immutable image so the OCI hook can replace that regular
        # rootfs file without touching /bin/sh or a read-only volume.
        container.update(
            {
                "command": ["/bin/sh", "-c"],
                "args": ["exec /opt/eval/gap-probe"],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "runAsUser": 65534,
                    "runAsGroup": 65534,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [
                    {"name": "probe", "mountPath": "/opt/eval", "readOnly": True}
                ],
            }
        )
        volumes.append(
            {
                "name": "probe",
                "configMap": {
                    "name": "startup-gap-probe-bin",
                    "defaultMode": 365,
                },
            }
        )

    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": args.namespace,
            "labels": labels,
            "annotations": annotations,
        },
        "spec": {
            "nodeName": node_name,
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 1,
            "containers": [container],
        },
    }
    if volumes:
        pod["spec"]["volumes"] = volumes
    return pod


def container_status(
    pod: dict[str, Any], *, container_name: str
) -> dict[str, Any]:
    """Return the status for the explicitly selected container."""

    statuses = pod.get("status", {}).get("containerStatuses", [])
    for status in statuses:
        if status.get("name") == container_name:
            return status
    return {}


def fetch_probe_logs(cmd: Commands, args: argparse.Namespace, pod_name: str) -> str:
    cp = cmd.kubectl_run(
        ["logs", pod_name, "-n", args.namespace, "-c", "probe"],
        timeout=30,
        check=False,
    )
    return cp.stdout or ""


def fetch_tetragon_positive_events(
    cmd: Commands,
    *,
    tetragon_pod: str | None,
    namespace: str,
    pod_name: str,
    container_id: str,
    since_time: str | None,
) -> dict[str, Any]:
    """Collect a rate-limited raw-syscall Post event as selector evidence.

    The exporter is read only after the workload terminates.  Neither its log
    delivery time nor this collection call contributes to readiness latency.
    """

    if not tetragon_pod or not since_time or not container_id:
        return {"available": False, "reason": "event_identity_or_source_missing", "events": []}
    deadline = time.monotonic() + 5.0
    cp: subprocess.CompletedProcess[str] | None = None
    parsed: list[dict[str, Any]] = []
    matched: list[dict[str, Any]] = []
    parse_errors = 0
    while time.monotonic() < deadline:
        cp = cmd.kubectl_run(
            [
                "logs",
                tetragon_pod,
                "-n",
                "kube-system",
                "-c",
                "export-stdout",
                f"--since-time={since_time}",
            ],
            timeout=30,
            check=False,
        )
        parsed = []
        parse_errors = 0
        for raw in (cp.stdout or "").splitlines():
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if isinstance(value, dict):
                parsed.append(value)

        matched = []
        for event in parsed:
            payload = event.get("process_tracepoint")
            if not isinstance(payload, dict):
                continue
            if (
                str(payload.get("subsys", payload.get("subsystem", "")))
                != "raw_syscalls"
                or str(payload.get("event", "")) != "sys_enter"
            ):
                continue
            process = payload.get("process")
            if not isinstance(process, dict):
                continue
            pod = process.get("pod")
            if not isinstance(pod, dict):
                continue
            if pod.get("namespace") != namespace or pod.get("name") != pod_name:
                continue
            pod_container = pod.get("container")
            if not isinstance(pod_container, dict):
                continue
            if pod_container.get("name") != "probe":
                continue
            event_container = strip_runtime_prefix(str(pod_container.get("id", "")))
            if event_container != container_id:
                continue
            matched.append(event)
        if matched:
            break
        time.sleep(0.1)
    assert cp is not None
    return {
        "available": cp.returncode == 0,
        "positive": bool(matched),
        "source": f"kube-system/{tetragon_pod}:export-stdout",
        "matched_count": len(matched),
        "parsed_count": len(parsed),
        "parse_error_count": parse_errors,
        "returncode": cp.returncode,
        "stderr_tail": (cp.stderr or "").strip()[-1000:],
        "events": matched,
    }


def split_container_logs(
    backend: str, raw_logs: str
) -> tuple[str, str, list[str]]:
    """Preserve wrapper diagnostics without feeding them to the JSON parser."""
    probe_lines: list[str] = []
    wrapper_lines: list[str] = []
    reasons: list[str] = []

    for line_number, line in enumerate(raw_logs.splitlines(), 1):
        if not line.strip():
            continue
        if line.startswith("[sygma-wrapper]"):
            wrapper_lines.append(line)
            if backend != "sygma":
                reasons.append(f"unexpected_wrapper_log_line_{line_number}")
        elif line.lstrip().startswith("{"):
            probe_lines.append(line)
        else:
            reasons.append(f"unexpected_container_log_line_{line_number}")

    if backend == "sygma":
        required_markers = {
            "start": "SYGMA WRAPPER START",
            "tracer_resume": "Resumed by attached tracer",
            "seccomp_installed": "Seccomp filter installed",
            "exec": "Executing:",
        }
        for name, marker in required_markers.items():
            count = sum(marker in line for line in wrapper_lines)
            if count != 1:
                reasons.append(f"sygma_wrapper_{name}_count_{count}")
    elif wrapper_lines:
        reasons.append(f"unexpected_wrapper_line_count_{len(wrapper_lines)}")

    probe_jsonl = "".join(f"{line}\n" for line in probe_lines)
    wrapper_log = "".join(f"{line}\n" for line in wrapper_lines)
    return probe_jsonl, wrapper_log, reasons


def fetch_hook_timeline(
    cmd: Commands,
    args: argparse.Namespace,
    container_id: str,
    pod_name: str,
    min_boottime_ns: int,
) -> list[dict[str, Any]]:
    cp = cmd.kubectl_run(
        [
            "exec",
            "-n",
            args.namespace,
            OBSERVER_NAME,
            "-c",
            "observer",
            "--",
            "cat",
            "/host-var-log/sygma-timeline.jsonl",
        ],
        timeout=30,
        check=False,
    )
    ret = []
    for raw in (cp.stdout or "").splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            event = json.loads(raw)
            event_id = strip_runtime_prefix(str(event.get("container_id", "")))
            exact_id = bool(container_id) and event_id == container_id
            fallback = (
                not container_id
                and event.get("pod_name") == pod_name
                and int(event.get("boottime_ns", 0)) >= min_boottime_ns
            )
            if exact_id or fallback:
                ret.append(event)
    return ret


def wait_hook_cleanup(
    cmd: Commands,
    args: argparse.Namespace,
    container_id: str,
    pod_name: str,
    min_boottime_ns: int,
    timeout: float = 10,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    events: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        events = fetch_hook_timeline(
            cmd, args, container_id, pod_name, min_boottime_ns
        )
        if any(event.get("event") == "sygma_cleanup_complete" for event in events):
            return events
        time.sleep(0.1)
    return events


def validate_trial_raw(
    backend: str,
    phase: str,
    probe_events: list[dict[str, Any]],
    map_events: list[dict[str, Any]],
    hook_events: list[dict[str, Any]],
    expected_policy_id: int | None = None,
    expected_application: str | None = None,
    expected_trial_id: str | None = None,
    expected_container_id: str | None = None,
    expected_pod_uid: str | None = None,
    expected_pod_name: str | None = None,
) -> list[str]:
    reasons: list[str] = []
    if phase != "Succeeded":
        reasons.append(f"pod_phase_{phase or 'unknown'}")
    starts = [e for e in probe_events if e.get("event") in {"probe_start", "start"}]
    summaries = [e for e in probe_events if e.get("event") in {"probe_summary", "summary"}]
    attempts = [e for e in probe_events if e.get("event") == "attempt"]
    app_spawns = [e for e in probe_events if e.get("event") == "app_spawn"]
    app_exits = [e for e in probe_events if e.get("event") == "app_exit"]
    if len(starts) != 1:
        reasons.append(f"probe_start_count_{len(starts)}")
    if len(summaries) != 1:
        reasons.append(f"probe_summary_count_{len(summaries)}")
    if attempts:
        reasons.append(f"unexpected_controlled_attempt_count_{len(attempts)}")
    for event in starts + summaries:
        if int(event.get("schema_version", -1)) != 3:
            reasons.append("application_launcher_schema_mismatch")
        if event.get("measurement_mode") != "application_lineage_syscalls":
            reasons.append("application_measurement_mode_mismatch")
    if expected_application and len(starts) == 1:
        observed_application = str(
            starts[0].get("application", "synthetic")
        )
        if observed_application != expected_application:
            reasons.append(
                "probe_application_"
                f"{observed_application}_expected_{expected_application}"
            )
    if expected_application and expected_application != "synthetic":
        if len(app_spawns) != 1:
            reasons.append(f"app_spawn_count_{len(app_spawns)}")
        if len(app_exits) != 1:
            reasons.append(f"app_exit_count_{len(app_exits)}")
        for event_name, events in (("spawn", app_spawns), ("exit", app_exits)):
            if len(events) == 1 and str(events[0].get("application", "")) != expected_application:
                reasons.append(
                    f"app_{event_name}_application_"
                    f"{events[0].get('application', '')}_expected_{expected_application}"
                )
    if len(summaries) == 1:
        summary = summaries[0]
        if expected_application and expected_application != "synthetic":
            if str(summary.get("application", "")) != expected_application:
                reasons.append("probe_summary_application_mismatch")
            if summary.get("app_alive_at_summary") is not True:
                reasons.append("application_not_alive_at_probe_summary")
            if summary.get("measurement_interrupted") is not False:
                reasons.append("application_measurement_interrupted")
            if len(app_spawns) == 1:
                try:
                    summary_pid = int(summary.get("app_pid", 0))
                    spawn_pid = int(app_spawns[0].get("pid", 0))
                except (TypeError, ValueError):
                    summary_pid = spawn_pid = 0
                if summary_pid <= 0 or summary_pid != spawn_pid:
                    reasons.append("application_pid_mismatch")
        if (
            expected_application
            and expected_application != "synthetic"
            and len(app_exits) == 1
            and str(app_exits[0].get("phase", "")) != "cleanup"
        ):
            reasons.append(
                f"application_exit_phase_{app_exits[0].get('phase', 'missing')}"
            )

    prestart_enters = [
        event for event in hook_events if event.get("event") == "oci_prestart_enter"
    ]
    prestart_completes = [
        event for event in hook_events if event.get("event") == "oci_prestart_complete"
    ]
    if len(prestart_enters) != 1:
        reasons.append(f"oci_prestart_enter_count_{len(prestart_enters)}")
    if len(prestart_completes) != 1:
        reasons.append(f"oci_prestart_complete_count_{len(prestart_completes)}")

    expected_mode = "enforcement" if backend == "sygma" else "tetragon-measurement"
    expected_role = "policy-and-release" if backend == "sygma" else "timestamp-only"
    for event in prestart_enters + prestart_completes:
        if int(event.get("schema_version", -1)) != HOOK_TIMELINE_SCHEMA_VERSION:
            reasons.append("hook_timeline_schema_mismatch")
        if event.get("component") != "sygma-oci-hook":
            reasons.append("hook_timeline_component_mismatch")
        if event.get("backend") != backend:
            reasons.append("hook_timeline_backend_mismatch")
        if event.get("mode") != expected_mode:
            reasons.append("hook_timeline_mode_mismatch")
        if event.get("hook_role") != expected_role:
            reasons.append("hook_timeline_role_mismatch")
        if event.get("container_name") != "probe":
            reasons.append("hook_timeline_container_name_mismatch")
        if expected_trial_id is not None and event.get("trial_id") != expected_trial_id:
            reasons.append("hook_timeline_trial_id_mismatch")
        if (
            expected_application is not None
            and event.get("application") != expected_application
        ):
            reasons.append("hook_timeline_application_mismatch")
        if expected_container_id is not None and strip_runtime_prefix(
            str(event.get("container_id", ""))
        ) != strip_runtime_prefix(expected_container_id):
            reasons.append("hook_timeline_container_id_mismatch")
        if expected_pod_uid is not None and event.get("pod_uid") != expected_pod_uid:
            reasons.append("hook_timeline_pod_uid_mismatch")
        if expected_pod_name is not None and event.get("pod_name") != expected_pod_name:
            reasons.append("hook_timeline_pod_name_mismatch")

    common_order: list[int] = []
    if len(prestart_enters) == 1 and len(prestart_completes) == 1:
        try:
            enter_boot = int(prestart_enters[0]["boottime_ns"])
            complete_boot = int(prestart_completes[0]["boottime_ns"])
        except (KeyError, TypeError, ValueError):
            reasons.append("prestart_boundary_boottime_invalid")
        else:
            common_order = [enter_boot, complete_boot]
            if enter_boot <= 0 or complete_boot < enter_boot:
                reasons.append("prestart_boundary_order_invalid")
            if len(starts) == 1:
                try:
                    probe_start_boot = int(starts[0]["boottime_ns"])
                except (KeyError, TypeError, ValueError):
                    reasons.append("probe_start_boottime_invalid")
                else:
                    if complete_boot > probe_start_boot:
                        reasons.append("atomicity_prestart_complete_after_probe_start")

    if backend == "sygma":
        ready = [e for e in hook_events if e.get("event") == "sygma_direct_policy_ready"]
        if len(ready) != 1:
            reasons.append(f"sygma_ready_count_{len(ready)}")
        elif starts and int(ready[0].get("boottime_ns", 0)) > int(
            starts[0].get("boottime_ns", 0)
        ):
            reasons.append("sygma_ready_after_probe_start")
        for event_name in (
            "target_release_begin",
            "target_release_signal_sent",
        ):
            count = sum(event.get("event") == event_name for event in hook_events)
            if count != 1:
                reasons.append(f"{event_name}_count_{count}")
        ordered_names = (
            "oci_prestart_enter",
            "sygma_direct_policy_ready",
            "target_release_begin",
            "target_release_signal_sent",
            "oci_prestart_complete",
        )
        ordered = []
        for event_name in ordered_names:
            matches = [
                int(event.get("boottime_ns", 0))
                for event in hook_events
                if event.get("event") == event_name
            ]
            if len(matches) == 1:
                ordered.append(matches[0])
        if len(ordered) == len(ordered_names) and ordered != sorted(ordered):
            reasons.append("sygma_atomicity_invariant_violation")
        if len(ordered) == len(ordered_names) and starts:
            try:
                probe_start_boot = int(starts[0]["boottime_ns"])
            except (KeyError, TypeError, ValueError):
                pass
            else:
                if ordered[-1] > probe_start_boot:
                    reasons.append("sygma_atomicity_invariant_violation")
    else:
        forbidden_hook_events = {
            "sygma_direct_policy_ready",
            "target_release_begin",
            "target_release_signal_sent",
            "sygma_cleanup_complete",
        }
        unexpected_policy_events = sum(
            event.get("event") in forbidden_hook_events for event in hook_events
        )
        if unexpected_policy_events:
            reasons.append(
                f"tetragon_timing_hook_policy_event_count_{unexpected_policy_events}"
            )
        ready_events = [e for e in map_events if e.get("event") == "watch_ready"]
        if len(ready_events) != 1:
            reasons.append(f"tetragon_watch_ready_count_{len(ready_events)}")
        inserts = [e for e in map_events if e.get("event") == "map_insert"]
        if len(inserts) != 1:
            reasons.append(f"tetragon_map_insert_count_{len(inserts)}")
        if expected_policy_id is not None:
            for event_name, events in (
                ("watch_ready", ready_events),
                ("map_insert", inserts),
            ):
                for event in events:
                    try:
                        observed_policy_id = int(event.get("policy_id", -1))
                    except (TypeError, ValueError):
                        observed_policy_id = -1
                    if observed_policy_id != expected_policy_id:
                        reasons.append(
                            f"tetragon_{event_name}_policy_id_"
                            f"{observed_policy_id}_expected_{expected_policy_id}"
                        )
        if len(inserts) == 1:
            try:
                lower = int(inserts[0]["last_absent_boottime_ns"])
                upper = int(inserts[0]["first_present_boottime_ns"])
            except (KeyError, TypeError, ValueError):
                reasons.append("tetragon_map_insert_boottime_bounds_invalid")
            else:
                if lower <= 0 or upper < lower:
                    reasons.append("tetragon_map_insert_boottime_bounds_invalid")
                if len(ready_events) == 1:
                    try:
                        ready_time = int(ready_events[0]["boottime_ns"])
                    except (KeyError, TypeError, ValueError):
                        reasons.append("tetragon_watch_ready_boottime_invalid")
                    else:
                        if ready_time <= 0 or ready_time > lower:
                            reasons.append("tetragon_watch_ready_after_map_lower")
        if len(summaries) == 1 and len(inserts) == 1:
            try:
                probe_cgroup_id = int(summaries[0].get("cgroup_id", 0))
                probe_cgroup_errno = int(summaries[0].get("cgroup_id_errno", 0))
                map_cgroup_id = int(inserts[0].get("cgroup_id", 0))
            except (TypeError, ValueError):
                reasons.append("invalid_cgroup_id_encoding")
            else:
                if probe_cgroup_errno != 0 or probe_cgroup_id <= 0:
                    reasons.append(
                        f"probe_cgroup_id_unavailable_errno_{probe_cgroup_errno}"
                    )
                elif map_cgroup_id != probe_cgroup_id:
                    reasons.append(
                        f"cgroup_id_mismatch_probe_{probe_cgroup_id}_map_{map_cgroup_id}"
                    )
    return reasons


def append_trial(path: pathlib.Path, trial: dict[str, Any]) -> None:
    with path.open("a") as stream:
        stream.write(json_line(trial))
        stream.flush()
        os.fsync(stream.fileno())


def retryable_infrastructure_failure(trial: Mapping[str, Any]) -> str | None:
    """Classify only failures that occurred before application execution.

    A retry is deliberately narrower than general trial invalidity.  In
    particular, an ordering violation, a non-zero missed-syscall count, or an
    application/runtime failure after probe_start is never retried.
    """

    abort = trial.get("hook_prestart_abort")
    if not isinstance(abort, Mapping) or not str(abort.get("failure", "")):
        return None
    if (
        trial.get("backend") != "sygma"
        or bool(trial.get("valid"))
        or trial.get("pod_phase") != "Failed"
        or trial.get("container_termination_reason") != "StartError"
        or trial.get("probe_started") is True
        or trial.get("application_syscall_snapshot") is not None
        or normalize_container_started_time(trial.get("container_started_time"))
    ):
        return None
    try:
        exit_code = int(trial.get("container_exit_code", -1))
    except (TypeError, ValueError):
        return None
    if exit_code != 128:
        return None
    return "sygma_prestart_start_error_before_application"


def run_trial(
    cmd: Commands,
    args: argparse.Namespace,
    *,
    backend: str,
    trial_id: str,
    warmup: bool,
    node_name: str,
    policy_id: int,
    result_dir: pathlib.Path,
    tetragon_pod: str | None = None,
) -> dict[str, Any]:
    raw_rel = pathlib.Path("raw") / trial_id
    raw_dir = result_dir / raw_rel
    raw_dir.mkdir(parents=True, exist_ok=False)
    pod_name = ("gap-" + trial_id.lower()).replace("_", "-")[:63].rstrip("-")
    delete_pod(cmd, args.namespace, pod_name)

    mapwatch: MapWatchProcess | None = None
    pre_snapshot: dict[str, Any] | None = None
    if backend == "tetragon":
        # Tetragon 1.4 may retain a completed/deleted Pod's cgroup key. The
        # watcher snapshots that baseline and emits only newly inserted IDs;
        # the probe later provides an exact target-ID correlation.
        pre_snapshot = map_snapshot(cmd, args, policy_id)
        mapwatch = MapWatchProcess(
            args,
            policy_id,
            raw_dir / "mapwatch.jsonl",
            raw_dir / "mapwatch.stderr.log",
        )
        try:
            mapwatch.wait_ready()
        except Exception:
            mapwatch.finish(timeout=1)
            raise
    else:
        (raw_dir / "mapwatch.jsonl").write_text("")
        (raw_dir / "mapwatch.stderr.log").write_text("")

    pod_obj = workload_pod(args, backend, trial_id, pod_name, node_name)
    (raw_dir / "pod-request.json").write_text(json.dumps(pod_obj, indent=2, sort_keys=True))
    submit = clock_pair()
    creation_error: str | None = None
    created: dict[str, Any] = {}
    try:
        created = cmd.kubectl_json(
            ["create", "-f", "-", "-o", "json"], obj=pod_obj, timeout=45
        )
    except Exception as exc:  # preserve a complete invalid trial record
        creation_error = str(exc)
    ack = clock_pair()

    terminal: dict[str, Any] = created
    if creation_error is None:
        try:
            terminal = wait_pod_condition(
                cmd,
                args.namespace,
                pod_name,
                terminal=True,
                timeout=(args.duration_ms + args.evidence_hold_ms) / 1000 + 45,
            )
        except Exception as exc:
            creation_error = f"terminal_wait: {exc}"

    if mapwatch is not None:
        mapwatch.finish(
            timeout=(args.duration_ms + args.evidence_hold_ms) / 1000 + 15
        )

    if terminal:
        (raw_dir / "pod.json").write_text(json.dumps(terminal, indent=2, sort_keys=True))
    else:
        (raw_dir / "pod.json").write_text("{}\n")

    logs = fetch_probe_logs(cmd, args, pod_name) if creation_error is None else ""
    (raw_dir / "container.log").write_text(logs)
    probe_logs, wrapper_logs, log_split_reasons = split_container_logs(backend, logs)
    (raw_dir / "probe.jsonl").write_text(probe_logs)
    (raw_dir / "wrapper.log").write_text(wrapper_logs)

    status = container_status(terminal, container_name="probe")
    full_container_id = str(status.get("containerID", ""))
    container_id = strip_runtime_prefix(full_container_id)
    container_image = str(status.get("image", ""))
    container_image_id = str(status.get("imageID", ""))
    requested_image_digest = pinned_image_reference_digest(args.carrier_image)
    observed_image_digest = image_sha256_digest(container_image_id)
    started_at = normalize_container_started_time(
        status.get("state", {}).get("terminated", {}).get("startedAt")
        or status.get("state", {}).get("running", {}).get("startedAt")
    )
    hook_events = fetch_hook_timeline(
        cmd,
        args,
        container_id,
        pod_name,
        submit["boottime_ns"] - 1_000_000_000,
    )
    hook_path = raw_dir / "hook-timeline.jsonl"
    hook_path.write_text("".join(json_line(e) for e in hook_events))
    map_events, map_parse_errors = read_json_lines_checked(raw_dir / "mapwatch.jsonl")
    probe_events, probe_parse_errors = read_json_lines_checked(raw_dir / "probe.jsonl")
    summaries = [
        event for event in probe_events if event.get("event") == "probe_summary"
    ]
    application_syscall_evidence: dict[str, Any]
    try:
        counter_cgroup_id = (
            int(summaries[0].get("cgroup_id", 0)) if len(summaries) == 1 else 0
        )
    except (TypeError, ValueError):
        counter_cgroup_id = 0
    sygma_ready_events = [
        event
        for event in hook_events
        if event.get("event") == "sygma_direct_policy_ready"
    ]
    sygma_ready_boottime_ns: int | None = None
    if backend == "sygma" and len(sygma_ready_events) == 1:
        with contextlib.suppress(KeyError, TypeError, ValueError):
            sygma_ready_boottime_ns = int(sygma_ready_events[0]["boottime_ns"])
    if counter_cgroup_id > 0:
        application_syscall_evidence = fetch_application_syscalls(
            cmd,
            args,
            counter_cgroup_id,
            cleanup=True,
            before_boottime_ns=sygma_ready_boottime_ns,
        )
    else:
        application_syscall_evidence = {
            "available": False,
            "snapshot": None,
            "records": [],
            "reason": "probe_cgroup_id_unavailable",
        }
    application_snapshot = application_syscall_evidence.get("snapshot")
    application_counter_path = raw_dir / "application-syscalls.jsonl"
    application_counter_path.write_text(
        "".join(
            json_line(event)
            for event in application_syscall_evidence.get("records", [])
        )
    )
    if backend == "sygma":
        sygma_policy_evidence = build_sygma_application_evidence(
            hook_events, application_snapshot
        )
    else:
        sygma_policy_evidence = {
            "available": False,
            "positive": False,
            "reason": "not_sygma_arm",
        }
    evidence_path = raw_dir / "sygma-policy-evidence.jsonl"
    evidence_path.write_text(json_line(sygma_policy_evidence))

    if backend == "tetragon":
        tetragon_positive_evidence = fetch_tetragon_positive_events(
            cmd,
            tetragon_pod=tetragon_pod,
            namespace=args.namespace,
            pod_name=pod_name,
            container_id=container_id,
            since_time=terminal.get("metadata", {}).get("creationTimestamp"),
        )
    else:
        tetragon_positive_evidence = {
            "available": False,
            "reason": "not_tetragon_arm",
            "events": [],
        }
    tetragon_event_path = raw_dir / "tetragon-events.jsonl"
    tetragon_event_path.write_text(
        "".join(
            json_line(event)
            for event in tetragon_positive_evidence.get("events", [])
        )
    )
    phase = terminal.get("status", {}).get("phase", "") if terminal else ""
    reasons = []
    if creation_error:
        reasons.append(creation_error)
    reasons.extend(log_split_reasons)
    reasons.extend(map_parse_errors)
    reasons.extend(probe_parse_errors)
    if not application_syscall_evidence.get("available"):
        reasons.append("application_syscall_snapshot_unavailable")
    elif not application_snapshot or int(application_snapshot.get("total", 0)) <= 0:
        reasons.append("application_syscall_count_not_positive")
    elif int(application_snapshot.get("histogram_total", -1)) > int(
        application_snapshot.get("total", -2)
    ):
        # meta.total (an atomic counter) is read after the per-syscall
        # histogram is fully enumerated (see emit_app_syscalls in
        # mapwatch/policy_map_watch.c), so it can only be >= histogram_total;
        # anything else means the two counters disagree about the same
        # cgroup, which is a real inconsistency.
        reasons.append("application_syscall_histogram_total_mismatch")
    if backend == "sygma" and not sygma_policy_evidence.get("positive"):
        reasons.append("sygma_policy_not_ready_before_first_application_syscall")
    if status and int(status.get("restartCount", 0)) != 0:
        reasons.append(f"container_restart_count_{status.get('restartCount')}")
    terminated = status.get("state", {}).get("terminated", {}) if status else {}
    if terminated and int(terminated.get("exitCode", -1)) != 0:
        reasons.append(f"container_exit_code_{terminated.get('exitCode')}")
    if not container_id:
        reasons.append("missing_container_id")
    if not container_image_id or observed_image_digest is None:
        reasons.append("missing_container_image_digest")
    elif (
        requested_image_digest is not None
        and observed_image_digest != requested_image_digest
    ):
        reasons.append(
            "container_image_digest_mismatch_requested_"
            f"{requested_image_digest}_observed_{observed_image_digest}"
        )
    if not started_at:
        reasons.append("missing_container_started_time")
    reasons.extend(
        validate_trial_raw(
            backend,
            phase,
            probe_events,
            map_events,
            hook_events,
            expected_policy_id=policy_id if backend == "tetragon" else None,
            expected_application=args.application,
            expected_trial_id=trial_id,
            expected_container_id=container_id,
            expected_pod_uid=terminal.get("metadata", {}).get("uid"),
            expected_pod_name=pod_name,
        )
    )

    inserts = [event for event in map_events if event.get("event") == "map_insert"]
    if backend == "sygma":
        if sygma_policy_evidence.get("application_syscalls_uncovered") != 0:
            reasons.append("sygma_application_syscalls_uncovered_not_zero")
    if backend == "tetragon" and not tetragon_positive_evidence.get("positive"):
        absence_explanation = "not_observed_within_5s_exporter_poll"
        if len(summaries) == 1 and len(inserts) == 1:
            try:
                probe_end = int(summaries[0]["boottime_ns"])
                map_upper = int(inserts[0]["first_present_boottime_ns"])
                if map_upper >= probe_end:
                    absence_explanation = "map_insert_at_or_after_probe_end"
            except (KeyError, TypeError, ValueError):
                pass
        tetragon_positive_evidence["absence_explanation"] = absence_explanation
    if backend == "tetragon" and len(inserts) == 1 and application_snapshot:
        try:
            definite = int(
                inserts[0]["application_syscalls_uncovered_definite"]
            )
            possible = int(
                inserts[0]["application_syscalls_uncovered_possible"]
            )
            application_total = int(application_snapshot["total"])
        except (KeyError, TypeError, ValueError):
            reasons.append("tetragon_application_syscall_bounds_invalid")
        else:
            if not (0 <= definite <= possible <= application_total):
                reasons.append(
                    "tetragon_application_syscall_bounds_out_of_range_"
                    f"{definite}_{possible}_{application_total}"
                )
    probe_cgroup_id = summaries[0].get("cgroup_id") if len(summaries) == 1 else None
    map_cgroup_id = inserts[0].get("cgroup_id") if len(inserts) == 1 else None
    prestart_aborts = [
        event for event in hook_events if event.get("event") == "oci_prestart_abort"
    ]
    prestart_abort = prestart_aborts[0] if len(prestart_aborts) == 1 else None

    trial = {
        "schema_version": PROTOCOL_SCHEMA_VERSION,
        "trial_id": trial_id,
        "backend": backend,
        "application": args.application,
        "warmup": warmup,
        "valid": not reasons,
        "invalid_reason": "; ".join(reasons) if reasons else None,
        "pod_namespace": args.namespace,
        "pod_name": pod_name,
        "pod_uid": terminal.get("metadata", {}).get("uid"),
        "container_id": container_id,
        "container_id_runtime": full_container_id,
        "container_image": container_image,
        "container_image_id": container_image_id,
        "container_image_digest": observed_image_digest,
        "node_name": terminal.get("spec", {}).get("nodeName", node_name),
        "api_clock_domain": "runner_host",
        "api_submit_realtime_ns": submit["realtime_ns"],
        "api_submit_boottime_ns": submit["boottime_ns"],
        "api_ack_realtime_ns": ack["realtime_ns"],
        "api_ack_boottime_ns": ack["boottime_ns"],
        "pod_creation_time": terminal.get("metadata", {}).get("creationTimestamp"),
        "container_started_time": started_at,
        "container_exit_code": terminated.get("exitCode") if terminated else None,
        "container_termination_reason": terminated.get("reason") if terminated else None,
        "container_termination_message": terminated.get("message") if terminated else None,
        "pod_phase": phase,
        "probe_started": len([
            event for event in probe_events if event.get("event") == "probe_start"
        ]) == 1,
        "hook_prestart_abort": prestart_abort,
        "probe_cgroup_id": probe_cgroup_id,
        "tetragon_map_cgroup_id": map_cgroup_id,
        "tetragon_filter_id": policy_id if backend == "tetragon" else None,
        "tetragon_pre_snapshot": pre_snapshot,
        "application_syscall_snapshot": application_snapshot,
        "sygma_policy_evidence": {
            key: value
            for key, value in sygma_policy_evidence.items()
            if key != "records"
        },
        "tetragon_positive_evidence": {
            key: value
            for key, value in tetragon_positive_evidence.items()
            if key != "events"
        },
        "raw": {
            "container_log": str(raw_rel / "container.log"),
            "probe_jsonl": str(raw_rel / "probe.jsonl"),
            "wrapper_log": str(raw_rel / "wrapper.log"),
            "mapwatch_jsonl": str(raw_rel / "mapwatch.jsonl"),
            "application_syscalls_jsonl": str(
                raw_rel / "application-syscalls.jsonl"
            ),
            "hook_timeline_jsonl": str(raw_rel / "hook-timeline.jsonl"),
            "sygma_policy_evidence_jsonl": str(
                raw_rel / "sygma-policy-evidence.jsonl"
            ),
            "tetragon_events_jsonl": str(raw_rel / "tetragon-events.jsonl"),
            "pod_json": str(raw_rel / "pod.json"),
        },
    }

    delete_pod(cmd, args.namespace, pod_name)
    if backend == "sygma" and container_id:
        hook_events = wait_hook_cleanup(
            cmd,
            args,
            container_id,
            pod_name,
            submit["boottime_ns"] - 1_000_000_000,
        )
        hook_path.write_text("".join(json_line(e) for e in hook_events))
        cleanup_events = [
            event for event in hook_events
            if event.get("event") == "sygma_cleanup_complete"
        ]
        if len(cleanup_events) != 1:
            trial["valid"] = False
            extra = f"sygma_cleanup_complete_count_{len(cleanup_events)}"
            trial["invalid_reason"] = "; ".join(
                value for value in [trial.get("invalid_reason"), extra] if value
            )
    if backend == "tetragon":
        try:
            post = map_snapshot(cmd, args, policy_id)
            trial["tetragon_post_snapshot"] = post
            target_cgroup = int(map_cgroup_id) if map_cgroup_id is not None else 0
            retained = {
                int(value) for value in post.get("cgroup_ids", [])
            }
            trial["tetragon_cleanup_observed"] = (
                target_cgroup > 0 and target_cgroup not in retained
            )
        except Exception as exc:
            trial["valid"] = False
            extra = f"policy_map_post_snapshot: {exc}"
            trial["invalid_reason"] = "; ".join(
                x for x in [trial.get("invalid_reason"), extra] if x
            )
    return trial


def make_schedule(
    trials: int, warmups: int, seed: int, arms: Sequence[str] = ("sygma", "tetragon")
) -> list[tuple[str, bool, int]]:
    rng = random.Random(seed)
    schedule: list[tuple[str, bool, int]] = []
    for warmup, blocks in ((True, warmups), (False, trials)):
        for index in range(1, blocks + 1):
            block_arms = list(arms)
            rng.shuffle(block_arms)
            schedule.extend((arm, warmup, index) for arm in block_arms)
    return schedule


def capture_metadata(
    cmd: Commands,
    args: argparse.Namespace,
    node_name: str,
    tetragon_pod: str,
    tetragon_mode: dict[str, Any],
    policy_state: dict[str, Any],
    policy_id: int,
    hook_hash: dict[str, str],
    redis_policy: dict[str, Any],
    schedule: list[tuple[str, bool, int]],
    sygma_pinned_map_capability: dict[str, Any] | None = None,
    carrier_image_policy: dict[str, Any] | None = None,
    sygma_component_hashes: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    def optional(argv: list[str]) -> dict[str, Any]:
        cp = cmd.run(argv, timeout=30, check=False)
        return {"returncode": cp.returncode, "stdout": cp.stdout, "stderr": cp.stderr}

    nodes = cmd.kubectl_json(["get", "nodes", "-o", "json"])
    target_nodes = [
        node for node in nodes.get("items", [])
        if node.get("metadata", {}).get("name") == node_name
    ]
    if len(target_nodes) != 1:
        raise ExperimentError(
            f"target node metadata is ambiguous or missing for {node_name}"
        )
    target_node = target_nodes[0]
    tetragon_ds = cmd.kubectl_json(
        ["get", "ds", "tetragon", "-n", "kube-system", "-o", "json"]
    )
    kube_system_pods = cmd.kubectl_json(
        ["get", "pods", "-n", "kube-system", "-o", "json"]
    )
    target_node_pods = cmd.kubectl_json(
        [
            "get",
            "pods",
            "-A",
            "--field-selector",
            f"spec.nodeName={node_name}",
            "-o",
            "json",
        ]
    )
    return {
        "schema_version": PROTOCOL_SCHEMA_VERSION,
        "run_id": args.run_id,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "arguments": {
            key: str(value) if isinstance(value, pathlib.Path) else value
            for key, value in vars(args).items()
        },
        "source_snapshot_sha256": source_snapshot_hash(),
        "node_name": node_name,
        "nodes": nodes,
        "target_node": target_node,
        "target_node_info": target_node.get("status", {}).get("nodeInfo", {}),
        "target_node_pods": target_node_pods,
        "tetragon_pod": tetragon_pod,
        "tetragon_daemonset": tetragon_ds,
        "kube_system_pods": kube_system_pods,
        "tetragon_mode": tetragon_mode,
        "tetragon_policy_filter_id": policy_id,
        "tetragon_policy_state": policy_state,
        "hook_hash": hook_hash,
        "sygma_component_hashes": sygma_component_hashes,
        "sygma_pinned_map_capability": sygma_pinned_map_capability,
        "sygma_redis_policy": redis_policy,
        "carrier_image_policy": carrier_image_policy,
        "schedule": [
            {"backend": backend, "warmup": warmup, "block": block}
            for backend, warmup, block in schedule
        ],
        # These commands execute where the runner lives. Target-node runtime
        # identity comes from target_node.status.nodeInfo above.
        "runner_host_uname": optional(["uname", "-a"]),
        "runner_host_containerd_version": optional(["containerd", "--version"]),
        "runner_host_runc_version": optional(["runc", "--version"]),
        "git_head": optional(["git", "rev-parse", "HEAD"]),
        "git_status": optional(["git", "status", "--short"]),
    }


def cleanup_owned(cmd: Commands, args: argparse.Namespace) -> list[str]:
    """Best-effort cleanup of only resources with experiment-owned identity."""

    operations = [
        (
            "pods",
            [
                "delete",
                "pods",
                "-n",
                args.namespace,
                "-l",
                f"app.kubernetes.io/part-of={EXPERIMENT_PART_OF_LABEL}",
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout=45s",
            ],
            55,
        ),
        (
            "tetragon_policy",
            [
                "delete",
                "tracingpoliciesnamespaced.cilium.io",
                POLICY_NAME,
                "-n",
                args.namespace,
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout=45s",
            ],
            55,
        ),
        (
            "binary_configmaps",
            [
                "delete",
                "configmaps",
                "startup-gap-probe-bin",
                "startup-gap-mapwatch-bin",
                "-n",
                args.namespace,
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout=30s",
            ],
            40,
        ),
    ]
    errors: list[str] = []
    for name, argv, timeout in operations:
        try:
            cp = cmd.kubectl_run(argv, timeout=timeout, check=False)
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            continue
        if cp.returncode != 0:
            errors.append(
                f"{name}: kubectl exit {cp.returncode}: "
                f"{(cp.stderr or cp.stdout or '').strip()[-1000:]}"
            )
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=100, help="measured blocks per arm")
    parser.add_argument("--warmups", type=int, default=10, help="warm-up blocks per arm")
    parser.add_argument("--duration-ms", type=int, default=5000)
    parser.add_argument(
        "--evidence-hold-ms",
        type=int,
        default=5000,
        help="post-summary non-measurement hold for live map evidence",
    )
    parser.add_argument("--interval-us", type=int, default=1000)
    parser.add_argument("--map-poll-us", type=int, default=200)
    parser.add_argument(
        "--infrastructure-retries",
        type=int,
        default=2,
        help=(
            "replacement attempts allowed only for a SYGMA StartError proven "
            "to occur in prestart before any application execution"
        ),
    )
    parser.add_argument("--seed", type=int, default=20260802)
    parser.add_argument(
        "--arms",
        default="sygma,tetragon",
        help="comma-separated subset of {sygma,tetragon} to schedule (default: both)",
    )
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument("--node", help="pin to this node; single ready node is required otherwise")
    parser.add_argument(
        "--application",
        choices=APPLICATIONS,
        default="nginx",
        help=(
            "workload profile; real applications require an immutable image "
            "built with the baked gap-launch entrypoint"
        ),
    )
    parser.add_argument(
        "--carrier-image",
        default="localhost/sygma-q3/installer:artifact-v1",
        help=(
            "cached carrier image; primary runs require IMAGE@sha256:DIGEST "
            "(the mutable default is diagnostic-only)"
        ),
    )
    parser.add_argument(
        "--observer-image",
        help=(
            "separate immutable utility image for the privileged observer "
            "(defaults to --carrier-image)"
        ),
    )
    parser.add_argument(
        "--image-pull-policy", choices=["Never", "IfNotPresent", "Always"], default="Never"
    )
    parser.add_argument("--redis-addr")
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--run-id", default=utc_run_id())
    parser.add_argument("--results-root", type=pathlib.Path, default=EVAL_ROOT / "results")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-sygma-policy", action="store_true")
    parser.add_argument(
        "--allow-hook-hash-mismatch",
        action="store_true",
        help="legacy diagnostic only: allow only the hook artifact mismatch",
    )
    parser.add_argument(
        "--diagnostic-allow-sygma-artifact-mismatch",
        action="store_true",
        help="diagnostic only: allow core/hook/tracer/wrapper artifact mismatch",
    )
    parser.add_argument("--allow-unexpected-tetragon-config", action="store_true")
    parser.add_argument(
        "--diagnostic-skip-sygma-canary",
        "--diagnostic-skip-sygma-readiness-canary",
        action="store_true",
        dest="diagnostic_skip_sygma_canary",
        help=(
            "diagnostic only: continue even though the mandatory pre-campaign "
            "SYGMA readiness canary is skipped"
        ),
    )
    parser.add_argument("--keep-resources", action="store_true")
    args = parser.parse_args()
    if args.trials < 1 or args.warmups < 0 or args.infrastructure_retries < 0:
        parser.error(
            "--trials must be >=1, --warmups must be >=0, and "
            "--infrastructure-retries must be >=0"
        )
    if (
        args.duration_ms < 100
        or args.evidence_hold_ms < 100
        or args.interval_us < 1
        or args.map_poll_us < 1
    ):
        parser.error("invalid timing parameter")
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    if not arms or any(a not in ("sygma", "tetragon") for a in arms) or len(set(arms)) != len(arms):
        parser.error("--arms must be a comma-separated subset of {sygma,tetragon} with no duplicates")
    args.arms = arms
    return args


def main() -> int:
    args = parse_args()
    ensure_tools(args)
    result_dir = args.results_root.resolve() / args.run_id
    result_dir.mkdir(parents=True, exist_ok=False)
    (result_dir / "raw").mkdir()
    cmd = Commands(result_dir, args.kubectl)
    trials_path = result_dir / "trials.jsonl"
    infrastructure_failures_path = result_dir / "infrastructure-failures.jsonl"
    summary_error: str | None = None

    try:
        carrier_image_policy = validate_carrier_image_policy(args)
        if not args.skip_build:
            cmd.run(["bash", str(EVAL_ROOT / "scripts" / "build.sh")], timeout=120)
        probe_bin = EVAL_ROOT / "build" / "gap-probe"
        mapwatch_bin = EVAL_ROOT / "build" / "policy-map-watch"

        ensure_namespace(cmd, args.namespace)
        apply_binary_configmap(
            cmd, args.namespace, "startup-gap-probe-bin", "gap-probe", probe_bin
        )
        apply_binary_configmap(
            cmd,
            args.namespace,
            "startup-gap-mapwatch-bin",
            "policy-map-watch",
            mapwatch_bin,
        )

        nodes = cmd.kubectl_json(["get", "nodes", "-o", "json"])
        ready_nodes = []
        for node in nodes.get("items", []):
            conditions = node.get("status", {}).get("conditions", [])
            if any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in conditions
            ):
                ready_nodes.append(node["metadata"]["name"])
        if args.node:
            if args.node not in ready_nodes:
                raise ExperimentError(f"requested node is not Ready: {args.node}")
            node_name = args.node
        elif len(ready_nodes) == 1:
            node_name = ready_nodes[0]
        else:
            raise ExperimentError(
                f"select --node explicitly; ready nodes are {ready_nodes}"
            )
        selected_node = next(
            node for node in nodes.get("items", [])
            if node.get("metadata", {}).get("name") == node_name
        )
        architecture = str(
            selected_node.get("status", {}).get("nodeInfo", {}).get("architecture", "")
        ).lower()
        if architecture not in {"amd64", "x86_64"}:
            raise ExperimentError(
                f"startup-gap probe supports x86-64 only; node {node_name} "
                f"reports architecture {architecture or 'unknown'}"
            )

        delete_pod(cmd, args.namespace, OBSERVER_NAME)
        cmd.kubectl_json(
            ["create", "-f", "-", "-o", "json"],
            obj=observer_object(args, node_name),
            timeout=45,
        )
        observer_ready = wait_pod_condition(
            cmd, args.namespace, OBSERVER_NAME, ready=True, timeout=60
        )
        observer_status = container_status(
            observer_ready, container_name="observer"
        )
        observer_image_id = str(observer_status.get("imageID", ""))
        observer_observed_digest = image_sha256_digest(observer_image_id)
        carrier_image_policy["observer_observed_image_id"] = observer_image_id
        carrier_image_policy["observer_observed_digest"] = observer_observed_digest
        observer_requested_digest = carrier_image_policy.get("observer_digest")
        if observer_requested_digest is not None and (
            observer_observed_digest != observer_requested_digest
        ):
            raise ExperimentError(
                "observer image digest mismatch: requested "
                f"{observer_requested_digest}, observed {observer_observed_digest}"
            )

        sygma_pinned_map_capability = preflight_sygma_pinned_maps(cmd, args)

        tetragon_mode = verify_tetragon_mode(
            cmd, args.allow_unexpected_tetragon_config
        )
        tetragon_mode["policy_isolation"] = verify_tetragon_policy_isolation(
            cmd, args.namespace, args.application
        )
        tetragon_pod = find_tetragon_pod(cmd, node_name)
        sygma_core = find_sygma_core_container(cmd, node_name)

        # Recreate only our namespaced policy, then wait until the agent says
        # ENABLED before creating any workload Pod.
        cmd.kubectl_run(
            [
                "delete",
                "tracingpoliciesnamespaced.cilium.io",
                POLICY_NAME,
                "-n",
                args.namespace,
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout=45s",
            ],
            timeout=55,
            check=False,
        )
        cmd.apply_object(tetragon_policy_object(args.namespace))
        policy_id, policy_state = wait_tetragon_policy(
            cmd, tetragon_pod, args.namespace
        )
        wait_policy_map_empty(cmd, args, policy_id)

        sygma_component_hashes = installed_sygma_component_hashes(cmd, args)
        sygma_component_hashes["core"] = hash_running_sygma_core(cmd, sygma_core)
        artifact_verification = verify_sygma_component_artifacts(
            args, sygma_component_hashes
        )
        sygma_component_hashes["artifact_verification"] = artifact_verification
        hook_hash = artifact_verification["hook"]
        redis_addr = discover_redis_addr(cmd, args.redis_addr)
        redis_policy: dict[str, Any]
        if args.skip_sygma_policy:
            redis_policy = {"skipped": True, "redis_addr": redis_addr}
        else:
            redis_policy = prepare_sygma_policy(
                cmd, redis_addr, args.application
            )

        schedule = make_schedule(args.trials, args.warmups, args.seed, arms=args.arms)
        metadata = capture_metadata(
            cmd,
            args,
            node_name,
            tetragon_pod,
            tetragon_mode,
            policy_state,
            policy_id,
            hook_hash,
            redis_policy,
            schedule,
            sygma_pinned_map_capability=sygma_pinned_map_capability,
            carrier_image_policy=carrier_image_policy,
            sygma_component_hashes=sygma_component_hashes,
        )
        metadata["infrastructure_retry_policy"] = {
            "maximum_replacement_attempts_per_logical_trial": (
                args.infrastructure_retries
            ),
            "eligible_failure_class": (
                "sygma_prestart_start_error_before_application"
            ),
            "raw_failure_records": str(infrastructure_failures_path.name),
            "application_or_atomicity_failures_are_retryable": False,
        }
        (result_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True)
        )

        # Run one unmeasured SYGMA canary before the campaign.  It validates
        # the hook readiness/barrier timeline and observation-only behavior:
        # every timed target call must remain successful.
        if args.diagnostic_skip_sygma_canary:
            canary = {
                "valid": False,
                "skipped": True,
                "purpose": "sygma_readiness_preflight",
                "invalid_reason": "diagnostic_skip_sygma_canary",
            }
        else:
            canary = run_trial(
                cmd,
                args,
                backend="sygma",
                trial_id="preflight-sygma-canary",
                warmup=True,
                node_name=node_name,
                policy_id=policy_id,
                result_dir=result_dir,
                tetragon_pod=tetragon_pod,
            )
            canary["purpose"] = "sygma_readiness_preflight"
        metadata["sygma_readiness_canary"] = canary
        (result_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True)
        )
        (result_dir / "sygma-canary.json").write_text(
            json.dumps(canary, indent=2, sort_keys=True)
        )
        if not canary.get("valid") and not args.diagnostic_skip_sygma_canary:
            raise ExperimentError(
                "SYGMA readiness canary failed: "
                + str(canary.get("invalid_reason") or "unknown reason")
            )

        counters = {"warmup": 0, "measured": 0}
        infrastructure_failure_attempts = 0
        replacement_attempts_started = 0
        total = len(schedule)
        for ordinal, (backend, warmup, block) in enumerate(schedule, 1):
            prefix = "w" if warmup else "m"
            counters["warmup" if warmup else "measured"] += 1
            trial_id = f"{prefix}{block:03d}-{backend}"
            trial: dict[str, Any]
            for attempt_number in range(1, args.infrastructure_retries + 2):
                attempt_trial_id = f"{trial_id}-a{attempt_number:02d}"
                print(
                    f"[{ordinal}/{total}] {trial_id} "
                    f"(attempt {attempt_number}/{args.infrastructure_retries + 1})",
                    flush=True,
                )
                try:
                    trial = run_trial(
                        cmd,
                        args,
                        backend=backend,
                        trial_id=attempt_trial_id,
                        warmup=warmup,
                        node_name=node_name,
                        policy_id=policy_id,
                        result_dir=result_dir,
                        tetragon_pod=tetragon_pod,
                    )
                except Exception as exc:
                    traceback.print_exc()
                    failed_pod_name = (
                        "gap-" + attempt_trial_id.lower()
                    ).replace("_", "-")[:63].rstrip("-")
                    with contextlib.suppress(Exception):
                        delete_pod(cmd, args.namespace, failed_pod_name)
                    trial = {
                        "schema_version": PROTOCOL_SCHEMA_VERSION,
                        "trial_id": attempt_trial_id,
                        "backend": backend,
                        "application": args.application,
                        "warmup": warmup,
                        "valid": False,
                        "invalid_reason": f"runner_exception: {exc}",
                        "raw": {},
                    }

                trial["attempt_trial_id"] = attempt_trial_id
                trial["logical_trial_id"] = trial_id
                trial["attempt_number"] = attempt_number
                trial["trial_id"] = trial_id
                failure_class = retryable_infrastructure_failure(trial)
                trial["failure_class"] = failure_class
                if failure_class is None:
                    break

                infrastructure_failure_attempts += 1
                append_trial(infrastructure_failures_path, trial)
                if attempt_number <= args.infrastructure_retries:
                    replacement_attempts_started += 1
                    print(
                        "  retrying replacement trial after pre-application "
                        f"infrastructure failure: {attempt_trial_id}",
                        flush=True,
                    )
                    continue
                trial["infrastructure_retry_exhausted"] = True
                break

            trial["infrastructure_retries_used"] = int(
                trial.get("attempt_number", 1)
            ) - 1
            append_trial(trials_path, trial)

        metadata["infrastructure_retry_observation"] = {
            "failure_attempts": infrastructure_failure_attempts,
            "replacement_attempts_started": replacement_attempts_started,
        }
        (result_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True)
        )

        analyzer = EVAL_ROOT / "scripts" / "analyze.py"
        cp = cmd.run(
            [sys.executable, str(analyzer), str(result_dir)],
            timeout=120,
            check=False,
        )
        if cp.returncode != 0:
            summary_error = (cp.stderr or cp.stdout or "analysis failed")[-4000:]
            raise ExperimentError(summary_error)
        print(f"Results: {result_dir}")
        return 0
    except Exception as exc:
        (result_dir / "RUN_FAILED.txt").write_text(
            f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}"
        )
        print(f"ERROR: {exc}\nPartial results: {result_dir}", file=sys.stderr)
        return 1
    finally:
        if not args.keep_resources:
            cleanup_errors = cleanup_owned(cmd, args)
            if cleanup_errors:
                (result_dir / "CLEANUP_FAILED.txt").write_text(
                    "\n".join(cleanup_errors) + "\n"
                )
                print(
                    "WARNING: experiment resource cleanup was incomplete; see "
                    f"{result_dir / 'CLEANUP_FAILED.txt'}",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    raise SystemExit(main())
