#!/usr/bin/env python3
"""Strict repeated-deployment evaluation of SYGMA initialization policies."""

import argparse
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time


HERE = Path(__file__).resolve().parent
MANIFEST = HERE.parent
KUBECTL_REQUEST_TIMEOUT = 10
REQUIRED_STATE_MAPS = {
    "syscall_graph_map",
    "pid_mount_ns_map",
    "execution_time_map",
    "process_state_map",
    "tid_to_namespace",
    "container_info_map",
}
APPS = {
    "nginx": (MANIFEST / "nginx-sygmaconfig.yaml", MANIFEST / "nginx_sygma.yaml"),
    "redis": (MANIFEST / "redis-sygmaconfig.yaml", MANIFEST / "redis.yaml"),
    "mysql": (HERE / "mysql-sygmaconfig.yaml", HERE / "mysql.yaml"),
    "httpd": (HERE / "httpd-sygmaconfig.yaml", HERE / "httpd.yaml"),
}

CSV_FIELDS = [
    "iteration",
    "valid",
    "invalid_reason",
    "ready",
    "init_violation",
    "init_unique_transitions",
    "init_events",
    "pod_uid",
    "previous_pod_uid",
    "container_id",
    "previous_container_id",
    "identity_replaced",
    "node_name",
    "restart_count",
    "host_pid",
    "mntns",
    "pidns",
    "phase0_graph_rows",
    "phase0_start_row",
    "pid_mount_value",
    "execution_time",
    "process_image_id",
    "heartbeat_before",
    "heartbeat_after",
    "heartbeat_delta",
    "blocked_map_id",
    "heartbeat_map_id",
    "ready_error",
]


class CommandError(RuntimeError):
    """An external command failed for an operational reason."""


class InvalidMeasurement(RuntimeError):
    """The detector could not prove that an iteration was measurable."""


def command(*args, check=True, capture=False, timeout=None):
    try:
        result = subprocess.run(
            args,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise CommandError(
            f"command timed out after {timeout}s: {' '.join(args)}"
        ) from error
    if check and result.returncode:
        detail = ""
        if capture:
            detail = (result.stderr or result.stdout or "").strip()
        raise CommandError(
            f"command failed ({result.returncode}): {' '.join(args)}"
            + (f"\n{detail}" if detail else "")
        )
    return result


def snapshot(kind, *options):
    result = command(
        sys.executable,
        str(HERE / "map_snapshot.py"),
        kind,
        *map(str, options),
        capture=True,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise InvalidMeasurement(f"{kind} snapshot returned invalid JSON: {error}") from error


def counter_snapshot(kind):
    value = snapshot(kind)
    required = {
        "id",
        "type",
        "key_size",
        "value_size",
        "max_entries",
        "entry_count",
        "entries",
    }
    missing = required.difference(value)
    if missing:
        raise InvalidMeasurement(f"{kind} snapshot lacks fields: {sorted(missing)}")
    if value["entry_count"] >= value["max_entries"]:
        raise InvalidMeasurement(
            f"{kind} map is full ({value['entry_count']}/{value['max_entries']})"
        )
    return value


def assert_same_counter_map(before, after, label):
    if before["id"] != after["id"]:
        raise InvalidMeasurement(
            f"{label} map changed during the iteration "
            f"(id {before['id']} -> {after['id']})"
        )
    if after["entry_count"] >= after["max_entries"]:
        raise InvalidMeasurement(
            f"{label} map became full "
            f"({after['entry_count']}/{after['max_entries']})"
        )


def normalize_container_id(container_id):
    value = container_id.strip()
    if "://" in value:
        _runtime, value = value.split("://", 1)
    if not value:
        raise InvalidMeasurement("Pod has an empty container ID")
    return value


def get_pod(namespace, app, required=False):
    result = command(
        "kubectl",
        "get",
        f"pod/{app}",
        "-n",
        namespace,
        "-o",
        "json",
        f"--request-timeout={KUBECTL_REQUEST_TIMEOUT}s",
        check=False,
        capture=True,
        timeout=KUBECTL_REQUEST_TIMEOUT + 2,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        lowered = detail.lower()
        exact_not_found = (
            "(notfound)" in lowered
            and f'pods "{app.lower()}" not found' in lowered
        )
        if exact_not_found:
            if required:
                raise InvalidMeasurement(f"pod/{app} does not exist")
            return None
        raise CommandError(
            f"command failed ({result.returncode}): kubectl get pod/{app}\n{detail}"
        )
    try:
        pod = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CommandError(f"kubectl returned invalid Pod JSON: {error}") from error
    if not isinstance(pod, dict):
        raise CommandError("kubectl returned a non-object Pod")
    return pod


def pod_identity(pod, container_name):
    metadata = pod.get("metadata") or {}
    status = pod.get("status") or {}
    uid = metadata.get("uid")
    node_name = (pod.get("spec") or {}).get("nodeName")
    statuses = status.get("containerStatuses") or []
    matching = [item for item in statuses if item.get("name") == container_name]
    if len(matching) != 1:
        raise InvalidMeasurement(
            f"expected one status for container {container_name!r}, got {len(matching)}"
        )
    container = matching[0]
    raw_container_id = container.get("containerID")
    running = (container.get("state") or {}).get("running")
    if not uid or not node_name or not raw_container_id or not running:
        raise InvalidMeasurement(
            "Pod identity is incomplete or its target container is not running"
        )
    restart_count = int(container.get("restartCount", 0))
    if restart_count != 0:
        raise InvalidMeasurement(
            f"target container restarted within this deployment ({restart_count} restarts)"
        )
    return {
        "pod_uid": uid,
        "container_id": normalize_container_id(raw_container_id),
        "node_name": node_name,
        "restart_count": restart_count,
    }


def assert_identity_equal(observed, expected, context):
    for field in ("pod_uid", "container_id"):
        if observed[field] != expected[field]:
            raise InvalidMeasurement(
                f"{context}: {field} changed unexpectedly "
                f"({expected[field]} -> {observed[field]})"
            )


def assert_identity_replaced(previous, current):
    if previous["pod_uid"] == current["pod_uid"]:
        raise InvalidMeasurement("new deployment reused the previous Pod UID")
    if previous["container_id"] == current["container_id"]:
        raise InvalidMeasurement("new deployment reused the previous container ID")


def pod_uid(pod):
    uid = (pod.get("metadata") or {}).get("uid")
    if not uid:
        raise InvalidMeasurement("Pod metadata has no UID")
    return uid


def current_container_id(pod, container_name):
    statuses = (pod.get("status") or {}).get("containerStatuses") or []
    matching = [item for item in statuses if item.get("name") == container_name]
    if len(matching) > 1:
        raise InvalidMeasurement(
            f"multiple statuses exist for container {container_name!r}"
        )
    if not matching or not matching[0].get("containerID"):
        return None
    return normalize_container_id(matching[0]["containerID"])


def command_detail(result):
    return (result.stderr or result.stdout or "").strip()


def transient_delete_error(detail):
    value = detail.lower()
    return not value or any(
        marker in value
        for marker in (
            "connection refused",
            "connection reset",
            "context deadline exceeded",
            "eof",
            "i/o timeout",
            "server is currently unable",
            "service unavailable",
            "temporarily unavailable",
            "timed out",
            "tls handshake timeout",
            "too many requests",
            "unable to connect",
        )
    )


def delete_request(namespace, app, request_timeout=KUBECTL_REQUEST_TIMEOUT):
    return command(
        "kubectl",
        "delete",
        f"pod/{app}",
        "-n",
        namespace,
        "--wait=false",
        f"--request-timeout={request_timeout}s",
        check=False,
        capture=True,
        timeout=request_timeout + 2,
    )


def wait_pod_absent(
    namespace,
    app,
    expected_uid,
    timeout,
    initial_result=None,
    expected_container_id=None,
):
    """Poll by exact Pod UID until deletion converges to NotFound.

    A nonzero delete-client exit is not itself a deletion failure. The API may
    have accepted and completed the request before a watch/connection error.
    The authoritative success condition here is observing NotFound.
    """

    deadline = time.monotonic() + timeout
    result = initial_result
    attempts = 1 if result is not None else 0
    next_retry = time.monotonic() + 0.5
    last_get_error = None

    while True:
        try:
            pod = get_pod(namespace, app)
            last_get_error = None
        except CommandError as error:
            if not transient_delete_error(str(error)):
                raise
            pod = None
            last_get_error = error

        if last_get_error is None:
            if pod is None:
                return

            current_uid = pod_uid(pod)
            if current_uid != expected_uid:
                raise InvalidMeasurement(
                    f"a different pod/{app} UID appeared after the delete "
                    f"request ({expected_uid} -> {current_uid})"
                )

            deletion_started = bool(
                (pod.get("metadata") or {}).get("deletionTimestamp")
            )
            if not deletion_started and expected_container_id is not None:
                observed_container_id = current_container_id(pod, app)
                if (
                    observed_container_id is not None
                    and observed_container_id != expected_container_id
                ):
                    raise InvalidMeasurement(
                        f"pod/{app} container changed while waiting for deletion "
                        f"({expected_container_id} -> {observed_container_id})"
                    )
            if (
                not deletion_started
                and result is not None
                and result.returncode
                and not transient_delete_error(command_detail(result))
            ):
                raise CommandError(
                    f"kubectl delete pod/{app} failed ({result.returncode}): "
                    f"{command_detail(result)}"
                )

            now = time.monotonic()
            if not deletion_started and now >= next_retry:
                remaining = max(deadline - now, 0.1)
                request_timeout = max(
                    1, min(KUBECTL_REQUEST_TIMEOUT, int(remaining))
                )
                result = delete_request(
                    namespace,
                    app,
                    request_timeout=request_timeout,
                )
                attempts += 1
                next_retry = now + min(0.5 * (2 ** min(attempts - 1, 3)), 5.0)

        if time.monotonic() >= deadline:
            details = []
            if result is not None and result.returncode:
                details.append(
                    f"last delete error ({result.returncode}): "
                    f"{command_detail(result) or '<empty>'}"
                )
            if last_get_error is not None:
                details.append(f"last GET error: {last_get_error}")
            suffix = f" ({'; '.join(details)})" if details else ""
            raise CommandError(
                f"pod/{app} with UID {expected_uid} was not observed as "
                f"NotFound within {timeout}s{suffix}"
            )
        time.sleep(0.1)


def delete_pod(namespace, app, timeout, expected_identity=None):
    pod = get_pod(namespace, app)
    if pod is None:
        if expected_identity is not None:
            raise InvalidMeasurement(
                f"pod/{app} disappeared before the runner could delete it"
            )
        return

    expected_uid = pod_uid(pod)
    expected_container_id = None
    if expected_identity is not None:
        if expected_uid != expected_identity["pod_uid"]:
            raise InvalidMeasurement(
                f"before deletion: pod_uid changed unexpectedly "
                f"({expected_identity['pod_uid']} -> {expected_uid})"
            )
        expected_container_id = expected_identity.get("container_id")
        if not (pod.get("metadata") or {}).get("deletionTimestamp"):
            if expected_container_id is not None:
                current_identity = pod_identity(pod, app)
                assert_identity_equal(
                    current_identity, expected_identity, "before deletion"
                )
        else:
            observed_container_id = current_container_id(pod, app)
            if (
                expected_container_id is not None
                and observed_container_id is not None
                and observed_container_id != expected_container_id
            ):
                raise InvalidMeasurement(
                    f"terminating pod/{app} has a different container ID "
                    f"({expected_container_id} -> {observed_container_id})"
                )
            wait_pod_absent(
                namespace,
                app,
                expected_uid,
                timeout,
                expected_container_id=expected_container_id,
            )
            print(f"pod/{app} deleted (UID {expected_uid})", flush=True)
            return

    result = delete_request(namespace, app)
    wait_pod_absent(
        namespace,
        app,
        expected_uid,
        timeout,
        initial_result=result,
        expected_container_id=expected_container_id,
    )
    print(f"pod/{app} deleted (UID {expected_uid})", flush=True)


def create_pod(namespace, workload):
    # `create` must fail on AlreadyExists; an `apply ... unchanged` is never a
    # successful deployment iteration.
    result = command(
        "kubectl",
        "create",
        "-f",
        str(workload),
        "-n",
        namespace,
        "-o",
        "json",
        f"--request-timeout={KUBECTL_REQUEST_TIMEOUT}s",
        capture=True,
        timeout=KUBECTL_REQUEST_TIMEOUT + 2,
    )
    try:
        created = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CommandError(f"kubectl create returned invalid Pod JSON: {error}") from error
    return {"pod_uid": pod_uid(created)}


def wait_ready(namespace, app, timeout):
    result = command(
        "kubectl",
        "wait",
        "--for=condition=Ready",
        f"pod/{app}",
        "-n",
        namespace,
        f"--timeout={timeout}s",
        check=False,
        capture=True,
    )
    detail = (result.stderr or result.stdout).strip()
    if result.returncode == 0:
        return True, detail

    lowered = detail.lower()
    timeout_markers = (
        "timed out waiting for the condition",
        "timed out waiting for condition",
        "context deadline exceeded",
    )
    if any(marker in lowered for marker in timeout_markers):
        return False, detail
    raise CommandError(
        f"kubectl wait failed ({result.returncode}) for pod/{app}: {detail}"
    )


def resolve_namespace(container_id):
    value = snapshot("namespace", "--container-id", container_id)
    required = {"container_id", "host_pid", "mntns", "pidns", "source"}
    missing = required.difference(value)
    if missing:
        raise InvalidMeasurement(f"namespace resolution lacks fields: {sorted(missing)}")
    if value["container_id"] != container_id:
        raise InvalidMeasurement(
            "namespace resolver returned a different container ID "
            f"({value['container_id']} != {container_id})"
        )
    for field in ("host_pid", "mntns", "pidns"):
        if int(value[field]) <= 0:
            raise InvalidMeasurement(f"namespace resolver returned invalid {field}")
    return value


def detector_readiness(namespace):
    readiness = snapshot(
        "readiness",
        "--mntns",
        namespace["mntns"],
        "--pidns",
        namespace["pidns"],
        "--host-pid",
        namespace["host_pid"],
    )
    if int(readiness.get("phase0_graph_rows", 0)) <= 0:
        raise InvalidMeasurement("no phase-0 policy rows exist for the exact namespace")
    if readiness.get("phase0_start_row") is not True:
        raise InvalidMeasurement(
            "phase-0 policy lacks the START transition row (from_syscall=500)"
        )
    for name in (
        "syscall_graph_map",
        "process_state_map",
        "tid_to_namespace",
        "container_info_map",
    ):
        metadata = (readiness.get("maps") or {}).get(name) or {}
        if int(metadata.get("entry_count", -1)) < 0:
            raise InvalidMeasurement(f"{name} entry count is unavailable")
        if int(metadata["entry_count"]) >= int(metadata.get("max_entries", 0)):
            raise InvalidMeasurement(
                f"{name} is full "
                f"({metadata['entry_count']}/{metadata.get('max_entries')})"
            )

    pid_mount_value = readiness.get("pid_mount_value")
    if pid_mount_value is None or int(pid_mount_value) <= 0:
        raise InvalidMeasurement("pid_mount_ns_map lacks the exact namespace")

    execution = readiness.get("execution")
    if not isinstance(execution, dict):
        raise InvalidMeasurement("execution_time_map lacks the exact namespace")
    if not execution.get("comm"):
        raise InvalidMeasurement("execution_time_map has an empty target binary")
    if execution.get("execution_time") != 1:
        raise InvalidMeasurement(
            "main-binary exec phase boundary was not observed "
            f"(execution_time={execution.get('execution_time')})"
        )

    process_state = readiness.get("root_process_state")
    if not isinstance(process_state, dict):
        raise InvalidMeasurement("process_state_map lacks the container root host PID")
    if int(process_state.get("image_id", 0)) <= 0:
        raise InvalidMeasurement(
            "root process_state is not an enforcement state (image_id <= 0)"
        )
    if readiness.get("root_tid_namespace_match") is not True:
        raise InvalidMeasurement(
            "tid_to_namespace does not link the container root PID "
            "to the exact namespace"
        )
    if int(len(readiness.get("namespace_tids") or [])) <= 0:
        raise InvalidMeasurement("no TID is linked to the exact namespace")
    if not readiness.get("container_info"):
        raise InvalidMeasurement("container_info_map lacks the exact namespace")
    return readiness


def wait_detector_readiness(namespace, timeout):
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        try:
            return detector_readiness(namespace)
        except InvalidMeasurement as error:
            last_error = error
        if time.monotonic() >= deadline:
            raise InvalidMeasurement(
                f"detector did not become ready within {timeout}s: {last_error}"
            ) from last_error
        time.sleep(0.1)


def _counter_has_namespace(metadata, namespace, phase_position):
    for key in metadata["entries"]:
        parts = list(map(int, key.split(":")))
        if (
            parts[0] == namespace["mntns"]
            and parts[1] == namespace["pidns"]
            and (phase_position is None or parts[phase_position] in (0, 1))
        ):
            return True
    return False


def assert_namespace_cleaned(namespace, blocked, heartbeat):
    if _counter_has_namespace(blocked, namespace, 4):
        raise InvalidMeasurement(
            "poststop left blocked_history rows for the previous namespace"
        )
    if _counter_has_namespace(heartbeat, namespace, 2):
        raise InvalidMeasurement(
            "poststop left transition_check_count rows for the previous namespace"
        )

    state = snapshot(
        "readiness",
        "--mntns",
        namespace["mntns"],
        "--pidns",
        namespace["pidns"],
        "--host-pid",
        namespace["host_pid"],
    )
    leftovers = []
    if int(state.get("graph_rows", 0)) != 0:
        leftovers.append(f"syscall_graph_map={state['graph_rows']}")
    if state.get("pid_mount_value") is not None:
        leftovers.append("pid_mount_ns_map")
    if state.get("execution") is not None:
        leftovers.append("execution_time_map")
    if state.get("root_process_state") is not None:
        leftovers.append("root process_state")
    if state.get("namespace_tids"):
        leftovers.append(f"tid_to_namespace={len(state['namespace_tids'])}")
    if state.get("container_info") is not None:
        leftovers.append("container_info_map")
    if leftovers:
        raise InvalidMeasurement(
            "poststop cleanup left state for the previous namespace: "
            + ", ".join(leftovers)
        )

    for name in (
        "syscall_graph_map",
        "process_state_map",
        "tid_to_namespace",
        "container_info_map",
    ):
        metadata = (state.get("maps") or {}).get(name) or {}
        if int(metadata.get("entry_count", -1)) < 0:
            raise InvalidMeasurement(f"{name} entry count is unavailable after poststop")
        if int(metadata["entry_count"]) >= int(metadata.get("max_entries", 0)):
            raise InvalidMeasurement(
                f"{name} is full after poststop "
                f"({metadata['entry_count']}/{metadata.get('max_entries')})"
            )


def wait_namespace_cleanup(namespace, timeout):
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        blocked = counter_snapshot("blocked")
        heartbeat = counter_snapshot("heartbeat")
        try:
            assert_namespace_cleaned(namespace, blocked, heartbeat)
            # observed_transition_map is not cleared by poststop (unlike
            # blocked_history/transition_check_count): its pinned key space
            # is mntns/pidns-scoped, and the container runtime reuses those
            # namespace IDs across pod generations. A fresh baseline is
            # snapshotted here so phase0_observed_delta() below-diffs
            # against whatever residual count already exists for this exact
            # (reused) namespace, the same way phase0_violations() already
            # does for blocked_history.
            observed_all = counter_snapshot("observed-all")
            return blocked, heartbeat, observed_all
        except InvalidMeasurement as error:
            last_error = error
        if time.monotonic() >= deadline:
            raise InvalidMeasurement(
                f"poststop cleanup did not complete within {timeout}s: {last_error}"
            ) from last_error
        time.sleep(0.1)


def heartbeat_delta(before, after, namespace):
    assert_same_counter_map(before, after, "transition_check_count")
    key = f"{namespace['mntns']}:{namespace['pidns']}:0"
    previous = int(before["entries"].get(key, 0))
    if key not in after["entries"]:
        raise InvalidMeasurement(
            "phase-0 transition heartbeat is absent for the exact namespace"
        )
    current = int(after["entries"][key])
    if current <= previous:
        raise InvalidMeasurement(
            "phase-0 transition heartbeat did not increase "
            f"for the exact namespace ({previous} -> {current})"
        )
    return previous, current, current - previous


def phase0_violations(before, after, namespace):
    assert_same_counter_map(before, after, "blocked_history")
    for key in before["entries"]:
        mntns, pidns, _source, _target, phase = map(int, key.split(":"))
        if (
            mntns == namespace["mntns"]
            and pidns == namespace["pidns"]
            and phase == 0
            and key not in after["entries"]
        ):
            raise InvalidMeasurement(
                f"blocked_history entry disappeared during the iteration: {key}"
            )

    rows = []
    for key, current_value in after["entries"].items():
        mntns, pidns, source, target, phase = map(int, key.split(":"))
        if (
            mntns != namespace["mntns"]
            or pidns != namespace["pidns"]
            or phase != 0
        ):
            continue
        previous_value = int(before["entries"].get(key, 0))
        current_value = int(current_value)
        if current_value < previous_value:
            raise InvalidMeasurement(
                f"blocked_history counter decreased for {key} "
                f"({previous_value} -> {current_value})"
            )
        if current_value > previous_value:
            rows.append(
                {
                    "mntns": mntns,
                    "pidns": pidns,
                    "from": source,
                    "to": target,
                    "phase": 0,
                    "count": current_value - previous_value,
                }
            )
    return rows


def phase0_observed_delta(before, after, namespace):
    assert_same_counter_map(before, after, "observed_transition_map")
    for key in before["entries"]:
        mntns, pidns, _source, _target, phase = map(int, key.split(":"))
        if (
            mntns == namespace["mntns"]
            and pidns == namespace["pidns"]
            and phase == 0
            and key not in after["entries"]
        ):
            raise InvalidMeasurement(
                f"observed_transition_map entry disappeared during the iteration: {key}"
            )

    rows = []
    for key, current_value in after["entries"].items():
        mntns, pidns, source, target, phase = map(int, key.split(":"))
        if (
            mntns != namespace["mntns"]
            or pidns != namespace["pidns"]
            or phase != 0
        ):
            continue
        previous_value = int(before["entries"].get(key, 0))
        current_value = int(current_value)
        if current_value < previous_value:
            raise InvalidMeasurement(
                f"observed_transition_map counter decreased for {key} "
                f"({previous_value} -> {current_value})"
            )
        if current_value > previous_value:
            rows.append(
                {
                    "from": source,
                    "to": target,
                    "count": current_value - previous_value,
                }
            )
    return rows


def observe_deployment(
    namespace,
    app,
    workload,
    previous_observation,
    ready_timeout,
    instrumentation_timeout,
    require_ready=False,
    on_pod_created=None,
):
    if previous_observation is None:
        before_blocked = counter_snapshot("blocked")
        before_heartbeat = counter_snapshot("heartbeat")
        before_observed_all = counter_snapshot("observed-all")
        previous_identity = None
    else:
        before_blocked, before_heartbeat, before_observed_all = wait_namespace_cleanup(
            previous_observation["namespace"], instrumentation_timeout
        )
        previous_identity = previous_observation["identity"]

    created_identity = create_pod(namespace, workload)
    if on_pod_created is not None:
        on_pod_created(created_identity)
    ready, ready_error = wait_ready(namespace, app, ready_timeout)
    pod = get_pod(namespace, app, required=True)
    identity = pod_identity(pod, app)
    if previous_identity is not None:
        assert_identity_replaced(previous_identity, identity)

    exact_namespace = resolve_namespace(identity["container_id"])
    readiness = wait_detector_readiness(exact_namespace, instrumentation_timeout)
    after_heartbeat = counter_snapshot("heartbeat")
    after_blocked = counter_snapshot("blocked")
    after_observed_all = counter_snapshot("observed-all")

    stable_pod = get_pod(namespace, app, required=True)
    stable_identity = pod_identity(stable_pod, app)
    assert_identity_equal(stable_identity, identity, "during map collection")

    heartbeat_before, heartbeat_after, heartbeat_increase = heartbeat_delta(
        before_heartbeat, after_heartbeat, exact_namespace
    )
    violations = phase0_violations(
        before_blocked, after_blocked, exact_namespace
    )
    # observed_transition_map is not cleared by poststop, so its pinned
    # entries persist across pod generations that reuse the same mntns/pidns.
    # Diff before/after (like blocked_history) instead of trusting the raw
    # snapshot's absolute per-edge counts.
    observed_transitions = phase0_observed_delta(
        before_observed_all, after_observed_all, exact_namespace
    )
    observed_event_count = sum(item["count"] for item in observed_transitions)
    if observed_event_count != heartbeat_increase:
        raise InvalidMeasurement(
            "observed transition event count differs from the phase-0 heartbeat "
            f"({observed_event_count} != {heartbeat_increase})"
        )
    if require_ready and not ready:
        raise InvalidMeasurement(
            f"unmeasured warm-up Pod did not become Ready: {ready_error}"
        )
    return {
        "ready": ready,
        "ready_error": ready_error,
        "identity": identity,
        "previous_identity": previous_identity,
        "namespace": exact_namespace,
        "readiness": readiness,
        "heartbeat": {
            "before": heartbeat_before,
            "after": heartbeat_after,
            "delta": heartbeat_increase,
            "map_id": after_heartbeat["id"],
        },
        "blocked_map_id": after_blocked["id"],
        "violations": violations,
        "observed_transitions": observed_transitions,
        "observed_event_count": observed_event_count,
    }


def valid_csv_row(iteration, observation):
    identity = observation["identity"]
    previous = observation["previous_identity"]
    namespace = observation["namespace"]
    readiness = observation["readiness"]
    execution = readiness["execution"]
    process_state = readiness["root_process_state"]
    violations = observation["violations"]
    heartbeat = observation["heartbeat"]
    return {
        "iteration": iteration,
        "valid": 1,
        "invalid_reason": "",
        "ready": int(observation["ready"]),
        "init_violation": int(bool(violations)),
        "init_unique_transitions": len(violations),
        "init_events": sum(item["count"] for item in violations),
        "pod_uid": identity["pod_uid"],
        "previous_pod_uid": previous["pod_uid"],
        "container_id": identity["container_id"],
        "previous_container_id": previous["container_id"],
        "identity_replaced": 1,
        "node_name": identity["node_name"],
        "restart_count": identity["restart_count"],
        "host_pid": namespace["host_pid"],
        "mntns": namespace["mntns"],
        "pidns": namespace["pidns"],
        "phase0_graph_rows": readiness["phase0_graph_rows"],
        "phase0_start_row": int(readiness["phase0_start_row"]),
        "pid_mount_value": readiness["pid_mount_value"],
        "execution_time": execution["execution_time"],
        "process_image_id": process_state["image_id"],
        "heartbeat_before": heartbeat["before"],
        "heartbeat_after": heartbeat["after"],
        "heartbeat_delta": heartbeat["delta"],
        "blocked_map_id": observation["blocked_map_id"],
        "heartbeat_map_id": heartbeat["map_id"],
        "ready_error": observation["ready_error"],
    }


def invalid_csv_row(iteration, error):
    row = {field: "" for field in CSV_FIELDS}
    row.update(
        {
            "iteration": iteration,
            "valid": 0,
            "invalid_reason": " ".join(str(error).splitlines()),
        }
    )
    return row


def append_checkpoint_record(
    writer,
    csv_file,
    detail_file,
    row,
    record,
):
    # JSONL is the canonical record: write and fsync it before the derived CSV.
    # A crash between the two writes leaves at most one reconstructable CSV row.
    detail_file.write(json.dumps(record) + "\n")
    detail_file.flush()
    os.fsync(detail_file.fileno())
    writer.writerow(row)
    csv_file.flush()
    os.fsync(csv_file.fileno())


def detail_record(iteration, observation):
    return {
        "iteration": iteration,
        "valid": True,
        "ready": observation["ready"],
        "ready_error": observation["ready_error"],
        "identity": observation["identity"],
        "previous_identity": observation["previous_identity"],
        "namespace": observation["namespace"],
        "instrumentation": observation["readiness"],
        "heartbeat": observation["heartbeat"],
        "blocked_map_id": observation["blocked_map_id"],
        "phase0_violations": observation["violations"],
        "phase0_transitions": observation["observed_transitions"],
        "phase0_observed_event_count": observation["observed_event_count"],
    }


def train_policy(app, config, config_name, namespace, delete_timeout, training_timeout):
    delete_pod(namespace, app, delete_timeout)
    command(
        "kubectl",
        "delete",
        "sygmaconfig",
        config_name,
        "-n",
        namespace,
        "--ignore-not-found=true",
        "--wait=true",
        f"--timeout={delete_timeout}s",
    )
    command("kubectl", "apply", "-f", str(config), "-n", namespace)
    command(
        "kubectl",
        "wait",
        "--for=jsonpath={.status.collectionComplete}=true",
        f"sygmaconfig/{config_name}",
        "-n",
        namespace,
        f"--timeout={training_timeout}s",
    )


def establish_validated_baseline(
    app,
    workload,
    namespace,
    ready_timeout,
    instrumentation_timeout,
    delete_timeout,
    output,
):
    delete_pod(namespace, app, delete_timeout)
    created_identity = None

    def remember_created(identity):
        nonlocal created_identity
        created_identity = identity

    try:
        observation = observe_deployment(
            namespace,
            app,
            workload,
            previous_observation=None,
            ready_timeout=ready_timeout,
            instrumentation_timeout=instrumentation_timeout,
            require_ready=True,
            on_pod_created=remember_created,
        )
    except Exception as error:
        preflight = {
            "application": app,
            "valid": False,
            "reason": " ".join(str(error).splitlines()),
        }
        (output / f"{app}-preflight.json").write_text(
            json.dumps(preflight, indent=2) + "\n"
        )
        try:
            if created_identity is not None:
                delete_pod(
                    namespace,
                    app,
                    delete_timeout,
                    expected_identity=created_identity,
                )
            elif get_pod(namespace, app) is not None:
                raise InvalidMeasurement(
                    f"pod/{app} exists after a failed create, but its created "
                    "UID was not confirmed; refusing name-only cleanup"
                )
        except Exception as cleanup_error:
            raise InvalidMeasurement(
                f"{app} preflight failed: {error}; cleanup also failed: {cleanup_error}"
            ) from error
        raise

    preflight = {
        "application": app,
        "valid": True,
        "identity": observation["identity"],
        "namespace": observation["namespace"],
        "instrumentation": observation["readiness"],
        "heartbeat": observation["heartbeat"],
    }
    (output / f"{app}-preflight.json").write_text(
        json.dumps(preflight, indent=2) + "\n"
    )
    print(
        f"{app} preflight: valid heartbeat={observation['heartbeat']['delta']} "
        f"phase0_graph_rows={observation['readiness']['phase0_graph_rows']}",
        flush=True,
    )
    # Leave this Pod running. Iteration 1 must delete this exact identity and
    # prove that both its Pod UID and container ID changed.
    return observation


def read_json_object(path, description):
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise InvalidMeasurement(
            f"cannot read {description} {path}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise InvalidMeasurement(f"{description} {path} is not a JSON object")
    return value


def read_jsonl(path):
    records = []
    try:
        with path.open() as source:
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    raise InvalidMeasurement(
                        f"{path}: blank JSONL record at line {line_number}"
                    )
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise InvalidMeasurement(
                        f"{path}: invalid JSON at line {line_number}: {error}"
                    ) from error
                if not isinstance(value, dict):
                    raise InvalidMeasurement(
                        f"{path}: line {line_number} is not a JSON object"
                    )
                records.append(value)
    except OSError as error:
        raise InvalidMeasurement(f"cannot read {path}: {error}") from error
    return records


def identity_pair(value, context):
    if not isinstance(value, dict):
        raise InvalidMeasurement(f"{context} has no identity object")
    pod_value = value.get("pod_uid")
    container_value = value.get("container_id")
    if not pod_value or not container_value:
        raise InvalidMeasurement(f"{context} has an incomplete identity")
    return pod_value, container_value


def detail_to_observation(record):
    required = {
        "ready",
        "ready_error",
        "identity",
        "previous_identity",
        "namespace",
        "instrumentation",
        "heartbeat",
        "blocked_map_id",
        "phase0_violations",
    }
    missing = required.difference(record)
    if missing:
        raise InvalidMeasurement(
            f"resume detail lacks fields: {sorted(missing)}"
        )
    return {
        "ready": record["ready"],
        "ready_error": record["ready_error"],
        "identity": record["identity"],
        "previous_identity": record["previous_identity"],
        "namespace": record["namespace"],
        "readiness": record["instrumentation"],
        "heartbeat": record["heartbeat"],
        "blocked_map_id": record["blocked_map_id"],
        "violations": record["phase0_violations"],
    }


def validate_observation_structure(
    observation,
    app,
    namespace_name,
    context,
):
    identity = observation["identity"]
    namespace = observation["namespace"]
    readiness = observation["readiness"]
    heartbeat = observation["heartbeat"]
    if namespace.get("container_id") != identity.get("container_id"):
        raise InvalidMeasurement(
            f"{context}: namespace resolver container ID differs from Pod identity"
        )
    for field in ("host_pid", "mntns", "pidns"):
        if int(namespace.get(field, 0)) <= 0:
            raise InvalidMeasurement(f"{context}: invalid namespace {field}")
    if int(readiness.get("host_pid", namespace["host_pid"])) != int(
        namespace["host_pid"]
    ):
        raise InvalidMeasurement(f"{context}: readiness host PID differs")
    readiness_namespace = readiness.get("namespace") or {}
    for field in ("mntns", "pidns"):
        if readiness_namespace and int(readiness_namespace.get(field, 0)) != int(
            namespace[field]
        ):
            raise InvalidMeasurement(
                f"{context}: readiness {field} differs from resolved namespace"
            )
    container_info = readiness.get("container_info")
    if container_info != f"{namespace_name}/{app}/{app}":
        raise InvalidMeasurement(
            f"{context}: unexpected container_info {container_info!r}"
        )
    before = int(heartbeat["before"])
    after = int(heartbeat["after"])
    delta = int(heartbeat["delta"])
    if after - before != delta or delta <= 0:
        raise InvalidMeasurement(f"{context}: inconsistent heartbeat delta")


def validate_checkpoint(app, csv_path, detail_path, preflight_path, iterations):
    try:
        with csv_path.open(newline="") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames != CSV_FIELDS:
                raise InvalidMeasurement(
                    f"{csv_path}: CSV schema/order differs from this runner"
                )
            rows = list(reader)
    except OSError as error:
        raise InvalidMeasurement(f"cannot read {csv_path}: {error}") from error

    records = read_jsonl(detail_path)
    if len(rows) != len(records):
        raise InvalidMeasurement(
            f"checkpoint row mismatch: CSV={len(rows)}, JSONL={len(records)}"
        )

    preflight = read_json_object(preflight_path, "preflight")
    if preflight.get("application") != app or preflight.get("valid") is not True:
        raise InvalidMeasurement(f"{preflight_path}: preflight is not valid for {app}")
    previous_pair = identity_pair(
        preflight.get("identity"), f"{preflight_path} preflight"
    )
    preflight_instrumentation = preflight.get("instrumentation") or {}
    preflight_container_info = preflight_instrumentation.get("container_info")
    if not isinstance(preflight_container_info, str):
        raise InvalidMeasurement(
            f"{preflight_path}: preflight lacks container_info"
        )
    container_parts = preflight_container_info.split("/")
    if len(container_parts) != 3 or container_parts[1:] != [app, app]:
        raise InvalidMeasurement(
            f"{preflight_path}: invalid container_info {preflight_container_info!r}"
        )
    checkpoint_namespace = container_parts[0]
    baseline_maps = preflight_instrumentation.get("maps") or {}
    baseline_map_ids = {
        name: int(metadata["id"])
        for name, metadata in baseline_maps.items()
        if isinstance(metadata, dict) and metadata.get("id") is not None
    }
    missing_map_ids = REQUIRED_STATE_MAPS.difference(baseline_map_ids)
    if missing_map_ids:
        raise InvalidMeasurement(
            f"{preflight_path}: preflight lacks map IDs "
            f"{sorted(missing_map_ids)}"
        )
    baseline_heartbeat_id = int(
        (preflight.get("heartbeat") or {}).get("map_id", 0)
    )
    if baseline_heartbeat_id <= 0:
        raise InvalidMeasurement(
            f"{preflight_path}: preflight lacks a heartbeat map ID"
        )
    blocked_map_id = None

    valid_count = 0
    terminal_invalid = None
    seen_pods = {previous_pair[0]}
    seen_containers = {previous_pair[1]}
    for position, (row, record) in enumerate(zip(rows, records), 1):
        try:
            csv_iteration = int(row.get("iteration", ""))
            csv_valid = int(row.get("valid", ""))
            detail_iteration = int(record.get("iteration"))
        except (TypeError, ValueError) as error:
            raise InvalidMeasurement(
                f"checkpoint record {position} has invalid iteration/valid fields"
            ) from error
        if csv_iteration != position or detail_iteration != position:
            raise InvalidMeasurement(
                f"checkpoint is not contiguous at record {position} "
                f"(CSV={csv_iteration}, JSONL={detail_iteration})"
            )
        if csv_valid not in (0, 1) or record.get("valid") is not bool(csv_valid):
            raise InvalidMeasurement(
                f"checkpoint validity differs at iteration {position}"
            )

        if csv_valid == 0:
            if position != len(rows) or terminal_invalid is not None:
                raise InvalidMeasurement(
                    "only one terminal invalid checkpoint row can be resumed"
                )
            if any(row.get(field, "") for field in CSV_FIELDS[3:]):
                raise InvalidMeasurement(
                    f"invalid iteration {position} unexpectedly contains measurements"
                )
            csv_reason = row.get("invalid_reason", "")
            detail_reason = str(record.get("invalid_reason", ""))
            if not csv_reason or csv_reason != detail_reason:
                raise InvalidMeasurement(
                    f"invalid reason differs at iteration {position}"
                )
            terminal_invalid = {
                "csv": row,
                "detail": record,
            }
            continue

        if terminal_invalid is not None:
            raise InvalidMeasurement("valid data appears after an invalid checkpoint")
        valid_count += 1
        observation = detail_to_observation(record)
        current_pair = identity_pair(
            observation["identity"], f"iteration {position}"
        )
        detail_previous_pair = identity_pair(
            observation["previous_identity"],
            f"iteration {position} previous identity",
        )
        if detail_previous_pair != previous_pair:
            raise InvalidMeasurement(
                f"identity chain breaks before iteration {position}"
            )
        if row["pod_uid"] != current_pair[0] or row["container_id"] != current_pair[1]:
            raise InvalidMeasurement(
                f"CSV/JSONL current identity differs at iteration {position}"
            )
        if (
            row["previous_pod_uid"] != detail_previous_pair[0]
            or row["previous_container_id"] != detail_previous_pair[1]
        ):
            raise InvalidMeasurement(
                f"CSV/JSONL previous identity differs at iteration {position}"
            )
        if current_pair[0] in seen_pods or current_pair[1] in seen_containers:
            raise InvalidMeasurement(
                f"Pod/container identity was reused at iteration {position}"
            )

        namespace = observation["namespace"]
        instrumentation = observation["readiness"]
        heartbeat = observation["heartbeat"]
        violations = observation["violations"]
        validate_observation_structure(
            observation,
            app,
            checkpoint_namespace,
            f"iteration {position}",
        )
        expected_row = valid_csv_row(position, observation)
        for field in CSV_FIELDS:
            actual = row.get(field, "")
            expected = str(expected_row.get(field, ""))
            if actual != expected:
                raise InvalidMeasurement(
                    f"CSV/JSONL {field} differs at iteration {position} "
                    f"({actual!r} != {expected!r})"
                )

        current_maps = instrumentation.get("maps") or {}
        for name, expected_id in baseline_map_ids.items():
            try:
                current_id = int((current_maps.get(name) or {})["id"])
            except (KeyError, TypeError, ValueError) as error:
                raise InvalidMeasurement(
                    f"iteration {position} lacks map ID for {name}"
                ) from error
            if current_id != expected_id:
                raise InvalidMeasurement(
                    f"{name} changed during the checkpoint "
                    f"({expected_id} -> {current_id})"
                )
        if baseline_heartbeat_id and int(heartbeat["map_id"]) != baseline_heartbeat_id:
            raise InvalidMeasurement(
                "transition_check_count map differs from preflight"
            )
        if blocked_map_id is None:
            blocked_map_id = int(observation["blocked_map_id"])
        elif int(observation["blocked_map_id"]) != blocked_map_id:
            raise InvalidMeasurement("blocked_history map changed within checkpoint")

        seen_pods.add(current_pair[0])
        seen_containers.add(current_pair[1])
        previous_pair = current_pair

    if valid_count > iterations:
        raise InvalidMeasurement(
            f"checkpoint has {valid_count} valid iterations, more than target "
            f"{iterations}"
        )
    if terminal_invalid is not None and len(rows) != valid_count + 1:
        raise InvalidMeasurement("terminal invalid row does not follow the valid prefix")
    if valid_count == iterations and terminal_invalid is not None:
        raise InvalidMeasurement(
            "checkpoint already reached the target but has an extra invalid row"
        )

    return {
        "rows": rows,
        "records": records,
        "valid_count": valid_count,
        "terminal_invalid": terminal_invalid,
        "preflight": preflight,
        "namespace": checkpoint_namespace,
        "map_ids": baseline_map_ids,
    }


def validate_resume_policy(config_name, namespace, expected_image_id):
    result = command(
        "kubectl",
        "get",
        "sygmaconfig",
        config_name,
        "-n",
        namespace,
        "-o",
        "json",
        f"--request-timeout={KUBECTL_REQUEST_TIMEOUT}s",
        capture=True,
        timeout=KUBECTL_REQUEST_TIMEOUT + 2,
    )
    try:
        config = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise InvalidMeasurement(
            f"sygmaconfig/{config_name} returned invalid JSON: {error}"
        ) from error
    status = config.get("status") or {}
    if status.get("collectionComplete") is not True:
        raise InvalidMeasurement(
            f"sygmaconfig/{config_name} is not collectionComplete"
        )
    try:
        image_id = int(status.get("imageID"))
    except (TypeError, ValueError) as error:
        raise InvalidMeasurement(
            f"sygmaconfig/{config_name} has no valid status.imageID"
        ) from error
    if image_id != int(expected_image_id):
        raise InvalidMeasurement(
            f"sygmaconfig/{config_name} imageID changed "
            f"({expected_image_id} -> {image_id})"
        )
    metadata = config.get("metadata") or {}
    return {
        "uid": metadata.get("uid"),
        "generation": metadata.get("generation"),
        "creation_timestamp": metadata.get("creationTimestamp"),
        "resource_version": metadata.get("resourceVersion"),
        "image_id": image_id,
        "phase": status.get("phase"),
    }


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_run_metadata(
    app,
    config_name,
    config_path,
    workload_path,
    args,
    baseline,
):
    image_id = baseline["readiness"]["root_process_state"]["image_id"]
    policy = validate_resume_policy(
        config_name,
        args.namespace,
        image_id,
    )
    maps = baseline["readiness"].get("maps") or {}
    metadata = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "application": app,
        "namespace": args.namespace,
        "expected_iterations": args.iterations,
        "config_sha256": file_sha256(config_path),
        "workload_sha256": file_sha256(workload_path),
        "sygmaconfig": policy,
        "map_ids": {
            name: int(value["id"])
            for name, value in maps.items()
            if isinstance(value, dict) and value.get("id") is not None
        },
        "blocked_map_id": int(baseline["blocked_map_id"]),
        "heartbeat_map_id": int(baseline["heartbeat"]["map_id"]),
        "image_id": int(image_id),
        "baseline_identity": baseline["identity"],
    }
    path = args.output / f"{app}-run-metadata.json"
    path.write_text(json.dumps(metadata, indent=2) + "\n")
    return metadata


def validate_run_metadata(
    app,
    config_path,
    workload_path,
    args,
    policy,
    checkpoint,
    expected_blocked_id,
    expected_heartbeat_id,
):
    path = args.output / f"{app}-run-metadata.json"
    if not path.exists():
        return None
    metadata = read_json_object(path, "run metadata")
    expected_values = {
        "schema_version": 1,
        "application": app,
        "namespace": args.namespace,
        "expected_iterations": args.iterations,
        "config_sha256": file_sha256(config_path),
        "workload_sha256": file_sha256(workload_path),
        "blocked_map_id": expected_blocked_id,
        "heartbeat_map_id": expected_heartbeat_id,
    }
    for field, expected in expected_values.items():
        if metadata.get(field) != expected:
            raise InvalidMeasurement(
                f"{path}: {field} changed "
                f"({metadata.get(field)!r} != {expected!r})"
            )
    stored_policy = metadata.get("sygmaconfig") or {}
    for field in ("uid", "generation", "creation_timestamp", "image_id"):
        if stored_policy.get(field) != policy.get(field):
            raise InvalidMeasurement(
                f"sygmaconfig {field} changed "
                f"({stored_policy.get(field)!r} -> {policy.get(field)!r})"
            )
    stored_map_ids = metadata.get("map_ids") or {}
    if {
        name: int(value) for name, value in stored_map_ids.items()
    } != checkpoint["map_ids"]:
        raise InvalidMeasurement(f"{path}: stored BPF map IDs differ")
    return metadata


def validate_live_map_ids(previous_observation, expected_map_ids):
    namespace = previous_observation["namespace"]
    state = snapshot(
        "readiness",
        "--mntns",
        namespace["mntns"],
        "--pidns",
        namespace["pidns"],
        "--host-pid",
        namespace["host_pid"],
    )
    current_maps = state.get("maps") or {}
    for name, expected_id in expected_map_ids.items():
        metadata = current_maps.get(name) or {}
        try:
            current_id = int(metadata["id"])
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidMeasurement(
                f"cannot read live map ID for {name}"
            ) from error
        if current_id != int(expected_id):
            raise InvalidMeasurement(
                f"cannot resume across a {name} replacement "
                f"({expected_id} -> {current_id})"
            )
    return state


def atomic_write_checkpoint(csv_path, detail_path, rows, records):
    csv_mode = (
        stat.S_IMODE(csv_path.stat().st_mode) if csv_path.exists() else 0o644
    )
    detail_mode = (
        stat.S_IMODE(detail_path.stat().st_mode)
        if detail_path.exists()
        else 0o644
    )
    csv_temp = None
    detail_temp = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            newline="",
            dir=csv_path.parent,
            prefix=f".{csv_path.name}.",
            delete=False,
        ) as target:
            csv_temp = Path(target.name)
            os.fchmod(target.fileno(), csv_mode)
            writer = csv.DictWriter(target, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
            target.flush()
            os.fsync(target.fileno())
        with tempfile.NamedTemporaryFile(
            "w",
            dir=detail_path.parent,
            prefix=f".{detail_path.name}.",
            delete=False,
        ) as target:
            detail_temp = Path(target.name)
            os.fchmod(target.fileno(), detail_mode)
            for record in records:
                target.write(json.dumps(record) + "\n")
            target.flush()
            os.fsync(target.fileno())
        detail_temp.replace(detail_path)
        csv_temp.replace(csv_path)
        directory_fd = os.open(csv_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        for temporary in (csv_temp, detail_temp):
            if temporary is not None and temporary.exists():
                temporary.unlink()


def archive_terminal_invalid(
    app,
    output,
    csv_path,
    detail_path,
    checkpoint,
):
    if checkpoint["terminal_invalid"] is None:
        return None

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = output / "operational-errors" / f"{app}-{stamp}"
    backup.mkdir(parents=True, exist_ok=False)
    for path in (
        csv_path,
        detail_path,
        output / f"{app}-summary.json",
        output / f"{app}-preflight.json",
    ):
        if path.exists():
            shutil.copy2(path, backup / path.name)

    event = {
        "timestamp": stamp,
        "application": app,
        "classification": "pre-deployment operational failure",
        "failure_stage": checkpoint["terminal_invalid"]["detail"].get(
            "failure_stage", "legacy-delete-previous-pod"
        ),
        "retry_iteration": checkpoint["valid_count"] + 1,
        "archived_csv_row": checkpoint["terminal_invalid"]["csv"],
        "archived_detail_record": checkpoint["terminal_invalid"]["detail"],
        "backup_directory": str(backup),
    }
    (backup / "event.json").write_text(json.dumps(event, indent=2) + "\n")
    with (output / f"{app}-operational-errors.jsonl").open("a") as journal:
        journal.write(json.dumps(event) + "\n")

    transaction_path = output / f".{app}-checkpoint-transaction.json"
    transaction = {
        "application": app,
        "operation": "remove-terminal-operational-error",
        "backup_directory": str(backup),
        "csv_path": str(csv_path),
        "detail_path": str(detail_path),
    }
    transaction_path.write_text(json.dumps(transaction, indent=2) + "\n")
    try:
        valid_count = checkpoint["valid_count"]
        atomic_write_checkpoint(
            csv_path,
            detail_path,
            checkpoint["rows"][:valid_count],
            checkpoint["records"][:valid_count],
        )
    except BaseException:
        # Keep the transaction marker so the next --resume restores the exact
        # archived pair before attempting validation again.
        raise
    else:
        transaction_path.unlink()
    return event


def recover_checkpoint_transaction(app, output):
    transaction_path = output / f".{app}-checkpoint-transaction.json"
    if not transaction_path.exists():
        return
    transaction = read_json_object(transaction_path, "checkpoint transaction")
    if (
        transaction.get("application") != app
        or transaction.get("operation")
        not in {
            "remove-terminal-operational-error",
            "repair-derived-csv-tail",
        }
    ):
        raise InvalidMeasurement(
            f"{transaction_path}: unknown checkpoint transaction"
        )
    backup = Path(str(transaction.get("backup_directory", "")))
    csv_path = Path(str(transaction.get("csv_path", "")))
    detail_path = Path(str(transaction.get("detail_path", "")))
    expected_csv = output / f"{app}-iterations.csv"
    expected_detail = output / f"{app}-violations.jsonl"
    if csv_path != expected_csv or detail_path != expected_detail:
        raise InvalidMeasurement(
            f"{transaction_path}: transaction targets unexpected paths"
        )
    backup_csv = backup / csv_path.name
    backup_detail = backup / detail_path.name
    if not backup_csv.exists() or not backup_detail.exists():
        raise InvalidMeasurement(
            f"{transaction_path}: checkpoint backup is incomplete"
        )
    shutil.copy2(backup_csv, csv_path)
    shutil.copy2(backup_detail, detail_path)
    transaction_path.unlink()
    print(
        f"{app}: restored interrupted checkpoint transaction from {backup}",
        flush=True,
    )


def repair_derived_csv_tail(app, output):
    csv_path = output / f"{app}-iterations.csv"
    detail_path = output / f"{app}-violations.jsonl"
    if not csv_path.exists() or not detail_path.exists():
        return
    try:
        with csv_path.open(newline="") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames != CSV_FIELDS:
                return
            rows = list(reader)
    except OSError:
        return
    records = read_jsonl(detail_path)
    if len(records) == len(rows):
        return
    if len(records) != len(rows) + 1:
        return

    record = records[-1]
    expected_iteration = len(records)
    try:
        record_iteration = int(record.get("iteration"))
    except (TypeError, ValueError):
        return
    if record_iteration != expected_iteration:
        return
    if record.get("valid") is True:
        row = valid_csv_row(
            expected_iteration,
            detail_to_observation(record),
        )
    elif record.get("valid") is False and record.get("invalid_reason"):
        row = {field: "" for field in CSV_FIELDS}
        row.update(
            {
                "iteration": expected_iteration,
                "valid": 0,
                "invalid_reason": str(record["invalid_reason"]),
            }
        )
    else:
        return

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = output / "checkpoint-recovery" / f"{app}-{stamp}"
    backup.mkdir(parents=True, exist_ok=False)
    shutil.copy2(csv_path, backup / csv_path.name)
    shutil.copy2(detail_path, backup / detail_path.name)
    transaction_path = output / f".{app}-checkpoint-transaction.json"
    transaction = {
        "application": app,
        "operation": "repair-derived-csv-tail",
        "backup_directory": str(backup),
        "csv_path": str(csv_path),
        "detail_path": str(detail_path),
    }
    transaction_path.write_text(json.dumps(transaction, indent=2) + "\n")
    try:
        atomic_write_checkpoint(
            csv_path,
            detail_path,
            rows + [row],
            records,
        )
    except BaseException:
        raise
    else:
        transaction_path.unlink()
    print(
        f"{app}: recovered derived CSV iteration {expected_iteration} "
        "from the fsynced JSONL journal",
        flush=True,
    )


def prepare_resume(app, config_name, config_path, workload_path, args):
    csv_path = args.output / f"{app}-iterations.csv"
    detail_path = args.output / f"{app}-violations.jsonl"
    preflight_path = args.output / f"{app}-preflight.json"
    present = [path.exists() for path in (csv_path, detail_path, preflight_path)]
    if not any(present):
        return None
    if not args.resume:
        raise InvalidMeasurement(
            f"results already exist for {app}; use a new --output directory or "
            "--resume"
        )
    recover_checkpoint_transaction(app, args.output)
    repair_derived_csv_tail(app, args.output)
    present = [path.exists() for path in (csv_path, detail_path, preflight_path)]
    if not all(present):
        raise InvalidMeasurement(
            f"incomplete {app} checkpoint: CSV, JSONL, and preflight must all exist"
        )

    checkpoint = validate_checkpoint(
        app,
        csv_path,
        detail_path,
        preflight_path,
        args.iterations,
    )
    if checkpoint["namespace"] != args.namespace:
        raise InvalidMeasurement(
            f"checkpoint namespace {checkpoint['namespace']!r} differs from "
            f"--namespace {args.namespace!r}"
        )
    summary_path = args.output / f"{app}-summary.json"
    if summary_path.exists():
        summary = read_json_object(summary_path, "summary")
        if summary.get("application") != app:
            raise InvalidMeasurement(f"{summary_path}: application differs")
        try:
            expected_iterations = int(summary.get("expected_iterations"))
        except (TypeError, ValueError) as error:
            raise InvalidMeasurement(
                f"{summary_path}: expected_iterations is unavailable"
            ) from error
        if expected_iterations != args.iterations:
            raise InvalidMeasurement(
                f"checkpoint target was {expected_iterations}, not "
                f"{args.iterations}"
            )
    valid_count = checkpoint["valid_count"]

    terminal_invalid = checkpoint["terminal_invalid"]
    if terminal_invalid is not None:
        failure_stage = terminal_invalid["detail"].get("failure_stage")
        legacy_reason = str(
            terminal_invalid["detail"].get("invalid_reason", "")
        )
        legacy_delete_failure = (
            failure_stage is None
            and legacy_reason.startswith("command failed")
            and f"kubectl delete pod/{app} " in legacy_reason
        )
        if failure_stage != "delete_previous_pod" and not legacy_delete_failure:
            raise InvalidMeasurement(
                "the terminal invalid row did not fail while deleting the "
                "previous Pod; it cannot be automatically retried"
            )

    if valid_count == 0:
        preflight = checkpoint["preflight"]
        preflight_observation = {
            "identity": preflight["identity"],
            "namespace": preflight.get("namespace") or {},
            "readiness": preflight.get("instrumentation") or {},
            "heartbeat": preflight.get("heartbeat") or {},
        }
        validate_live_map_ids(
            preflight_observation,
            checkpoint["map_ids"],
        )
        current_heartbeat = counter_snapshot("heartbeat")
        expected_heartbeat_id = int(
            preflight_observation["heartbeat"]["map_id"]
        )
        if current_heartbeat["id"] != expected_heartbeat_id:
            raise InvalidMeasurement(
                "cannot resume across a transition_check_count map replacement "
                f"({expected_heartbeat_id} -> {current_heartbeat['id']})"
            )
        expected_image_id = preflight_observation["readiness"][
            "root_process_state"
        ]["image_id"]
        policy = validate_resume_policy(
            config_name,
            args.namespace,
            expected_image_id,
        )
        metadata_path = args.output / f"{app}-run-metadata.json"
        if metadata_path.exists():
            stored_metadata = read_json_object(metadata_path, "run metadata")
            expected_blocked_id = int(stored_metadata["blocked_map_id"])
            current_blocked = counter_snapshot("blocked")
            if current_blocked["id"] != expected_blocked_id:
                raise InvalidMeasurement(
                    "cannot resume across a blocked_history map replacement "
                    f"({expected_blocked_id} -> {current_blocked['id']})"
                )
            validate_run_metadata(
                app,
                config_path,
                workload_path,
                args,
                policy,
                checkpoint,
                expected_blocked_id,
                expected_heartbeat_id,
            )

        existing = get_pod(args.namespace, app)
        expected_identity = preflight_observation["identity"]
        if existing is not None:
            if pod_uid(existing) != expected_identity["pod_uid"]:
                raise InvalidMeasurement(
                    f"pod/{app} has an unknown UID while resuming preflight"
                )
            delete_pod(
                args.namespace,
                app,
                args.delete_timeout,
                expected_identity=expected_identity,
            )
        wait_namespace_cleanup(
            preflight_observation["namespace"],
            args.instrumentation_timeout,
        )
        archive_terminal_invalid(
            app, args.output, csv_path, detail_path, checkpoint
        )
        return {
            "completed": False,
            "valid_count": 0,
            "previous_observation": None,
            "active_identity": None,
            "skip_first_delete": False,
        }

    previous_observation = detail_to_observation(
        checkpoint["records"][valid_count - 1]
    )
    if valid_count == args.iterations:
        expected_identity = previous_observation["identity"]
        existing = get_pod(args.namespace, app)
        if existing is not None:
            existing_uid = pod_uid(existing)
            if existing_uid != expected_identity["pod_uid"]:
                raise InvalidMeasurement(
                    f"completed checkpoint has an unknown pod/{app} UID "
                    f"({expected_identity['pod_uid']} -> {existing_uid})"
                )
            if not (existing.get("metadata") or {}).get("deletionTimestamp"):
                existing_identity = pod_identity(existing, app)
                assert_identity_equal(
                    existing_identity,
                    expected_identity,
                    "completed checkpoint cleanup",
                )
            delete_pod(
                args.namespace,
                app,
                args.delete_timeout,
                expected_identity=expected_identity,
            )
        wait_namespace_cleanup(
            previous_observation["namespace"],
            args.instrumentation_timeout,
        )
        print(
            f"{app}: completed checkpoint cleanup verified "
            f"({valid_count}/{args.iterations})",
            flush=True,
        )
        return {
            "completed": True,
            "valid_count": valid_count,
        }

    expected_blocked_id = int(previous_observation["blocked_map_id"])
    expected_heartbeat_id = int(previous_observation["heartbeat"]["map_id"])
    current_blocked = counter_snapshot("blocked")
    current_heartbeat = counter_snapshot("heartbeat")
    if current_blocked["id"] != expected_blocked_id:
        raise InvalidMeasurement(
            "cannot resume across a blocked_history map replacement "
            f"({expected_blocked_id} -> {current_blocked['id']})"
        )
    if current_heartbeat["id"] != expected_heartbeat_id:
        raise InvalidMeasurement(
            "cannot resume across a transition_check_count map replacement "
            f"({expected_heartbeat_id} -> {current_heartbeat['id']})"
        )
    validate_live_map_ids(
        previous_observation,
        checkpoint["map_ids"],
    )

    expected_image_id = previous_observation["readiness"][
        "root_process_state"
    ]["image_id"]
    policy = validate_resume_policy(
        config_name,
        args.namespace,
        expected_image_id,
    )
    validate_run_metadata(
        app,
        config_path,
        workload_path,
        args,
        policy,
        checkpoint,
        expected_blocked_id,
        expected_heartbeat_id,
    )

    expected_identity = previous_observation["identity"]
    existing = get_pod(args.namespace, app)
    skip_first_delete = False
    active_identity = expected_identity
    if existing is None:
        wait_namespace_cleanup(
            previous_observation["namespace"],
            args.instrumentation_timeout,
        )
        skip_first_delete = True
        active_identity = None
    else:
        existing_uid = pod_uid(existing)
        if existing_uid != expected_identity["pod_uid"]:
            raise InvalidMeasurement(
                f"pod/{app} has an unknown UID while resuming "
                f"({expected_identity['pod_uid']} -> {existing_uid}); "
                "refusing to delete it"
            )
        if (existing.get("metadata") or {}).get("deletionTimestamp"):
            wait_pod_absent(
                args.namespace,
                app,
                existing_uid,
                args.delete_timeout,
            )
            wait_namespace_cleanup(
                previous_observation["namespace"],
                args.instrumentation_timeout,
            )
            skip_first_delete = True
            active_identity = None
        else:
            existing_identity = pod_identity(existing, app)
            assert_identity_equal(
                existing_identity,
                expected_identity,
                "resume checkpoint",
            )

    archived_error = archive_terminal_invalid(
        app, args.output, csv_path, detail_path, checkpoint
    )
    resume_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "application": app,
        "validated_iterations": valid_count,
        "next_iteration": valid_count + 1,
        "last_identity": expected_identity,
        "last_namespace": previous_observation["namespace"],
        "blocked_map_id": current_blocked["id"],
        "heartbeat_map_id": current_heartbeat["id"],
        "policy": policy,
        "last_pod_already_absent": skip_first_delete,
        "archived_operational_error": archived_error,
    }
    with (args.output / f"{app}-resume.jsonl").open("a") as journal:
        journal.write(json.dumps(resume_event) + "\n")
    print(
        f"{app} resume validated: {valid_count}/{args.iterations}; "
        f"next={valid_count + 1} "
        f"pod_absent={skip_first_delete}",
        flush=True,
    )
    return {
        "completed": False,
        "valid_count": valid_count,
        "previous_observation": previous_observation,
        "active_identity": active_identity,
        "skip_first_delete": skip_first_delete,
    }


def acquire_output_lock(output):
    path = output / ".run.lock"
    handle = path.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        handle.seek(0)
        owner = handle.read().strip() or "unknown owner"
        handle.close()
        raise InvalidMeasurement(
            f"another runner holds {path} ({owner})"
        ) from error
    handle.seek(0)
    handle.truncate()
    handle.write(
        json.dumps(
            {
                "pid": os.getpid(),
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        + "\n"
    )
    handle.flush()
    return handle


def run_app(app, config, workload, args):
    config_name = f"{app}-sygma-config"
    resume = prepare_resume(
        app,
        config_name,
        config,
        workload,
        args,
    )
    if resume is not None and resume["completed"]:
        print(
            f"{app}: existing checkpoint already has "
            f"{resume['valid_count']}/{args.iterations} valid iterations; skipped",
            flush=True,
        )
        return

    fresh_run = resume is None
    if fresh_run and not args.skip_training:
        train_policy(
            app,
            config,
            config_name,
            args.namespace,
            args.delete_timeout,
            args.training_timeout,
        )

    if fresh_run or resume["valid_count"] == 0:
        previous_observation = establish_validated_baseline(
            app,
            workload,
            args.namespace,
            args.ready_timeout,
            args.instrumentation_timeout,
            args.delete_timeout,
            args.output,
        )
        active_identity = previous_observation["identity"]
        start_iteration = 1
        skip_first_delete = False
        if fresh_run or resume["valid_count"] == 0:
            write_run_metadata(
                app,
                config_name,
                config,
                workload,
                args,
                previous_observation,
            )
    else:
        previous_observation = resume["previous_observation"]
        active_identity = resume["active_identity"]
        start_iteration = resume["valid_count"] + 1
        skip_first_delete = resume["skip_first_delete"]

    csv_path = args.output / f"{app}-iterations.csv"
    detail_path = args.output / f"{app}-violations.jsonl"
    file_mode = "w" if fresh_run else "a"
    run_error = None
    try:
        with csv_path.open(file_mode, newline="") as csv_file, detail_path.open(
            file_mode
        ) as detail_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
            if fresh_run:
                writer.writeheader()
                csv_file.flush()

            for iteration in range(start_iteration, args.iterations + 1):
                failure_stage = "delete_previous_pod"
                try:
                    if skip_first_delete:
                        skip_first_delete = False
                    else:
                        delete_pod(
                            args.namespace,
                            app,
                            args.delete_timeout,
                            expected_identity=previous_observation["identity"],
                        )
                        # The expected Pod is now authoritatively NotFound. A
                        # later observation failure may happen before the new
                        # identity is known.
                        active_identity = None
                    failure_stage = "observe_deployment"

                    def remember_created(identity):
                        nonlocal active_identity
                        active_identity = identity

                    observation = observe_deployment(
                        args.namespace,
                        app,
                        workload,
                        previous_observation,
                        args.ready_timeout,
                        args.instrumentation_timeout,
                        on_pod_created=remember_created,
                    )
                    active_identity = observation["identity"]
                except Exception as error:
                    invalid_record = {
                        "iteration": iteration,
                        "valid": False,
                        "failure_stage": failure_stage,
                        "pod_created": (
                            failure_stage == "observe_deployment"
                            and active_identity is not None
                        ),
                        "created_pod_uid": (
                            active_identity.get("pod_uid")
                            if failure_stage == "observe_deployment"
                            and active_identity is not None
                            else None
                        ),
                        "invalid_reason": " ".join(str(error).splitlines()),
                    }
                    append_checkpoint_record(
                        writer,
                        csv_file,
                        detail_file,
                        invalid_csv_row(iteration, error),
                        invalid_record,
                    )
                    raise InvalidMeasurement(
                        f"{app} iteration {iteration} is invalid; experiment stopped: "
                        f"{error}"
                    ) from error

                append_checkpoint_record(
                    writer,
                    csv_file,
                    detail_file,
                    valid_csv_row(iteration, observation),
                    detail_record(iteration, observation),
                )
                previous_observation = observation
                print(
                    f"{app} {iteration}/{args.iterations}: valid=1 "
                    f"ready={observation['ready']} "
                    f"init={len(observation['violations'])} "
                    f"heartbeat={observation['heartbeat']['delta']}",
                    flush=True,
                )
    except BaseException as error:
        run_error = error

    cleanup_error = None
    try:
        if active_identity is not None:
            delete_pod(
                args.namespace,
                app,
                args.delete_timeout,
                expected_identity=active_identity,
            )
        elif get_pod(args.namespace, app) is not None:
            raise InvalidMeasurement(
                f"pod/{app} exists after the runner lost its exact UID; "
                "refusing name-only cleanup"
            )
    except Exception as error:
        cleanup_error = error

    if run_error is not None and cleanup_error is not None:
        raise InvalidMeasurement(
            f"{run_error}; cleanup also failed: {cleanup_error}"
        ) from run_error
    if run_error is not None:
        raise run_error.with_traceback(run_error.__traceback__)
    if cleanup_error is not None:
        raise cleanup_error


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apps", nargs="+", choices=APPS, default=list(APPS))
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--ready-timeout", type=int, default=180)
    parser.add_argument("--instrumentation-timeout", type=int, default=30)
    parser.add_argument("--delete-timeout", type=int, default=180)
    parser.add_argument("--training-timeout", type=int, default=600)
    parser.add_argument("--skip-training", action="store_true")
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "validate and append to strict checkpoints in --output; completed "
            "apps are skipped and apps without checkpoints start normally"
        ),
    )
    parser.add_argument("--output", type=Path, default=HERE / "results")
    args = parser.parse_args()
    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    for option in (
        "ready_timeout",
        "instrumentation_timeout",
        "delete_timeout",
        "training_timeout",
    ):
        if getattr(args, option) <= 0:
            parser.error(f"--{option.replace('_', '-')} must be positive")
    return args


def main():
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    output_lock = acquire_output_lock(args.output)
    try:
        command("kubectl", "cluster-info", capture=True)

        # Fail before training or creating a workload if either observation map is
        # missing, stale-ABI, unreadable, or already full.
        counter_snapshot("blocked")
        counter_snapshot("heartbeat")
        counter_snapshot("observed-all")

        for app in args.apps:
            config, workload = APPS[app]
            csv_path = args.output / f"{app}-iterations.csv"
            try:
                run_app(app, config, workload, args)
            finally:
                if csv_path.exists():
                    command(
                        sys.executable,
                        str(HERE / "summarize.py"),
                        str(csv_path),
                        "--expected-iterations",
                        str(args.iterations),
                    )
    finally:
        output_lock.close()


if __name__ == "__main__":
    main()
