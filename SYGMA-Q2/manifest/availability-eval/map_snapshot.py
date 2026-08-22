#!/usr/bin/env python3
"""Read the exact SYGMA BPF state needed by the availability experiment."""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path


PIN = Path(os.environ.get("SYGMA_BPF_PIN", "/sys/fs/bpf/sygma"))


class SnapshotError(RuntimeError):
    """The requested runtime or BPF state could not be read safely."""


def _run_candidates(commands, description, allow_missing=False):
    failures = []
    missing = False
    for command in commands:
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError as error:
            failures.append(f"{' '.join(command)}: {error}")
            continue

        if result.returncode == 0:
            return result.stdout

        detail = (result.stderr or result.stdout).strip()
        lowered = detail.lower()
        # bpftool JSON output differs by version for a missing hash-map key.
        # Some releases print an error string, while bpftool 7.6 prints the
        # valid JSON literal `null` and exits with status 1.
        if (
            lowered == "null"
            or "key is not found" in lowered
            or "no such file or directory" in lowered
        ):
            missing = True
        failures.append(f"{' '.join(command)}: {detail or f'exit {result.returncode}'}")

    if allow_missing and missing:
        return None
    raise SnapshotError(f"{description} failed\n  " + "\n  ".join(failures))


def _bpftool(arguments, description, allow_missing=False):
    commands = [
        ["bpftool", "-j", *arguments],
        ["sudo", "-n", "bpftool", "-j", *arguments],
    ]
    return _run_candidates(commands, description, allow_missing=allow_missing)


def _json_output(output, description):
    try:
        return json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise SnapshotError(f"{description} returned invalid JSON: {error}") from error


def _map_path(name):
    return str(PIN / name)


def map_metadata(name, expected_type, key_size, value_size):
    output = _bpftool(
        ["map", "show", "pinned", _map_path(name)],
        f"show pinned map {name}",
    )
    data = _json_output(output, f"show pinned map {name}")
    if isinstance(data, list):
        if len(data) != 1:
            raise SnapshotError(f"map {name}: expected one pinned map, got {len(data)}")
        data = data[0]
    if not isinstance(data, dict):
        raise SnapshotError(f"map {name}: unexpected metadata {data!r}")

    actual = {
        "name": name,
        "id": int(data.get("id", -1)),
        "type": data.get("type"),
        # bpftool uses bytes_key/bytes_value in current JSON output. Accept
        # key_size/value_size as well for older packaged versions.
        "key_size": int(
            data.get("bytes_key", data.get("key_size", data.get("key", -1)))
        ),
        "value_size": int(
            data.get("bytes_value", data.get("value_size", data.get("value", -1)))
        ),
        "max_entries": int(data.get("max_entries", -1)),
    }
    expected = (expected_type, key_size, value_size)
    observed = (actual["type"], actual["key_size"], actual["value_size"])
    if observed != expected:
        raise SnapshotError(
            f"map {name}: ABI mismatch; expected type/key/value "
            f"{expected_type}/{key_size}/{value_size}, got "
            f"{actual['type']}/{actual['key_size']}/{actual['value_size']}"
        )
    if actual["id"] < 0 or actual["max_entries"] <= 0:
        raise SnapshotError(f"map {name}: incomplete metadata {actual!r}")
    return actual


def raw(field):
    if isinstance(field, list):
        return bytes(int(value, 16) if isinstance(value, str) else value for value in field)
    if isinstance(field, dict) and "bytes" in field:
        return raw(field["bytes"])
    raise SnapshotError(f"unsupported bpftool byte field: {field!r}")


def u32s(field, number):
    data = raw(field)
    required = number * 4
    if len(data) < required:
        raise SnapshotError(f"expected at least {required} bytes, got {len(data)}")
    return struct.unpack("<" + "I" * number, data[:required])


def u64(field):
    data = raw(field)
    if len(data) < 8:
        raise SnapshotError(f"expected at least 8 bytes, got {len(data)}")
    return struct.unpack("<Q", data[:8])[0]


def dump_map(name, expected_type, key_size, value_size):
    metadata = map_metadata(name, expected_type, key_size, value_size)
    output = _bpftool(
        ["map", "dump", "pinned", _map_path(name)],
        f"dump pinned map {name}",
    )
    entries = _json_output(output, f"dump pinned map {name}")
    if not isinstance(entries, list):
        raise SnapshotError(f"map {name}: expected a list of entries")
    metadata["entry_count"] = len(entries)
    return metadata, entries


def lookup_map(name, expected_type, key_size, value_size, key):
    metadata = map_metadata(name, expected_type, key_size, value_size)
    if len(key) != key_size:
        raise SnapshotError(f"map {name}: lookup key is {len(key)} bytes, expected {key_size}")
    key_hex = [f"{byte:02x}" for byte in key]
    output = _bpftool(
        ["map", "lookup", "pinned", _map_path(name), "key", "hex", *key_hex],
        f"lookup key in pinned map {name}",
        allow_missing=True,
    )
    if output is None:
        return metadata, None
    entry = _json_output(output, f"lookup pinned map {name}")
    if not isinstance(entry, dict) or "value" not in entry:
        raise SnapshotError(f"map {name}: unexpected lookup result {entry!r}")
    return metadata, entry


def blocked_snapshot():
    metadata, entries = dump_map("blocked_history", "hash", 20, 4)
    result = {}
    for entry in entries:
        mntns, pidns, source, target, phase = u32s(entry["key"], 5)
        count = u32s(entry["value"], 1)[0]
        result[f"{mntns}:{pidns}:{source}:{target}:{phase}"] = count
    metadata["entries"] = result
    return metadata


def heartbeat_snapshot():
    metadata, entries = dump_map("transition_check_count", "hash", 12, 8)
    result = {}
    for entry in entries:
        mntns, pidns, phase = u32s(entry["key"], 3)
        result[f"{mntns}:{pidns}:{phase}"] = u64(entry["value"])
    metadata["entries"] = result
    return metadata


def observed_snapshot(mntns, pidns, phase):
    metadata, entries = dump_map("observed_transition_map", "hash", 20, 4)
    transitions = []
    for entry in entries:
        entry_mntns, entry_pidns, source, target, entry_phase = u32s(
            entry["key"], 5
        )
        if (entry_mntns, entry_pidns, entry_phase) != (mntns, pidns, phase):
            continue
        transitions.append(
            {
                "from": source,
                "to": target,
                "count": u32s(entry["value"], 1)[0],
            }
        )
    transitions.sort(key=lambda item: (item["from"], item["to"]))
    syscalls = sorted(
        {
            syscall
            for item in transitions
            for syscall in (item["from"], item["to"])
            if syscall != 500
        }
    )
    return {
        "namespace": {"mntns": mntns, "pidns": pidns},
        "phase": phase,
        "unique_transition_count": len(transitions),
        "event_count": sum(item["count"] for item in transitions),
        "unique_syscall_count": len(syscalls),
        "unique_syscalls": syscalls,
        "has_start_transition": any(item["from"] == 500 for item in transitions),
        "transitions": transitions,
        "map": metadata,
    }


def observed_all_snapshot():
    metadata, entries = dump_map("observed_transition_map", "hash", 20, 4)
    result = {}
    for entry in entries:
        mntns, pidns, source, target, phase = u32s(entry["key"], 5)
        result[f"{mntns}:{pidns}:{source}:{target}:{phase}"] = u32s(
            entry["value"], 1
        )[0]
    metadata["entries"] = result
    return metadata


def _map_key(*values):
    return struct.pack("<" + "I" * len(values), *values)


def readiness_snapshot(mntns, pidns, host_pid):
    graph_metadata, graph_entries = dump_map("syscall_graph_map", "hash", 16, 45)
    graph_rows = 0
    phase0_rows = 0
    phase0_start_row = False
    for entry in graph_entries:
        entry_mntns, entry_pidns, source, phase = u32s(entry["key"], 4)
        if entry_mntns == mntns and entry_pidns == pidns:
            graph_rows += 1
            if phase == 0:
                phase0_rows += 1
                if source == 500:
                    phase0_start_row = True

    namespace_key = _map_key(mntns, pidns)
    pid_mount_metadata, pid_mount_entry = lookup_map(
        "pid_mount_ns_map", "hash", 8, 8, namespace_key
    )
    execution_metadata, execution_entry = lookup_map(
        "execution_time_map", "hash", 8, 20, namespace_key
    )
    process_metadata, process_entries = dump_map(
        "process_state_map", "hash", 4, 20
    )
    matching_process_entries = [
        entry for entry in process_entries if u32s(entry["key"], 1)[0] == host_pid
    ]
    if len(matching_process_entries) > 1:
        raise SnapshotError(
            f"process_state_map contains duplicate keys for host PID {host_pid}"
        )
    process_entry = (
        matching_process_entries[0] if matching_process_entries else None
    )

    tid_metadata, tid_entries = dump_map("tid_to_namespace", "hash", 4, 8)
    namespace_tids = []
    for entry in tid_entries:
        tid = u32s(entry["key"], 1)[0]
        entry_mntns, entry_pidns = u32s(entry["value"], 2)
        if entry_mntns == mntns and entry_pidns == pidns:
            namespace_tids.append(tid)

    container_metadata, container_entries = dump_map(
        "container_info_map", "hash", 8, 64
    )
    matching_container_entries = [
        entry
        for entry in container_entries
        # container_info_key is pidns,mntns, unlike pid_mount_ns.
        if u32s(entry["key"], 2) == (pidns, mntns)
    ]
    if len(matching_container_entries) > 1:
        raise SnapshotError(
            "container_info_map contains duplicate keys for the exact namespace"
        )
    container_entry = (
        matching_container_entries[0] if matching_container_entries else None
    )
    container_name = None
    if container_entry is not None:
        container_name = (
            raw(container_entry["value"])
            .split(b"\0", 1)[0]
            .decode(errors="replace")
        )

    execution = None
    if execution_entry is not None:
        value = raw(execution_entry["value"])
        comm = value[:16].split(b"\0", 1)[0].decode(errors="replace")
        execution = {
            "comm": comm,
            "execution_time": struct.unpack("<I", value[16:20])[0],
        }

    process_state = None
    if process_entry is not None:
        previous, current, image_id, saved_previous, in_signal = u32s(
            process_entry["value"], 5
        )
        process_state = {
            "previous_syscall": previous,
            "current_syscall": current,
            "image_id": image_id,
            "saved_previous_syscall": saved_previous,
            "in_signal_handler": in_signal,
        }

    return {
        "namespace": {"mntns": mntns, "pidns": pidns},
        "host_pid": host_pid,
        "graph_rows": graph_rows,
        "phase0_graph_rows": phase0_rows,
        "phase0_start_row": phase0_start_row,
        "pid_mount_value": (
            u64(pid_mount_entry["value"]) if pid_mount_entry is not None else None
        ),
        "execution": execution,
        "root_process_state": process_state,
        "namespace_tids": sorted(namespace_tids),
        "root_tid_namespace_match": host_pid in namespace_tids,
        "container_info": container_name,
        "maps": {
            "syscall_graph_map": graph_metadata,
            "pid_mount_ns_map": pid_mount_metadata,
            "execution_time_map": execution_metadata,
            "process_state_map": process_metadata,
            "tid_to_namespace": tid_metadata,
            "container_info_map": container_metadata,
        },
    }


def normalize_container_id(container_id):
    value = container_id.strip()
    if "://" in value:
        _runtime, value = value.split("://", 1)
    if not value or any(character.isspace() for character in value):
        raise SnapshotError(f"invalid container ID {container_id!r}")
    return value


def _crictl_inspect(container_id):
    commands = [
        ["crictl", "inspect", "--output", "json", container_id],
        ["sudo", "-n", "crictl", "inspect", "--output", "json", container_id],
    ]
    output = _run_candidates(commands, f"crictl inspect {container_id}")
    data = _json_output(output, f"crictl inspect {container_id}")
    if not isinstance(data, dict):
        raise SnapshotError("crictl inspect returned a non-object")
    return data


def _inspect_info(data):
    info = data.get("info")
    if isinstance(info, str):
        info = _json_output(info, "crictl inspect info")
    return info if isinstance(info, dict) else {}


def _host_pid(data):
    info = _inspect_info(data)
    candidates = [
        info.get("pid"),
        data.get("pid"),
        data.get("status", {}).get("pid") if isinstance(data.get("status"), dict) else None,
    ]
    for candidate in candidates:
        try:
            pid = int(candidate)
        except (TypeError, ValueError):
            continue
        if pid > 1:
            return pid
    raise SnapshotError("crictl inspect did not contain a valid host PID")


def _inspected_container_id(data):
    status = data.get("status")
    if isinstance(status, dict):
        value = status.get("id")
        if isinstance(value, str):
            return normalize_container_id(value)
    return None


def _namespace_inode(host_pid, namespace):
    path = Path("/proc") / str(host_pid) / "ns" / namespace
    try:
        target = os.readlink(path)
    except OSError:
        output = _run_candidates(
            [
                ["readlink", str(path)],
                ["sudo", "-n", "readlink", str(path)],
            ],
            f"read namespace link {path}",
        )
        target = output.strip()
    match = re.fullmatch(rf"{re.escape(namespace)}:\[(\d+)\]", target)
    if not match:
        raise SnapshotError(f"unexpected namespace link {path} -> {target!r}")
    return int(match.group(1))


def resolve_namespace(container_id):
    requested_id = normalize_container_id(container_id)
    data = _crictl_inspect(requested_id)
    inspected_id = _inspected_container_id(data)
    if inspected_id is None:
        raise SnapshotError("crictl inspect did not return status.id")
    if inspected_id != requested_id:
        raise SnapshotError(
            f"crictl returned a different container: requested {requested_id}, "
            f"got {inspected_id}"
        )

    host_pid = _host_pid(data)
    if not Path("/proc", str(host_pid)).exists():
        raise SnapshotError(f"container host PID {host_pid} no longer exists")
    return {
        "source": "crictl-proc",
        "container_id": requested_id,
        "host_pid": host_pid,
        "mntns": _namespace_inode(host_pid, "mnt"),
        "pidns": _namespace_inode(host_pid, "pid"),
    }


def build_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("blocked", help="dump blocked_history with map metadata")
    subparsers.add_parser(
        "heartbeat", help="dump the phase-specific transition-check heartbeat"
    )

    namespace = subparsers.add_parser(
        "namespace", help="resolve one exact CRI container through its host PID"
    )
    namespace.add_argument("--container-id", required=True)

    readiness = subparsers.add_parser(
        "readiness", help="inspect policy and detector state for one exact container"
    )
    readiness.add_argument("--mntns", required=True, type=int)
    readiness.add_argument("--pidns", required=True, type=int)
    readiness.add_argument("--host-pid", required=True, type=int)

    observed = subparsers.add_parser(
        "observed", help="dump observed transitions for one exact namespace"
    )
    observed.add_argument("--mntns", required=True, type=int)
    observed.add_argument("--pidns", required=True, type=int)
    observed.add_argument("--phase", required=True, type=int)

    subparsers.add_parser(
        "observed-all", help="dump all observed transitions with map metadata"
    )
    return parser


def main():
    args = build_parser().parse_args()
    try:
        if args.command == "blocked":
            value = blocked_snapshot()
        elif args.command == "heartbeat":
            value = heartbeat_snapshot()
        elif args.command == "namespace":
            value = resolve_namespace(args.container_id)
        elif args.command == "observed":
            value = observed_snapshot(args.mntns, args.pidns, args.phase)
        elif args.command == "observed-all":
            value = observed_all_snapshot()
        else:
            value = readiness_snapshot(args.mntns, args.pidns, args.host_pid)
    except SnapshotError as error:
        print(f"map_snapshot: {error}", file=sys.stderr)
        return 1

    json.dump(value, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
