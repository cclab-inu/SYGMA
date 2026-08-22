#!/usr/bin/env python3
"""Preload the fixed SYGMA startup-gap policy into Redis.

This utility intentionally uses only Python's standard library and speaks
RESP2 directly.  It mirrors sygma-operator/pkg/storage/manager.go instead of
depending on redis-cli or a Python Redis package.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Sequence


IMAGE_NAME = "sygma-gap-probe:v1"
BINARY_NAME = "gap-probe"
BINARY_PATH = "/opt/eval/gap-probe"
START_SYSCALL = 500
MASK_BYTES = 45
POLICY_TTL_SECONDS = 24 * 60 * 60
UINT32_MAX = (1 << 32) - 1

VALID_SYSCALLS = tuple(range(0, 335)) + tuple(range(424, 449))
ALLOWED_MAIN_SYSCALLS = VALID_SYSCALLS


class RedisError(RuntimeError):
    """Redis returned an error reply or an invalid response."""


def _as_bytes(value: bytes | str | int) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def _encode_command(parts: Sequence[bytes | str | int]) -> bytes:
    encoded = [_as_bytes(part) for part in parts]
    chunks = [b"*" + str(len(encoded)).encode("ascii") + b"\r\n"]
    for part in encoded:
        chunks.extend(
            (
                b"$" + str(len(part)).encode("ascii") + b"\r\n",
                part,
                b"\r\n",
            )
        )
    return b"".join(chunks)


class RESPClient:
    """Small binary-safe RESP2 client sufficient for this preparation step."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self._socket = socket.create_connection((host, port), timeout=timeout)
        self._socket.settimeout(timeout)
        self._reader = self._socket.makefile("rb")

    def close(self) -> None:
        try:
            self._reader.close()
        finally:
            self._socket.close()

    def __enter__(self) -> "RESPClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def command(self, *parts: bytes | str | int) -> Any:
        self._socket.sendall(_encode_command(parts))
        return self._read_reply()

    def pipeline(
        self, commands: Sequence[Sequence[bytes | str | int]]
    ) -> list[Any]:
        if not commands:
            return []
        self._socket.sendall(b"".join(_encode_command(command) for command in commands))
        return [self._read_reply() for _ in commands]

    def transaction(
        self, commands: Sequence[Sequence[bytes | str | int]]
    ) -> list[Any]:
        replies = self.pipeline(
            [("MULTI",), *commands, ("EXEC",)]
        )
        if replies[0] != b"OK":
            raise RedisError(f"MULTI returned {replies[0]!r}")
        for index, reply in enumerate(replies[1:-1]):
            if reply != b"QUEUED":
                raise RedisError(
                    f"transaction command {index} was not queued: {reply!r}"
                )
        executed = replies[-1]
        if executed is None:
            raise RedisError("transaction aborted")
        if not isinstance(executed, list) or len(executed) != len(commands):
            raise RedisError("EXEC returned an unexpected number of replies")
        return executed

    def _read_line(self) -> bytes:
        line = self._reader.readline()
        if not line:
            raise RedisError("Redis closed the connection")
        if not line.endswith(b"\r\n"):
            raise RedisError("malformed RESP line")
        return line[:-2]

    def _read_reply(self) -> Any:
        prefix = self._reader.read(1)
        if not prefix:
            raise RedisError("Redis closed the connection")
        if prefix == b"+":
            return self._read_line()
        if prefix == b"-":
            message = self._read_line().decode("utf-8", "replace")
            raise RedisError(message)
        if prefix == b":":
            return int(self._read_line())
        if prefix == b"$":
            length = int(self._read_line())
            if length == -1:
                return None
            data = self._reader.read(length)
            terminator = self._reader.read(2)
            if len(data) != length or terminator != b"\r\n":
                raise RedisError("malformed RESP bulk string")
            return data
        if prefix == b"*":
            count = int(self._read_line())
            if count == -1:
                return None
            return [self._read_reply() for _ in range(count)]
        raise RedisError(f"unsupported RESP reply prefix {prefix!r}")


def syscall_to_bit_index(syscall: int) -> int:
    if 0 <= syscall <= 334:
        return syscall
    if 424 <= syscall <= 448:
        return 335 + syscall - 424
    raise ValueError(f"unsupported syscall number {syscall}")


def policy_mask(syscalls: Iterable[int]) -> bytes:
    """Return storage-manager-compatible 360-bit, big-endian mask bytes."""

    bits = 0
    for syscall in syscalls:
        bits |= 1 << syscall_to_bit_index(syscall)
    return bits.to_bytes(MASK_BYTES, byteorder="big", signed=False)


PHASE0_MASK = policy_mask(VALID_SYSCALLS)
PHASE1_MASK = policy_mask(ALLOWED_MAIN_SYSCALLS)


def phase0_rows(image_id: int) -> dict[str, bytes]:
    sources = (START_SYSCALL, *VALID_SYSCALLS)
    return {
        f"syscall_graph:{image_id}:0:{source}": PHASE0_MASK
        for source in sources
    }


def phase1_rows(image_id: int) -> dict[str, bytes]:
    # A main sequence admits its first syscall by source-key existence.  There
    # is deliberately no source row for the target and no synthetic START row.
    return {
        f"syscall_graph:{image_id}:1:{source}": PHASE1_MASK
        for source in ALLOWED_MAIN_SYSCALLS
    }


def typed_main_policy() -> bytes:
    # ocihook/ebpf/hook/main.go's installStateMachinePolicy only accepts
    # type "state-machine" (installTypedMainPolicy's older "sequence" type
    # was removed; see the 2026-08-20 note near
    # SYGMA_LEGACY_REQUIRED_PINNED_MAPS in scripts/run_experiment.py for the
    # broader map/policy-ABI audit this belongs to). A single initial state
    # whose allow-list is every valid syscall, with no explicit transitions,
    # is an allow-all observation policy: monitoring.c's
    # state_machine_policy_decision leaves process_state.policy_state
    # unchanged whenever policy_state_transition_map has no entry for the
    # current (state, syscall) pair, so omitting transitions is a self-loop
    # on state 0, not a gap in coverage.
    allowed = list(ALLOWED_MAIN_SYSCALLS)
    policy = {
        "type": "state-machine",
        "stateMachine": {
            "initialState": 0,
            "states": {"0": {"allowedSyscalls": allowed}},
        },
    }
    return json.dumps(
        policy, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _decode_text(value: Any, description: str) -> str:
    if not isinstance(value, bytes):
        raise RedisError(f"{description} is not a bulk string: {value!r}")
    return value.decode("utf-8")


def parse_image_id(value: Any, description: str) -> int:
    raw_id = _decode_text(value, description)
    if not raw_id.isascii() or not raw_id.isdigit():
        raise RedisError(f"{description} contains invalid ID {raw_id!r}")
    image_id = int(raw_id)
    if not 1 <= image_id <= UINT32_MAX:
        raise RedisError(f"{description} contains out-of-range ID {image_id}")
    return image_id


def scan_keys(client: RESPClient, pattern: str) -> set[str]:
    cursor = 0
    found: set[str] = set()
    while True:
        reply = client.command("SCAN", cursor, "MATCH", pattern, "COUNT", 1000)
        if not isinstance(reply, list) or len(reply) != 2:
            raise RedisError(f"malformed SCAN reply for {pattern!r}")
        cursor = int(_decode_text(reply[0], "SCAN cursor"))
        keys = reply[1]
        if not isinstance(keys, list):
            raise RedisError(f"malformed SCAN key list for {pattern!r}")
        for key in keys:
            found.add(_decode_text(key, "Redis key"))
        if cursor == 0:
            return found


def keys_for_image(client: RESPClient, image_id: int) -> set[str]:
    keys = scan_keys(client, f"syscall_graph:{image_id}:*")
    keys.update(scan_keys(client, f"syscall_meta:{image_id}:*"))
    for key in (
        f"main_policy:{image_id}",
        f"image_id_map:{image_id}",
        f"policy_ready:{image_id}",
    ):
        if client.command("EXISTS", key) == 1:
            keys.add(key)
    return keys


def image_aliases_for_id(client: RESPClient, image_id: int) -> set[str]:
    alias_keys = sorted(scan_keys(client, "image_name_map:*"))
    if not alias_keys:
        return set()
    values = client.pipeline([("GET", key) for key in alias_keys])
    expected = str(image_id).encode("ascii")
    return {
        key
        for key, value in zip(alias_keys, values)
        if value == expected
    }


def resolve_image_id(client: RESPClient) -> tuple[int, bool]:
    mapping_key = f"image_name_map:{IMAGE_NAME}"
    existing = client.command("GET", mapping_key)
    expected_owner = f"{IMAGE_NAME}:{BINARY_NAME}".encode("utf-8")
    if existing is not None:
        image_id = parse_image_id(existing, mapping_key)
        owner = client.command("GET", f"image_id_map:{image_id}")
        if owner not in (None, expected_owner):
            raise RedisError(
                f"refusing cleanup: image ID {image_id} is owned by {owner!r}, "
                f"not {expected_owner!r}"
            )
        aliases = image_aliases_for_id(client, image_id)
        if aliases != {mapping_key}:
            raise RedisError(
                f"refusing cleanup: image ID {image_id} is also referenced by "
                f"unexpected alias keys {sorted(aliases - {mapping_key})!r}"
            )
        return image_id, True

    # INCR follows the storage manager's allocation scheme.  Skip a candidate
    # if a stale/corrupt database already has any image-owned key for that ID;
    # this utility never deletes keys without the unique alias proving ownership.
    while True:
        image_id = client.command("INCR", "image_id_counter")
        if not isinstance(image_id, int) or not 1 <= image_id <= UINT32_MAX:
            raise RedisError(f"image_id_counter produced invalid ID {image_id!r}")
        if (
            not keys_for_image(client, image_id)
            and not image_aliases_for_id(client, image_id)
        ):
            return image_id, False


@dataclass(frozen=True)
class PolicyPlan:
    image_id: int
    phase0: dict[str, bytes]
    phase1: dict[str, bytes]
    main_policy: bytes


def make_plan(image_id: int) -> PolicyPlan:
    return PolicyPlan(
        image_id=image_id,
        phase0=phase0_rows(image_id),
        phase1=phase1_rows(image_id),
        main_policy=typed_main_policy(),
    )


def write_plan(client: RESPClient, plan: PolicyPlan) -> int:
    image_id = plan.image_id
    cleanup_keys = keys_for_image(client, image_id)
    cleanup_keys.add(f"image_name_map:{IMAGE_NAME}")
    cleanup_keys.add(f"temp_binary:{IMAGE_NAME}")

    commands: list[tuple[bytes | str | int, ...]] = [
        ("DEL", *sorted(cleanup_keys)),
        (
            "SET",
            f"image_name_map:{IMAGE_NAME}",
            image_id,
            "EX",
            POLICY_TTL_SECONDS,
        ),
        (
            "SET",
            f"image_id_map:{image_id}",
            f"{IMAGE_NAME}:{BINARY_NAME}",
            "EX",
            POLICY_TTL_SECONDS,
        ),
        (
            "SET",
            f"temp_binary:{IMAGE_NAME}",
            json.dumps(
                {"name": BINARY_NAME, "path": BINARY_PATH},
                sort_keys=True,
                separators=(",", ":"),
            ),
            "EX",
            POLICY_TTL_SECONDS,
        ),
    ]
    for key, value in sorted(plan.phase0.items()):
        commands.append(("SET", key, value, "EX", POLICY_TTL_SECONDS))
    commands.append(
        (
            "SET",
            f"syscall_meta:{image_id}:0",
            f"{len(plan.phase0)}:0",
            "EX",
            POLICY_TTL_SECONDS,
        )
    )
    for key, value in sorted(plan.phase1.items()):
        commands.append(("SET", key, value, "EX", POLICY_TTL_SECONDS))
    commands.extend(
        (
            (
                "SET",
                f"syscall_meta:{image_id}:1",
                f"{len(plan.phase1)}:0",
                "EX",
                POLICY_TTL_SECONDS,
            ),
            (
                "SET",
                f"main_policy:{image_id}",
                plan.main_policy,
                "EX",
                POLICY_TTL_SECONDS,
            ),
            # Matches sygma-operator/pkg/storage/manager.go's PolicyReadyKey:
            # the hook's loadImagePolicyToEBPF refuses to trust any payload
            # key until this nonempty marker exists (see
            # IsPolicyPublicationReady). manager.go sets it atomically
            # alongside main_policy; do the same here.
            (
                "SET",
                f"policy_ready:{image_id}",
                "prepare_sygma_policy",
                "EX",
                POLICY_TTL_SECONDS,
            ),
        )
    )
    client.transaction(commands)
    return len(cleanup_keys)


def _expect_equal(actual: Any, expected: Any, description: str) -> None:
    if actual != expected:
        raise RedisError(
            f"verification failed for {description}: "
            f"got {actual!r}, expected {expected!r}"
        )


def verify_plan(client: RESPClient, plan: PolicyPlan) -> dict[str, Any]:
    image_id = plan.image_id
    _expect_equal(
        client.command("GET", f"image_name_map:{IMAGE_NAME}"),
        str(image_id).encode("ascii"),
        "image-name mapping",
    )
    _expect_equal(
        client.command("GET", f"image_id_map:{image_id}"),
        f"{IMAGE_NAME}:{BINARY_NAME}".encode("utf-8"),
        "image-ID mapping",
    )
    _expect_equal(
        client.command("GET", f"temp_binary:{IMAGE_NAME}"),
        json.dumps(
            {"name": BINARY_NAME, "path": BINARY_PATH},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
        "temporary binary name/path mapping",
    )

    actual_phase0 = scan_keys(client, f"syscall_graph:{image_id}:0:*")
    actual_phase1 = scan_keys(client, f"syscall_graph:{image_id}:1:*")
    _expect_equal(actual_phase0, set(plan.phase0), "phase-0 key set")
    _expect_equal(actual_phase1, set(plan.phase1), "phase-1 key set")
    _expect_equal(
        client.command("GET", f"syscall_meta:{image_id}:0"),
        f"{len(plan.phase0)}:0".encode("ascii"),
        "phase-0 metadata",
    )
    _expect_equal(
        client.command("GET", f"syscall_meta:{image_id}:1"),
        f"{len(plan.phase1)}:0".encode("ascii"),
        "phase-1 metadata",
    )

    graph_commands = [
        ("GET", key) for key in (*sorted(plan.phase0), *sorted(plan.phase1))
    ]
    graph_values = client.pipeline(graph_commands)
    expected_values = [
        *(plan.phase0[key] for key in sorted(plan.phase0)),
        *(plan.phase1[key] for key in sorted(plan.phase1)),
    ]
    for index, (actual, expected) in enumerate(zip(graph_values, expected_values)):
        _expect_equal(actual, expected, f"graph mask #{index}")
        if not isinstance(actual, bytes) or len(actual) != MASK_BYTES:
            raise RedisError(f"graph mask #{index} is not exactly 45 bytes")

    raw_main = client.command("GET", f"main_policy:{image_id}")
    _expect_equal(raw_main, plan.main_policy, "typed main policy bytes")
    _expect_equal(
        client.command("GET", f"policy_ready:{image_id}"),
        b"prepare_sygma_policy",
        "policy publication ready marker",
    )
    try:
        decoded_main = json.loads(_decode_text(raw_main, "typed main policy"))
    except json.JSONDecodeError as error:
        raise RedisError("typed main policy is not valid JSON") from error
    _expect_equal(decoded_main.get("type"), "state-machine", "main policy type")
    state_machine = decoded_main.get("stateMachine") or {}
    _expect_equal(state_machine.get("initialState"), 0, "state-machine initial state")
    states = state_machine.get("states") or {}
    _expect_equal(set(states), {"0"}, "state-machine state set")
    _expect_equal(
        sorted(states.get("0", {}).get("allowedSyscalls") or []),
        sorted(ALLOWED_MAIN_SYSCALLS),
        "state 0 allow-list",
    )

    # All managed values should still have a positive TTL after preparation.
    ttl_keys = [
        f"image_name_map:{IMAGE_NAME}",
        f"image_id_map:{image_id}",
        f"syscall_meta:{image_id}:0",
        f"syscall_meta:{image_id}:1",
        f"main_policy:{image_id}",
        f"policy_ready:{image_id}",
        f"temp_binary:{IMAGE_NAME}",
        *sorted(plan.phase0),
        *sorted(plan.phase1),
    ]
    ttls = client.pipeline([("TTL", key) for key in ttl_keys])
    if any(not isinstance(ttl, int) or ttl <= 0 for ttl in ttls):
        raise RedisError(f"one or more managed keys have invalid TTLs: {ttls!r}")

    return {
        "binary_name": BINARY_NAME,
        "binary_path": BINARY_PATH,
        "policy_scope": "all_valid_x86_64_syscalls",
        "observation_only": True,
        "image_id": image_id,
        "image_name": IMAGE_NAME,
        "main_policy_type": "state-machine",
        "mask_bytes": MASK_BYTES,
        "phase0_rows": len(plan.phase0),
        "phase0_start_row": f"syscall_graph:{image_id}:0:{START_SYSCALL}",
        "phase1_rows": len(plan.phase1),
        "ttl_seconds": min(ttls),
        "verified": True,
    }


def self_test() -> dict[str, Any]:
    if len(VALID_SYSCALLS) != 360 or len(set(VALID_SYSCALLS)) != 360:
        raise AssertionError("valid syscall universe must contain exactly 360 entries")
    if syscall_to_bit_index(424) != 335 or syscall_to_bit_index(448) != 359:
        raise AssertionError("high syscall range mapping is incorrect")
    if PHASE0_MASK != b"\xff" * MASK_BYTES:
        raise AssertionError("all-valid mask must be 45 bytes of 0xff")
    if len(PHASE1_MASK) != MASK_BYTES:
        raise AssertionError("main mask length is not 45 bytes")
    if PHASE1_MASK != b"\xff" * MASK_BYTES:
        raise AssertionError("main observation mask must cover all valid syscalls")
    if sum(byte.bit_count() for byte in PHASE1_MASK) != 360:
        raise AssertionError("main mask must observe exactly 360 syscalls")
    sample = make_plan(1)
    if len(sample.phase0) != 361 or len(sample.phase1) != 360:
        raise AssertionError("unexpected policy row count")
    if f"syscall_graph:1:0:{START_SYSCALL}" not in sample.phase0:
        raise AssertionError("phase 0 START row is missing")
    decoded = json.loads(sample.main_policy)
    if decoded["type"] != "state-machine":
        raise AssertionError("typed policy must declare type state-machine")
    if len(decoded["stateMachine"]["states"]["0"]["allowedSyscalls"]) != 360:
        raise AssertionError("typed policy state 0 must allow all valid syscalls")
    encoded = _encode_command(("SET", "binary", b"\x00\r\n"))
    if encoded != b"*3\r\n$3\r\nSET\r\n$6\r\nbinary\r\n$3\r\n\x00\r\n\r\n":
        raise AssertionError("RESP command encoding is not binary safe")
    return {
        "image_name": IMAGE_NAME,
        "mask_bytes": MASK_BYTES,
        "phase0_rows": len(sample.phase0),
        "phase1_rows": len(sample.phase1),
        "self_test": "passed",
    }


def parse_redis_address(raw: str) -> tuple[str, int]:
    if raw.startswith("["):
        closing = raw.find("]")
        if closing == -1 or closing + 1 >= len(raw) or raw[closing + 1] != ":":
            raise ValueError("bracketed Redis address must be [host]:port")
        host = raw[1:closing]
        port_raw = raw[closing + 2 :]
    else:
        if raw.count(":") != 1:
            raise ValueError("Redis address must be host:port")
        host, port_raw = raw.rsplit(":", 1)
    if not host:
        raise ValueError("Redis host is empty")
    try:
        port = int(port_raw)
    except ValueError as error:
        raise ValueError(f"invalid Redis port {port_raw!r}") from error
    if not 1 <= port <= 65535:
        raise ValueError(f"Redis port is out of range: {port}")
    return host, port


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image-name",
        default=IMAGE_NAME,
        help=f"policy image alias (default: {IMAGE_NAME})",
    )
    parser.add_argument(
        "--binary-name",
        default=BINARY_NAME,
        help=f"main process basename, at most 15 bytes (default: {BINARY_NAME})",
    )
    parser.add_argument(
        "--binary-path",
        default=BINARY_PATH,
        help=f"absolute in-image main process path (default: {BINARY_PATH})",
    )
    parser.add_argument(
        "--redis-addr",
        metavar="HOST:PORT",
        help="Redis DB 0 address (required unless --dry-run or --self-test)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Redis connect/read/write timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify the already-preloaded alias without changing Redis",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and describe the fixed policy without connecting to Redis",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run deterministic mask/schema tests without connecting to Redis",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="compatibility flag; output is always one JSON object",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    global IMAGE_NAME, BINARY_NAME, BINARY_PATH

    parser = build_argument_parser()
    args = parser.parse_args(argv)
    try:
        image_name = args.image_name.strip()
        binary_name = args.binary_name.strip()
        binary_path = args.binary_path.strip()
        if not image_name or any(character.isspace() for character in image_name):
            raise ValueError("--image-name must be non-empty and contain no whitespace")
        if (
            not binary_name
            or "/" in binary_name
            or ":" in binary_name
            or len(binary_name.encode("utf-8")) > 15
        ):
            raise ValueError(
                "--binary-name must be a basename without ':' and at most 15 bytes"
            )
        if not binary_path.startswith("/") or any(
            character.isspace() for character in binary_path
        ):
            raise ValueError(
                "--binary-path must be an absolute path without whitespace"
            )
        IMAGE_NAME = image_name
        BINARY_NAME = binary_name
        BINARY_PATH = binary_path
        local_result = self_test()
        if args.self_test:
            print(json.dumps(local_result, sort_keys=True))
            return 0
        if args.dry_run:
            result = dict(local_result)
            result.update(
                {
                    "binary_name": BINARY_NAME,
                    "binary_path": BINARY_PATH,
                    "policy_scope": "all_valid_x86_64_syscalls",
                    "observation_only": True,
                    "dry_run": True,
                    "main_policy_bytes": len(typed_main_policy()),
                }
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if not args.redis_addr:
            parser.error("--redis-addr is required")
        if args.timeout <= 0:
            parser.error("--timeout must be positive")
        host, port = parse_redis_address(args.redis_addr)
        with RESPClient(host, port, args.timeout) as client:
            _expect_equal(client.command("PING"), b"PONG", "Redis PING")
            if args.verify_only:
                mapping = client.command("GET", f"image_name_map:{IMAGE_NAME}")
                if mapping is None:
                    raise RedisError(f"image alias {IMAGE_NAME!r} is not preloaded")
                image_id = parse_image_id(mapping, "image mapping")
                result = verify_plan(client, make_plan(image_id))
                result["mode"] = "verify-only"
            else:
                image_id, reused = resolve_image_id(client)
                plan = make_plan(image_id)
                cleaned = write_plan(client, plan)
                result = verify_plan(client, plan)
                result.update(
                    {
                        "cleaned_keys": cleaned,
                        "image_id_reused": reused,
                        "mode": "write-and-verify",
                    }
                )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, RedisError, ValueError, AssertionError) as error:
        print(f"prepare_sygma_policy: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
