#!/usr/bin/env python3
"""Analyze startup policy-gap experiment results.

The runner writes one record per trial to ``trials.jsonl`` and keeps the raw
probe, map watcher, and OCI-hook timelines in JSONL files.  This module turns
those records into one auditable row per trial and backend-level summaries.

Both arms are non-blocking, so every timed target-system-call attempt must
succeed. Both use OCI prestart entry as the lifecycle origin. SYGMA must prove
publish-before-release ordering and therefore has zero uncovered controlled
calls; its internal would-deny counter instead proves policy-path coverage.
Tetragon readiness is observed in ``(L,U]``. A definite uncovered call has
returned by ``L``; a possible uncovered call began no later than ``U``.
"""

from __future__ import annotations

import argparse
import csv
import errno as errno_module
import hashlib
import json
import math
import os
import random
import re
import statistics
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 3
HOOK_TIMELINE_SCHEMA_VERSION = 2
BOOTSTRAP_RESAMPLES = 2_000
TARGET_SYSCALL_NR = 63
TARGET_SYSCALL_NAME = "uname"

SYGMA_REQUIRED_HOOK_EVENTS = (
    "oci_prestart_enter",
    "sygma_direct_policy_ready",
    "target_release_begin",
    "target_release_signal_sent",
    "oci_prestart_complete",
    "sygma_cleanup_complete",
)


class AnalysisError(RuntimeError):
    """Raised when an input file cannot be analyzed safely."""


@dataclass(frozen=True)
class EventTime:
    ns: int
    clock: str  # "boottime", "realtime", or "unknown"


@dataclass(frozen=True)
class ProbeFacts:
    start_boottime_ns: int | None
    start_realtime_ns: int | None
    first_eperm_boottime_ns: int | None
    first_eperm_realtime_ns: int | None
    attempts: int
    successful: int
    eperm: int
    errors: int
    attempt_boottime_ns: tuple[int, ...]
    attempt_realtime_ns: tuple[int | None, ...]
    attempt_before_boottime_ns: tuple[int, ...]
    attempt_after_boottime_ns: tuple[int, ...]
    attempt_before_realtime_ns: tuple[int | None, ...]
    attempt_after_realtime_ns: tuple[int | None, ...]
    successful_before_first_eperm: int
    successful_before_first_eperm_boottime_ns: tuple[int, ...]
    last_success_before_first_eperm_boottime_ns: int | None
    last_success_before_first_eperm_realtime_ns: int | None
    summary_cgroup_id: int | None
    summary_cgroup_id_errno: int | None
    censored: bool
    summary_seen: bool


@dataclass(frozen=True)
class MapInsertFacts:
    lower_boottime_ns: int
    upper_boottime_ns: int
    lower_realtime_ns: int | None
    upper_realtime_ns: int | None
    policy_id: str | None
    cgroup_id: str | None

    @property
    def interval_width_ns(self) -> int:
        return self.upper_boottime_ns - self.lower_boottime_ns


@dataclass(frozen=True)
class HookReadyFacts:
    boottime_ns: int | None
    realtime_ns: int | None
    mnt_ns: int | None = None
    pid_ns: int | None = None
    host_tgid: int | None = None


@dataclass(frozen=True)
class HookTimelineFacts:
    ready: HookReadyFacts | None
    prestart_enter_boottime_ns: int | None
    prestart_enter_realtime_ns: int | None
    prestart_complete_boottime_ns: int | None
    prestart_complete_realtime_ns: int | None


TRIAL_COLUMNS = [
    "trial_id",
    "backend",
    "application",
    "warmup",
    "valid",
    "invalid_reason",
    "warnings",
    "container_id",
    "api_submit_realtime_ns",
    "api_submit_boottime_ns",
    "api_ack_realtime_ns",
    "api_ack_boottime_ns",
    "pod_creation_time",
    "container_started_time",
    "pod_creation_realtime_ns",
    "container_started_realtime_ns",
    "startup_latency_ns",
    "startup_latency_ms",
    "probe_start_realtime_ns",
    "probe_start_boottime_ns",
    "application_spawn_realtime_ns",
    "application_spawn_boottime_ns",
    "application_pid",
    "application_alive_at_summary",
    "application_exit_realtime_ns",
    "application_exit_boottime_ns",
    "application_exit_phase",
    "application_exit_code",
    "application_exit_signal",
    "first_eperm_realtime_ns",
    "first_eperm_boottime_ns",
    "behavioral_transition_lower_realtime_ns",
    "behavioral_transition_lower_boottime_ns",
    "behavioral_transition_upper_realtime_ns",
    "behavioral_transition_upper_boottime_ns",
    "behavioral_transition_interval_width_ns",
    "behavioral_transition_interval_width_ms",
    "behavioral_denial_latency_ns",
    "behavioral_denial_latency_ms",
    "policy_ready_source",
    "policy_ready_lower_realtime_ns",
    "policy_ready_upper_realtime_ns",
    "policy_ready_lower_boottime_ns",
    "policy_ready_upper_boottime_ns",
    "prestart_trigger_realtime_ns",
    "prestart_trigger_boottime_ns",
    "prestart_hook_duration_ns",
    "prestart_hook_duration_ms",
    "policy_apply_from_prestart_lower_ns",
    "policy_apply_from_prestart_lower_ms",
    "policy_apply_from_prestart_upper_ns",
    "policy_apply_from_prestart_upper_ms",
    "policy_ready_at_prestart",
    "userland_exposure_lower_ns",
    "userland_exposure_lower_ms",
    "userland_exposure_upper_ns",
    "userland_exposure_upper_ms",
    "controlled_attempts_uncovered_definite",
    "controlled_attempts_uncovered_possible",
    "sygma_atomicity_order_valid",
    "sygma_policy_observed_attempts",
    "sygma_non_probe_target_calls_observed",
    "sygma_controlled_attempts_unobserved",
    "sygma_observation_coverage",
    "sygma_ready_to_prestart_complete_ns",
    "sygma_ready_to_prestart_complete_ms",
    "signed_readiness_vs_probe_start_ns",
    "signed_readiness_vs_probe_start_ms",
    "sygma_prestart_lead_ns",
    "sygma_prestart_lead_ms",
    "security_gap_lower_ns",
    "security_gap_lower_ms",
    "security_gap_upper_ns",
    "security_gap_upper_ms",
    "security_gap_ns",
    "security_gap_ms",
    "map_interval_width_ns",
    "map_interval_width_ms",
    "missed_policy_calls",
    "missed_policy_calls_definite",
    "missed_policy_calls_possible",
    "successful_attempts_definitely_before_map_lower",
    "successful_attempts_ambiguous_in_map_interval",
    "oci_prestart_enter_realtime_ns",
    "oci_prestart_enter_boottime_ns",
    "oci_prestart_complete_realtime_ns",
    "oci_prestart_complete_boottime_ns",
    "sygma_hook_cost_ns",
    "sygma_hook_cost_ms",
    "sygma_first_policy_evaluation_boottime_ns",
    "sygma_policy_evaluation_positive",
    "sygma_target_policy_miss_count",
    "sygma_target_policy_other_phase_count",
    "sygma_target_policy_phase0_count",
    "sygma_target_policy_tgid",
    "sygma_target_policy_identity_matches_hook",
    "sygma_target_policy_evidence_positive",
    "sygma_ready_to_first_evaluation_ns",
    "sygma_ready_to_first_evaluation_ms",
    "tetragon_positive_event_observed",
    "tetragon_positive_event_count",
    "censored",
    "probe_attempts",
    "probe_successful",
    "probe_eperm",
    "probe_errors",
    "probe_summary_seen",
    "probe_jsonl",
    "mapwatch_jsonl",
    "hook_timeline_jsonl",
    "sygma_policy_evidence_jsonl",
    "tetragon_events_jsonl",
]


METRICS = (
    "controlled_attempts_uncovered_definite",
    "controlled_attempts_uncovered_possible",
    "policy_apply_from_prestart_lower_ms",
    "policy_apply_from_prestart_upper_ms",
    "userland_exposure_lower_ms",
    "userland_exposure_upper_ms",
    "prestart_hook_duration_ms",
    "sygma_policy_observed_attempts",
    "sygma_non_probe_target_calls_observed",
    "sygma_controlled_attempts_unobserved",
    "sygma_observation_coverage",
    "sygma_ready_to_prestart_complete_ms",
    "successful_attempts_definitely_before_map_lower",
    "successful_attempts_ambiguous_in_map_interval",
    "signed_readiness_vs_probe_start_ms",
    "startup_latency_ms",
    "map_interval_width_ms",
    "sygma_prestart_lead_ms",
    "sygma_ready_to_first_evaluation_ms",
)


SUMMARY_CSV_COLUMNS = [
    "scope",
    "application",
    "backend",
    "total",
    "n",
    "invalid",
    "censored",
    "excluded",
    "exclusion_reasons",
    "warmup",
    "metric",
    "metric_n",
    "median",
    "p95",
    "p99",
    "q1",
    "q3",
    "iqr",
    "mean",
    "sample_stddev",
    "bootstrap_median_ci95_lower",
    "bootstrap_median_ci95_upper",
    "bootstrap_resamples",
    "zero_miss_n",
    "zero_miss_count",
    "zero_miss_rate",
    "zero_uncovered_n",
    "zero_uncovered_count",
    "zero_uncovered_rate",
    "all_zero",
    "rule_of_three_upper_bound",
]


def _event_name(record: Mapping[str, Any]) -> str:
    value = (
        record.get("event")
        or record.get("type")
        or record.get("kind")
        or record.get("event_type")
        or ""
    )
    return str(value).strip().lower().replace("-", "_")


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off", ""}:
        return False
    return default


def _int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def timestamp_to_ns(value: Any, key_hint: str = "") -> int:
    """Convert an RFC3339 or numeric timestamp to integer nanoseconds.

    Numeric values with an explicit unit suffix are handled exactly.  Bare
    numeric timestamps use epoch-scale magnitude inference; raw experiment
    events use explicit ``*_ns`` fields and therefore avoid that ambiguity.
    """

    if value is None or isinstance(value, bool):
        raise ValueError("timestamp is missing or boolean")

    hint = key_hint.lower()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        if not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", text):
            return _rfc3339_to_ns(text)
        try:
            number = Decimal(text)
        except InvalidOperation as exc:
            raise ValueError(f"invalid numeric timestamp: {value!r}") from exc
    elif isinstance(value, (int, float, Decimal)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite timestamp")
        number = Decimal(str(value))
    else:
        raise ValueError(f"unsupported timestamp type: {type(value).__name__}")

    if hint.endswith("_ns") or "nanosecond" in hint:
        multiplier = Decimal(1)
    elif hint.endswith("_us") or "microsecond" in hint:
        multiplier = Decimal(1_000)
    elif hint.endswith("_ms") or "millisecond" in hint:
        multiplier = Decimal(1_000_000)
    elif hint.endswith("_s") or "second" in hint:
        multiplier = Decimal(1_000_000_000)
    else:
        magnitude = abs(number)
        if magnitude >= Decimal("1e17"):
            multiplier = Decimal(1)       # epoch nanoseconds
        elif magnitude >= Decimal("1e14"):
            multiplier = Decimal(1_000)   # epoch microseconds
        elif magnitude >= Decimal("1e11"):
            multiplier = Decimal(1_000_000)  # epoch milliseconds
        else:
            multiplier = Decimal(1_000_000_000)  # epoch/relative seconds
    return int(number * multiplier)


def _rfc3339_to_ns(text: str) -> int:
    # datetime accepts RFC3339 offsets and up to microsecond precision.  Keep
    # any additional fractional digits separately so Kubernetes' nanosecond
    # timestamps are not silently rounded away.
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})",
        text,
    )
    if not match:
        raise ValueError(f"invalid RFC3339 timestamp: {text!r}")
    base, fraction, offset = match.groups()
    dt = datetime.fromisoformat(base + ("+00:00" if offset == "Z" else offset))
    dt = dt.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = dt - epoch
    seconds = delta.days * 86_400 + delta.seconds
    fractional_ns = int(((fraction or "") + "000000000")[:9])
    return seconds * 1_000_000_000 + fractional_ns


def _first_timestamp(record: Mapping[str, Any], keys: Sequence[str]) -> int | None:
    for key in keys:
        if key in record and record[key] is not None:
            try:
                return timestamp_to_ns(record[key], key)
            except ValueError:
                continue
    return None


def _event_times(record: Mapping[str, Any]) -> tuple[int | None, int | None]:
    boot = _first_timestamp(
        record,
        (
            "boottime_ns",
            "ts_boottime_ns",
            "timestamp_boottime_ns",
            "time_boottime_ns",
            "monotonic_ns",
        ),
    )
    real = _first_timestamp(
        record,
        (
            "realtime_ns",
            "ts_realtime_ns",
            "timestamp_realtime_ns",
            "time_realtime_ns",
            "wall_time_ns",
        ),
    )
    generic_keys = ("timestamp_ns", "time_ns", "ts_ns", "timestamp", "time", "ts")
    generic = _first_timestamp(record, generic_keys)
    if generic is not None:
        clock = str(record.get("clock") or record.get("clock_id") or "").lower()
        if boot is None and ("boot" in clock or "mono" in clock):
            boot = generic
        elif real is None and ("real" in clock or "wall" in clock or "epoch" in clock):
            real = generic
        elif boot is None and real is None:
            # Experiment raw events are specified in boottime.  Treat an
            # otherwise unlabeled generic timestamp consistently as such.
            boot = generic
    return boot, real


def _explicit_boottime_ns(record: Mapping[str, Any]) -> int | None:
    """Return only a timestamp explicitly identified as CLOCK_BOOTTIME."""

    return _first_timestamp(
        record,
        (
            "boottime_ns",
            "ts_boottime_ns",
            "timestamp_boottime_ns",
            "time_boottime_ns",
        ),
    )


def read_jsonl(path: Path | str) -> list[dict[str, Any]]:
    path = Path(path)
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AnalysisError(f"{path}:{lineno}: invalid JSON: {exc.msg}") from exc
                if not isinstance(value, dict):
                    raise AnalysisError(f"{path}:{lineno}: JSONL record is not an object")
                records.append(value)
    except OSError as exc:
        raise AnalysisError(f"cannot read {path}: {exc}") from exc
    return records


def _attempt_outcome(record: Mapping[str, Any]) -> str:
    """Return ``success``, ``eperm``, or ``error`` for a probe attempt."""

    errno_value = record.get("errno")
    if isinstance(errno_value, Mapping):
        errno_value = errno_value.get("number") or errno_value.get("code") or errno_value.get("name")
    errno_number = _int_or_none(errno_value)
    errno_text = str(errno_value or "").strip().upper().replace(" ", "_")
    rc = None
    for key in ("rc", "ret", "return_value", "retval"):
        if key in record:
            rc = _int_or_none(record[key])
            break
    if errno_number in {errno_module.EPERM, -errno_module.EPERM} or errno_text in {
        "EPERM",
        "-EPERM",
        "OPERATION_NOT_PERMITTED",
    }:
        return "eperm"
    if (errno_number is not None and errno_number != 0) or (
        rc is not None and rc < 0
    ):
        # A textual "success" cannot override a failing raw syscall result.
        return "error"

    outcome = record.get("outcome", record.get("result", record.get("status")))
    if isinstance(outcome, Mapping):
        outcome = outcome.get("outcome") or outcome.get("status") or outcome.get("name")
    outcome_text = str(outcome or "").strip().lower().replace("-", "_").replace(" ", "_")
    if outcome_text in {"eperm", "denied", "blocked", "policy_denied", "operation_not_permitted"}:
        return "eperm"
    if outcome_text in {"success", "successful", "allowed", "allow", "ok", "passed"}:
        return "success"
    if outcome_text in {"error", "failed", "failure", "unexpected_error"}:
        return "error"

    if record.get("denied") is True:
        return "eperm"
    if record.get("success") is True or record.get("allowed") is True:
        return "success"
    if record.get("success") is False:
        return "error"

    if rc is not None:
        return "success" if rc >= 0 else "error"
    if errno_number == 0:
        return "success"
    return "error"


def parse_probe_events(records: Iterable[Mapping[str, Any]]) -> ProbeFacts:
    records = list(records)
    starts = [
        record
        for record in records
        if _event_name(record) in {"start", "probe_start", "gap_probe_start"}
    ]
    summaries = [
        record
        for record in records
        if _event_name(record) in {"summary", "probe_summary", "gap_probe_summary"}
    ]
    attempt_records = [
        record
        for record in records
        if _event_name(record)
        in {"attempt", "probe_attempt", "syscall_attempt", "gap_probe_attempt"}
    ]
    problems: list[str] = []
    if len(starts) != 1:
        problems.append(f"probe_start_count_{len(starts)}")
    if len(summaries) != 1:
        problems.append(f"probe_summary_count_{len(summaries)}")
    if not attempt_records:
        problems.append("no_probe_attempt_records")

    start_boot: int | None = None
    start_real: int | None = None
    first_eperm_boot: int | None = None
    first_eperm_real: int | None = None
    last_success_boot: int | None = None
    last_success_real: int | None = None
    attempts = successful = eperm_count = errors = 0
    successes_before = 0
    success_before_boot_times: list[int] = []
    attempt_boot_times: list[int] = []
    attempt_real_times: list[int | None] = []
    attempt_before_boot_times: list[int] = []
    attempt_after_boot_times: list[int] = []
    attempt_before_real_times: list[int | None] = []
    attempt_after_real_times: list[int | None] = []
    denial_seen = False
    summary_seen = len(summaries) == 1
    summary: Mapping[str, Any] | None = summaries[0] if summaries else None

    if starts:
        start = starts[0]
        start_boot = _explicit_boottime_ns(start)
        start_real = _first_timestamp(
            start,
            ("realtime_ns", "ts_realtime_ns", "timestamp_realtime_ns"),
        )
        syscall_nr = _int_or_none(start.get("syscall_nr"))
        syscall_name = _string_or_none(start.get("syscall_name"))
        if syscall_nr != TARGET_SYSCALL_NR:
            problems.append(
                f"unexpected_probe_syscall_{syscall_nr if syscall_nr is not None else 'missing'}"
            )
        if syscall_name != TARGET_SYSCALL_NAME:
            problems.append(
                "unexpected_probe_syscall_name_"
                f"{syscall_name if syscall_name is not None else 'missing'}"
            )
        if start_boot is None:
            problems.append("probe_start_boottime_ns_missing")

    previous_attempt_boot: int | None = None
    success_after_denial = 0
    for expected_seq, record in enumerate(attempt_records):
        attempts += 1
        seq = _int_or_none(record.get("seq"))
        if seq != expected_seq:
            problems.append(
                f"probe_attempt_seq_expected_{expected_seq}_observed_"
                f"{seq if seq is not None else 'missing'}"
            )
        # Standalone parser callers may still supply the historical point
        # timestamp. Protocol-v3 trials are checked below for the explicit
        # before/after fields before they are eligible for statistics.
        legacy_boot = _explicit_boottime_ns(record)
        legacy_real = _first_timestamp(
            record,
            ("realtime_ns", "ts_realtime_ns", "timestamp_realtime_ns"),
        )
        attempt_before_boot = _first_timestamp(
            record, ("before_boottime_ns",)
        ) or legacy_boot
        attempt_after_boot = _first_timestamp(
            record, ("after_boottime_ns",)
        ) or legacy_boot
        attempt_before_real = _first_timestamp(
            record, ("before_realtime_ns",)
        ) or legacy_real
        attempt_after_real = _first_timestamp(
            record, ("after_realtime_ns",)
        ) or legacy_real
        attempt_boot = attempt_before_boot
        attempt_real = attempt_before_real
        if attempt_before_boot is None:
            problems.append(
                f"probe_attempt_{expected_seq}_before_boottime_ns_missing"
            )
        if attempt_after_boot is None:
            problems.append(
                f"probe_attempt_{expected_seq}_after_boottime_ns_missing"
            )
        if (
            attempt_before_boot is not None
            and attempt_after_boot is not None
            and attempt_after_boot < attempt_before_boot
        ):
            problems.append(f"probe_attempt_{expected_seq}_interval_reversed")
        if attempt_boot is None:
            pass
        else:
            attempt_boot_times.append(attempt_boot)
            attempt_before_boot_times.append(attempt_boot)
            if start_boot is not None and attempt_boot < start_boot:
                problems.append(f"probe_attempt_{expected_seq}_precedes_probe_start")
            if previous_attempt_boot is not None and attempt_boot < previous_attempt_boot:
                problems.append(f"probe_attempt_{expected_seq}_boottime_not_monotonic")
            previous_attempt_boot = attempt_boot
        if attempt_after_boot is not None:
            attempt_after_boot_times.append(attempt_after_boot)
        attempt_real_times.append(attempt_real)
        attempt_before_real_times.append(attempt_before_real)
        attempt_after_real_times.append(attempt_after_real)

        outcome = _attempt_outcome(record)
        if outcome == "success":
            successful += 1
            if not denial_seen:
                successes_before += 1
                if attempt_boot is not None:
                    success_before_boot_times.append(attempt_boot)
                last_success_boot = attempt_boot
                last_success_real = attempt_real
            else:
                success_after_denial += 1
        elif outcome == "eperm":
            eperm_count += 1
            errno_value = _int_or_none(record.get("errno"))
            if errno_value not in {errno_module.EPERM, -errno_module.EPERM}:
                problems.append(f"probe_attempt_{expected_seq}_denial_is_not_eperm")
            if not denial_seen:
                denial_seen = True
                first_eperm_boot = attempt_boot
                first_eperm_real = attempt_real
        else:
            errors += 1
    if success_after_denial:
        problems.append(f"success_after_first_denial_count_{success_after_denial}")
    if errors:
        problems.append(f"probe_unexpected_error_count_{errors}")

    # Summary records provide a useful fallback when an older probe emitted no
    # per-attempt records.  Raw attempts remain authoritative when present.
    if attempts == 0 and summary is not None:
        attempts = _int_or_none(summary.get("attempts")) or 0
        successful = (
            _int_or_none(summary.get("successful"))
            or _int_or_none(summary.get("successes"))
            or _int_or_none(summary.get("allowed"))
            or 0
        )
        eperm_count = _int_or_none(summary.get("eperm")) or _int_or_none(summary.get("denied")) or 0
        errors = _int_or_none(summary.get("errors")) or 0
        fallback_missed = None
        for key in ("missed_policy_calls", "successful_before_first_eperm", "allowed_before_eperm"):
            fallback_missed = _int_or_none(summary.get(key))
            if fallback_missed is not None:
                break
        if successful > 0 and eperm_count > 0 and fallback_missed is None:
            problems.append("summary_only_mixed_outcomes_without_ordered_miss_count")
        if fallback_missed is not None:
            if fallback_missed < 0 or fallback_missed > successful:
                problems.append("summary_ordered_miss_count_out_of_range")
            successes_before = fallback_missed
        elif eperm_count == 0:
            successes_before = successful
        denial_seen = eperm_count > 0
        first_eperm_boot = _first_timestamp(
            summary, ("first_eperm_boottime_ns", "first_denial_boottime_ns")
        )
        first_eperm_real = _first_timestamp(
            summary, ("first_eperm_realtime_ns", "first_denial_realtime_ns")
        )

    summary_cgroup_id: int | None = None
    summary_cgroup_id_errno: int | None = None
    if summary is not None:
        summary_cgroup_id = _int_or_none(summary.get("cgroup_id"))
        summary_cgroup_id_errno = _int_or_none(summary.get("cgroup_id_errno"))
        if attempt_records:
            expected_summary = {
                "attempts": attempts,
                "successes": successful,
                "denied": eperm_count,
                "errors": errors,
            }
            for field, expected in expected_summary.items():
                observed = _int_or_none(summary.get(field))
                if observed != expected:
                    problems.append(
                        f"probe_summary_{field}_expected_{expected}_observed_"
                        f"{observed if observed is not None else 'missing'}"
                    )
        summary_boot = _explicit_boottime_ns(summary)
        if summary_boot is None:
            problems.append("probe_summary_boottime_ns_missing")
        elif previous_attempt_boot is not None and summary_boot < previous_attempt_boot:
            problems.append("probe_summary_precedes_last_attempt")

    if eperm_count > 0 and first_eperm_boot is None:
        problems.append("first_eperm_boottime_ns_missing")
    if problems:
        raise AnalysisError("probe validation failed: " + "; ".join(problems))

    return ProbeFacts(
        start_boottime_ns=start_boot,
        start_realtime_ns=start_real,
        first_eperm_boottime_ns=first_eperm_boot,
        first_eperm_realtime_ns=first_eperm_real,
        attempts=attempts,
        successful=successful,
        eperm=eperm_count,
        errors=errors,
        attempt_boottime_ns=tuple(attempt_boot_times),
        attempt_realtime_ns=tuple(attempt_real_times),
        attempt_before_boottime_ns=tuple(attempt_before_boot_times),
        attempt_after_boottime_ns=tuple(attempt_after_boot_times),
        attempt_before_realtime_ns=tuple(attempt_before_real_times),
        attempt_after_realtime_ns=tuple(attempt_after_real_times),
        successful_before_first_eperm=successes_before,
        successful_before_first_eperm_boottime_ns=tuple(success_before_boot_times),
        last_success_before_first_eperm_boottime_ns=last_success_boot,
        last_success_before_first_eperm_realtime_ns=last_success_real,
        summary_cgroup_id=summary_cgroup_id,
        summary_cgroup_id_errno=summary_cgroup_id_errno,
        # Observation-only trials use readiness markers rather than denial as
        # an endpoint.  ``censored`` is retained in the schema for backward
        # compatibility and is always false for this protocol.
        censored=False,
        summary_seen=summary_seen,
    )


def parse_mapwatch_events(records: Iterable[Mapping[str, Any]]) -> MapInsertFacts | None:
    candidates: list[MapInsertFacts] = []
    for record in records:
        if _event_name(record) not in {"map_insert", "insert", "policy_map_insert"}:
            continue
        lower_boot = _first_timestamp(
            record,
            (
                "last_absent_boottime_ns",
                "lower_boottime_ns",
                "interval_start_boottime_ns",
                "before_boottime_ns",
            ),
        )
        upper_boot = _first_timestamp(
            record,
            (
                "first_present_boottime_ns",
                "upper_boottime_ns",
                "interval_end_boottime_ns",
                "observed_boottime_ns",
                "after_boottime_ns",
                "boottime_ns",
            ),
        )
        lower_real = _first_timestamp(
            record,
            (
                "last_absent_realtime_ns",
                "lower_realtime_ns",
                "interval_start_realtime_ns",
                "before_realtime_ns",
            ),
        )
        upper_real = _first_timestamp(
            record,
            (
                "first_present_realtime_ns",
                "upper_realtime_ns",
                "interval_end_realtime_ns",
                "observed_realtime_ns",
                "after_realtime_ns",
                "realtime_ns",
            ),
        )

        # Accept a point observation as a zero-width interval.
        if upper_boot is None:
            generic_boot, generic_real = _event_times(record)
            upper_boot = generic_boot
            if upper_real is None:
                upper_real = generic_real
        if lower_boot is None:
            lower_boot = upper_boot
        if lower_real is None:
            lower_real = upper_real
        if lower_boot is None or upper_boot is None:
            continue
        if upper_boot < lower_boot:
            raise AnalysisError(
                "map_insert has first_present_boottime_ns before last_absent_boottime_ns"
            )
        candidates.append(
            MapInsertFacts(
                lower_boottime_ns=lower_boot,
                upper_boottime_ns=upper_boot,
                lower_realtime_ns=lower_real,
                upper_realtime_ns=upper_real,
                policy_id=_string_or_none(record.get("policy_id")),
                cgroup_id=_string_or_none(record.get("cgroup_id")),
            )
        )
    if not candidates:
        return None
    return min(candidates, key=lambda item: item.upper_boottime_ns)


def validate_tetragon_mapwatch_events(
    records: Iterable[Mapping[str, Any]],
    trial: Mapping[str, Any],
    probe: ProbeFacts,
) -> tuple[MapInsertFacts | None, list[str]]:
    """Validate one exact policy-filter insertion for the trial cgroup."""

    records = list(records)
    inserts = [
        record
        for record in records
        if _event_name(record) in {"map_insert", "insert", "policy_map_insert"}
    ]
    problems: list[str] = []
    if len(inserts) != 1:
        return None, [f"tetragon_map_insert_count_{len(inserts)}"]

    record = inserts[0]
    lower_boot = _first_timestamp(record, ("last_absent_boottime_ns",))
    upper_boot = _first_timestamp(record, ("first_present_boottime_ns",))
    if lower_boot is None:
        problems.append("tetragon_map_last_absent_boottime_ns_missing")
    if upper_boot is None:
        problems.append("tetragon_map_first_present_boottime_ns_missing")
    if lower_boot is not None and upper_boot is not None and upper_boot < lower_boot:
        problems.append("tetragon_map_insert_interval_reversed")

    expected_policy_id = _int_or_none(trial.get("tetragon_filter_id"))
    observed_policy_id = _int_or_none(record.get("policy_id"))
    if expected_policy_id is None:
        problems.append("trial_tetragon_filter_id_missing")
    elif observed_policy_id != expected_policy_id:
        problems.append(
            f"tetragon_policy_id_mismatch_trial_{expected_policy_id}_map_"
            f"{observed_policy_id if observed_policy_id is not None else 'missing'}"
        )

    trial_probe_cgroup_id = _int_or_none(trial.get("probe_cgroup_id"))
    trial_map_cgroup_id = _int_or_none(trial.get("tetragon_map_cgroup_id"))
    observed_cgroup_id = _int_or_none(record.get("cgroup_id"))
    summary_cgroup_id = probe.summary_cgroup_id
    if probe.summary_cgroup_id_errno != 0 or summary_cgroup_id is None or summary_cgroup_id <= 0:
        problems.append(
            "probe_summary_cgroup_id_unavailable_errno_"
            f"{probe.summary_cgroup_id_errno if probe.summary_cgroup_id_errno is not None else 'missing'}"
        )
    if trial_probe_cgroup_id is None or trial_probe_cgroup_id <= 0:
        problems.append("trial_probe_cgroup_id_missing")
    if trial_map_cgroup_id is None or trial_map_cgroup_id <= 0:
        problems.append("trial_tetragon_map_cgroup_id_missing")
    if observed_cgroup_id is None or observed_cgroup_id <= 0:
        problems.append("map_insert_cgroup_id_missing")

    comparable_cgroups = [
        value
        for value in (
            summary_cgroup_id,
            trial_probe_cgroup_id,
            trial_map_cgroup_id,
            observed_cgroup_id,
        )
        if value is not None and value > 0
    ]
    if len(comparable_cgroups) == 4 and len(set(comparable_cgroups)) != 1:
        problems.append(
            "tetragon_cgroup_id_mismatch_summary_"
            f"{summary_cgroup_id}_trial_probe_{trial_probe_cgroup_id}_"
            f"trial_map_{trial_map_cgroup_id}_map_{observed_cgroup_id}"
        )

    if lower_boot is None or upper_boot is None:
        return None, problems
    insertion = MapInsertFacts(
        lower_boottime_ns=lower_boot,
        upper_boottime_ns=upper_boot,
        lower_realtime_ns=_first_timestamp(record, ("last_absent_realtime_ns",)),
        upper_realtime_ns=_first_timestamp(record, ("first_present_realtime_ns",)),
        policy_id=_string_or_none(record.get("policy_id")),
        cgroup_id=_string_or_none(record.get("cgroup_id")),
    )
    return insertion, problems


def _normalize_container_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    prefixes = ("containerd://", "docker://", "cri-o://", "crio://", "sha256:")
    changed = True
    while changed:
        changed = False
        for prefix in prefixes:
            if text.startswith(prefix):
                text = text[len(prefix) :]
                changed = True
                break
    return text or None


def _container_matches(event_id: Any, wanted_id: str | None) -> bool:
    event = _normalize_container_id(event_id)
    wanted = _normalize_container_id(wanted_id)
    return event is not None and wanted is not None and event == wanted


def _hook_event_container_id(record: Mapping[str, Any]) -> Any:
    return (
        record.get("container_id")
        or record.get("containerID")
        or record.get("target_container_id")
    )


def parse_hook_timeline(
    records: Iterable[Mapping[str, Any]], container_id: str | None = None
) -> HookTimelineFacts:
    candidates: dict[str, list[HookReadyFacts]] = {
        "sygma_direct_policy_ready": [],
        "oci_prestart_enter": [],
        "oci_prestart_complete": [],
    }
    for record in records:
        name = _event_name(record)
        if name not in candidates:
            continue
        event_container = _hook_event_container_id(record)
        if not _container_matches(event_container, container_id):
            continue
        boot, real = _event_times(record)
        if boot is None and real is None:
            continue
        candidates[name].append(
            HookReadyFacts(
                boottime_ns=boot,
                realtime_ns=real,
                mnt_ns=_int_or_none(record.get("mnt_ns")),
                pid_ns=_int_or_none(record.get("pid_ns")),
                host_tgid=_int_or_none(record.get("host_pid")),
            )
        )

    def earliest(name: str) -> HookReadyFacts | None:
        values = candidates[name]
        if not values:
            return None
        return min(
            values,
            key=lambda item: (
                item.boottime_ns if item.boottime_ns is not None else item.realtime_ns or 0
            ),
        )

    ready = earliest("sygma_direct_policy_ready")
    enter = earliest("oci_prestart_enter")
    complete = earliest("oci_prestart_complete")
    return HookTimelineFacts(
        ready=ready,
        prestart_enter_boottime_ns=enter.boottime_ns if enter else None,
        prestart_enter_realtime_ns=enter.realtime_ns if enter else None,
        prestart_complete_boottime_ns=complete.boottime_ns if complete else None,
        prestart_complete_realtime_ns=complete.realtime_ns if complete else None,
    )


def parse_hook_events(
    records: Iterable[Mapping[str, Any]], container_id: str | None = None
) -> HookReadyFacts | None:
    """Compatibility wrapper returning only the direct-policy-ready marker."""

    return parse_hook_timeline(records, container_id).ready


def validate_sygma_hook_events(
    records: Iterable[Mapping[str, Any]], container_id: str | None
) -> list[str]:
    """Validate the complete hook/barrier timeline for one exact container."""

    records = list(records)
    problems: list[str] = []
    normalized_container = _normalize_container_id(container_id)
    if normalized_container is None:
        return ["sygma_hook_container_id_missing"]

    event_times: dict[str, int] = {}
    for name in SYGMA_REQUIRED_HOOK_EVENTS:
        matches = [
            record
            for record in records
            if _event_name(record) == name
            and _container_matches(_hook_event_container_id(record), normalized_container)
        ]
        if len(matches) != 1:
            problems.append(f"{name}_count_{len(matches)}")
            continue
        boottime_ns = _explicit_boottime_ns(matches[0])
        if boottime_ns is None:
            problems.append(f"{name}_boottime_ns_missing")
            continue
        event_times[name] = boottime_ns

    prestart_names = SYGMA_REQUIRED_HOOK_EVENTS[:-1]
    if all(name in event_times for name in prestart_names):
        ordered = [event_times[name] for name in prestart_names]
        if ordered != sorted(ordered):
            problems.append("sygma_prestart_event_order_invalid")
    if (
        "oci_prestart_complete" in event_times
        and "sygma_cleanup_complete" in event_times
        and event_times["sygma_cleanup_complete"]
        < event_times["oci_prestart_complete"]
    ):
        problems.append("sygma_cleanup_precedes_prestart_complete")
    return problems


def validate_common_prestart_events(
    records: Iterable[Mapping[str, Any]], trial: Mapping[str, Any]
) -> list[str]:
    """Validate the common lifecycle origin and exact trial identity."""

    records = list(records)
    problems: list[str] = []
    backend = str(trial.get("backend") or "").lower()
    container_id = _normalize_container_id(trial.get("container_id"))
    expected_mode = "enforcement" if backend == "sygma" else "tetragon-measurement"
    expected_role = "policy-and-release" if backend == "sygma" else "timestamp-only"
    expected = {
        "backend": backend,
        "trial_id": str(trial.get("trial_id") or ""),
        "application": str(trial.get("application") or "synthetic"),
        "pod_uid": str(trial.get("pod_uid") or ""),
        "pod_name": str(trial.get("pod_name") or ""),
        "container_name": "probe",
    }

    boundary_times: dict[str, int] = {}
    for event_name in ("oci_prestart_enter", "oci_prestart_complete"):
        matches = [
            record
            for record in records
            if _event_name(record) == event_name
            and _container_matches(_hook_event_container_id(record), container_id)
        ]
        if len(matches) != 1:
            problems.append(f"{event_name}_count_{len(matches)}")
            continue
        event = matches[0]
        if _int_or_none(event.get("schema_version")) != HOOK_TIMELINE_SCHEMA_VERSION:
            problems.append(f"{event_name}_schema_mismatch")
        if event.get("component") != "sygma-oci-hook":
            problems.append(f"{event_name}_component_mismatch")
        if event.get("mode") != expected_mode:
            problems.append(f"{event_name}_mode_mismatch")
        if event.get("hook_role") != expected_role:
            problems.append(f"{event_name}_role_mismatch")
        for field, value in expected.items():
            if field in {"pod_uid", "pod_name"} and not value:
                problems.append(f"trial_{field}_missing")
            elif str(event.get(field) or "") != value:
                problems.append(f"{event_name}_{field}_mismatch")
        boottime_ns = _explicit_boottime_ns(event)
        if boottime_ns is None or boottime_ns <= 0:
            problems.append(f"{event_name}_boottime_ns_missing")
        else:
            boundary_times[event_name] = boottime_ns

    if all(
        name in boundary_times
        for name in ("oci_prestart_enter", "oci_prestart_complete")
    ) and boundary_times["oci_prestart_complete"] < boundary_times["oci_prestart_enter"]:
        problems.append("prestart_boundary_order_invalid")

    if backend == "tetragon":
        forbidden = {
            "sygma_direct_policy_ready",
            "target_release_begin",
            "target_release_signal_sent",
            "sygma_cleanup_complete",
        }
        count = sum(_event_name(record) in forbidden for record in records)
        if count:
            problems.append(f"tetragon_timing_hook_policy_event_count_{count}")
    return problems


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _relative_raw_path(run_dir: Path, trial: Mapping[str, Any], key: str) -> str | None:
    raw = trial.get("raw")
    value = raw.get(key) if isinstance(raw, Mapping) else None
    # Compatibility with early runner fixtures, while canonical records keep
    # all three paths under ``raw``.
    if value is None:
        value = trial.get(key)
    return _string_or_none(value)


def _resolve_raw_path(run_dir: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (run_dir / candidate).resolve()
    base = run_dir.resolve()
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise AnalysisError(f"raw path escapes run directory: {relative!r}") from exc
    return resolved


def _blank_trial_row(trial: Mapping[str, Any], run_dir: Path) -> dict[str, Any]:
    row: dict[str, Any] = {column: None for column in TRIAL_COLUMNS}
    backend = str(trial.get("backend", "")).strip().lower()
    raw_valid = trial.get("valid")
    valid = raw_valid if isinstance(raw_valid, bool) else False
    invalid_reasons: list[str] = []
    existing_reason = _string_or_none(trial.get("invalid_reason"))
    if existing_reason:
        invalid_reasons.append(existing_reason)
    if not isinstance(raw_valid, bool):
        invalid_reasons.append("trial.valid is missing or is not boolean")
    trial_schema = _int_or_none(trial.get("schema_version"))
    if valid and trial_schema != SCHEMA_VERSION:
        valid = False
        invalid_reasons.append(
            f"trial schema_version {trial_schema} is not observation protocol "
            f"version {SCHEMA_VERSION}"
        )
    if backend not in {"sygma", "tetragon"}:
        valid = False
        invalid_reasons.append(f"unknown backend: {backend or '<missing>'}")
    row.update(
        {
            "trial_id": str(trial.get("trial_id", "")),
            "backend": backend,
            "application": str(trial.get("application") or "synthetic"),
            "warmup": _bool(trial.get("warmup")),
            "valid": valid,
            "invalid_reason": "; ".join(invalid_reasons) or None,
            "warnings": "",
            "container_id": _string_or_none(trial.get("container_id")),
            "pod_creation_time": trial.get("pod_creation_time"),
            "container_started_time": trial.get("container_started_time"),
        }
    )
    for key in (
        "api_submit_realtime_ns",
        "api_submit_boottime_ns",
        "api_ack_realtime_ns",
        "api_ack_boottime_ns",
    ):
        row[key] = _int_or_none(trial.get(key))
    for key in (
        "probe_jsonl",
        "mapwatch_jsonl",
        "hook_timeline_jsonl",
        "sygma_policy_evidence_jsonl",
        "tetragon_events_jsonl",
    ):
        row[key] = _relative_raw_path(run_dir, trial, key)
    return row


def _append_invalid_reason(row: dict[str, Any], reason: str) -> None:
    old = _string_or_none(row.get("invalid_reason"))
    row["invalid_reason"] = f"{old}; {reason}" if old else reason
    row["valid"] = False


def _set_duration(row: dict[str, Any], stem: str, value_ns: int | None) -> None:
    row[f"{stem}_ns"] = value_ns
    row[f"{stem}_ms"] = value_ns / 1_000_000 if value_ns is not None else None


def analyze_trial(trial: Mapping[str, Any], run_dir: Path | str) -> dict[str, Any]:
    run_path = Path(run_dir)
    row = _blank_trial_row(trial, run_path)
    warnings: list[str] = []

    # Preserve runner-invalid trials without requiring raw artifacts that may
    # intentionally not exist.
    if not row["valid"]:
        row["warnings"] = ""
        return row

    try:
        creation_ns = timestamp_to_ns(trial.get("pod_creation_time"), "pod_creation_time")
        started_ns = timestamp_to_ns(trial.get("container_started_time"), "container_started_time")
        row["pod_creation_realtime_ns"] = creation_ns
        row["container_started_realtime_ns"] = started_ns
        startup_ns = started_ns - creation_ns
        if startup_ns < 0:
            raise AnalysisError("container_started_time precedes pod_creation_time")
        _set_duration(row, "startup_latency", startup_ns)
    except (ValueError, AnalysisError) as exc:
        _append_invalid_reason(row, f"invalid pod timestamps: {exc}")

    probe_relative = row.get("probe_jsonl")
    if not probe_relative:
        _append_invalid_reason(row, "raw.probe_jsonl is missing")
        row["warnings"] = "; ".join(warnings)
        return row

    try:
        probe_records = read_jsonl(
            _resolve_raw_path(run_path, str(probe_relative))
        )
        probe = parse_probe_events(probe_records)
    except AnalysisError as exc:
        _append_invalid_reason(row, str(exc))
        row["warnings"] = "; ".join(warnings)
        return row

    row.update(
        {
            "probe_start_realtime_ns": probe.start_realtime_ns,
            "probe_start_boottime_ns": probe.start_boottime_ns,
            "first_eperm_realtime_ns": probe.first_eperm_realtime_ns,
            "first_eperm_boottime_ns": probe.first_eperm_boottime_ns,
            "censored": False,
            "probe_attempts": probe.attempts,
            "probe_successful": probe.successful,
            "probe_eperm": probe.eperm,
            "probe_errors": probe.errors,
            "probe_summary_seen": probe.summary_seen,
        }
    )
    if probe.start_boottime_ns is None:
        _append_invalid_reason(row, "probe_start CLOCK_BOOTTIME timestamp is missing")
    protocol_attempt_records = [
        record
        for record in probe_records
        if _event_name(record)
        in {"attempt", "probe_attempt", "syscall_attempt", "gap_probe_attempt"}
    ]
    for index, record in enumerate(protocol_attempt_records):
        if _int_or_none(record.get("schema_version")) != 2:
            _append_invalid_reason(row, f"probe_attempt_{index}_schema_mismatch")
        for field in (
            "before_boottime_ns",
            "after_boottime_ns",
            "before_realtime_ns",
            "after_realtime_ns",
        ):
            if _int_or_none(record.get(field)) is None:
                _append_invalid_reason(
                    row, f"probe_attempt_{index}_{field}_missing"
                )
    if probe.successful != probe.attempts or probe.eperm or probe.errors:
        _append_invalid_reason(
            row,
            "observation_mode_requires_all_success_"
            f"attempts_{probe.attempts}_successes_{probe.successful}_"
            f"eperm_{probe.eperm}_errors_{probe.errors}",
        )

    application = str(row.get("application") or "synthetic")
    if application != "synthetic":
        app_spawns = [
            record for record in probe_records if _event_name(record) == "app_spawn"
        ]
        app_exits = [
            record for record in probe_records if _event_name(record) == "app_exit"
        ]
        app_summaries = [
            record
            for record in probe_records
            if _event_name(record) in {"probe_summary", "summary"}
        ]
        if len(app_spawns) != 1:
            _append_invalid_reason(row, f"app_spawn_count_{len(app_spawns)}")
        if len(app_exits) != 1:
            _append_invalid_reason(row, f"app_exit_count_{len(app_exits)}")
        if len(app_summaries) != 1:
            _append_invalid_reason(row, f"app_summary_count_{len(app_summaries)}")
        if len(app_spawns) == 1:
            spawn = app_spawns[0]
            row["application_spawn_realtime_ns"] = _int_or_none(
                spawn.get("realtime_ns")
            )
            row["application_spawn_boottime_ns"] = _int_or_none(
                spawn.get("boottime_ns")
            )
            row["application_pid"] = _int_or_none(spawn.get("pid"))
            if str(spawn.get("application") or "") != application:
                _append_invalid_reason(row, "app_spawn_application_mismatch")
        if len(app_summaries) == 1:
            app_summary = app_summaries[0]
            row["application_alive_at_summary"] = app_summary.get(
                "app_alive_at_summary"
            )
            if str(app_summary.get("application") or "") != application:
                _append_invalid_reason(row, "app_summary_application_mismatch")
            if app_summary.get("app_alive_at_summary") is not True:
                _append_invalid_reason(row, "application_not_alive_at_probe_summary")
            if app_summary.get("measurement_interrupted") is not False:
                _append_invalid_reason(row, "application_measurement_interrupted")
            if (
                row.get("application_pid") is None
                or _int_or_none(app_summary.get("app_pid"))
                != row.get("application_pid")
            ):
                _append_invalid_reason(row, "application_pid_mismatch")
        if len(app_exits) == 1:
            app_exit = app_exits[0]
            row["application_exit_realtime_ns"] = _int_or_none(
                app_exit.get("realtime_ns")
            )
            row["application_exit_boottime_ns"] = _int_or_none(
                app_exit.get("boottime_ns")
            )
            row["application_exit_phase"] = _string_or_none(app_exit.get("phase"))
            row["application_exit_code"] = _int_or_none(app_exit.get("exit_code"))
            row["application_exit_signal"] = _int_or_none(
                app_exit.get("term_signal")
            )
            if str(app_exit.get("application") or "") != application:
                _append_invalid_reason(row, "app_exit_application_mismatch")
            if app_exit.get("phase") != "cleanup":
                _append_invalid_reason(
                    row,
                    f"application_exit_phase_{app_exit.get('phase', 'missing')}",
                )

    map_insert: MapInsertFacts | None = None
    hook_ready: HookReadyFacts | None = None
    hook_timeline: HookTimelineFacts | None = None
    hook_records: list[Mapping[str, Any]] = []
    map_relative = row.get("mapwatch_jsonl")
    hook_relative = row.get("hook_timeline_jsonl")
    backend = str(row.get("backend") or "").lower()
    if backend == "tetragon":
        if not map_relative:
            _append_invalid_reason(row, "raw.mapwatch_jsonl is missing")
        else:
            try:
                map_records = read_jsonl(
                    _resolve_raw_path(run_path, str(map_relative))
                )
                map_insert, map_problems = validate_tetragon_mapwatch_events(
                    map_records, trial, probe
                )
                for problem in map_problems:
                    _append_invalid_reason(row, problem)
            except AnalysisError as exc:
                _append_invalid_reason(row, str(exc))
    elif backend != "sygma":
        _append_invalid_reason(row, f"unsupported_backend_{backend}")

    if backend in {"sygma", "tetragon"}:
        if not hook_relative:
            _append_invalid_reason(row, "raw.hook_timeline_jsonl is missing")
        else:
            try:
                hook_records = read_jsonl(
                    _resolve_raw_path(run_path, str(hook_relative))
                )
                container_id = _string_or_none(row.get("container_id"))
                for problem in validate_common_prestart_events(hook_records, trial):
                    _append_invalid_reason(row, problem)
                if backend == "sygma":
                    for problem in validate_sygma_hook_events(
                        hook_records, container_id
                    ):
                        _append_invalid_reason(row, problem)
                hook_timeline = parse_hook_timeline(
                    hook_records,
                    container_id=container_id,
                )
                if backend == "sygma":
                    hook_ready = hook_timeline.ready
            except AnalysisError as exc:
                _append_invalid_reason(row, str(exc))

    if backend == "sygma":
        evidence_relative = row.get("sygma_policy_evidence_jsonl")
        if evidence_relative:
            try:
                evidence_records = read_jsonl(
                    _resolve_raw_path(run_path, str(evidence_relative))
                )
                evidence = [
                    record for record in evidence_records
                    if _event_name(record) == "sygma_policy_evidence"
                ]
                target_misses = [
                    record for record in evidence_records
                    if _event_name(record) in {
                        "sygma_policy_observed_calls",
                        "sygma_target_policy_misses",
                    }
                ]
                if len(evidence) == 1:
                    positive = evidence[0].get("policy_evaluated") is True
                    first_evaluation = _int_or_none(
                        evidence[0].get("first_policy_evaluation_boottime_ns")
                    )
                    row["sygma_policy_evaluation_positive"] = positive
                    row["sygma_first_policy_evaluation_boottime_ns"] = first_evaluation
                elif evidence:
                    warnings.append(
                        f"sygma_policy_evidence_count_{len(evidence)}"
                    )
                if len(target_misses) == 1:
                    miss_count = _int_or_none(target_misses[0].get("count"))
                    other_phase_count = _int_or_none(
                        target_misses[0].get("other_phase_count")
                    )
                    phase0_count = _int_or_none(
                        target_misses[0].get("phase0_count")
                    )
                    target_nr = _int_or_none(target_misses[0].get("syscall_nr"))
                    target_phase = _int_or_none(target_misses[0].get("phase"))
                    evidence_mnt_ns = _int_or_none(target_misses[0].get("mnt_ns"))
                    evidence_pid_ns = _int_or_none(target_misses[0].get("pid_ns"))
                    evidence_tgid = _int_or_none(target_misses[0].get("tgid"))
                    identity_matches = (
                        hook_ready is not None
                        and hook_ready.mnt_ns is not None
                        and hook_ready.pid_ns is not None
                        and hook_ready.host_tgid is not None
                        and evidence_mnt_ns == hook_ready.mnt_ns
                        and evidence_pid_ns == hook_ready.pid_ns
                        and evidence_tgid == hook_ready.host_tgid
                    )
                    row["sygma_target_policy_miss_count"] = miss_count
                    if miss_count is not None:
                        controlled_observed = min(miss_count, probe.attempts)
                        row["sygma_policy_observed_attempts"] = controlled_observed
                        row["sygma_non_probe_target_calls_observed"] = max(
                            0, miss_count - probe.attempts
                        )
                        row["sygma_controlled_attempts_unobserved"] = (
                            probe.attempts - controlled_observed
                        )
                        row["sygma_observation_coverage"] = (
                            controlled_observed / probe.attempts
                            if probe.attempts else None
                        )
                    row["sygma_target_policy_other_phase_count"] = other_phase_count
                    row["sygma_target_policy_phase0_count"] = phase0_count
                    row["sygma_target_policy_tgid"] = evidence_tgid
                    row["sygma_target_policy_identity_matches_hook"] = identity_matches
                    row["sygma_target_policy_evidence_positive"] = (
                        miss_count is not None
                        and miss_count >= probe.attempts
                        and other_phase_count == 0
                        and phase0_count == 0
                        and target_nr == TARGET_SYSCALL_NR
                        and target_phase == 1
                        and identity_matches
                    )
                else:
                    row["sygma_target_policy_evidence_positive"] = False
            except AnalysisError as exc:
                warnings.append(f"optional SYGMA policy evidence unavailable: {exc}")
        if not row.get("sygma_target_policy_evidence_positive"):
            _append_invalid_reason(
                row, "SYGMA policy-path observation coverage was incomplete"
            )
        if not row.get("sygma_policy_evaluation_positive"):
            warnings.append(
                "no auxiliary SYGMA first-policy-evaluation evidence; "
                "hook readiness remains authoritative"
            )
    elif backend == "tetragon":
        event_relative = row.get("tetragon_events_jsonl")
        positive_count = 0
        if event_relative:
            try:
                positive_count = len(
                    read_jsonl(_resolve_raw_path(run_path, str(event_relative)))
                )
            except AnalysisError as exc:
                warnings.append(f"optional Tetragon Post evidence unavailable: {exc}")
        row["tetragon_positive_event_count"] = positive_count
        row["tetragon_positive_event_observed"] = positive_count > 0
        if positive_count == 0:
            warnings.append(
                "no auxiliary Tetragon Post event; map insertion remains authoritative"
            )

    if map_insert is not None:
        row.update(
            {
                "policy_ready_lower_realtime_ns": map_insert.lower_realtime_ns,
                "policy_ready_upper_realtime_ns": map_insert.upper_realtime_ns,
                "map_interval_width_ns": map_insert.interval_width_ns,
                "map_interval_width_ms": map_insert.interval_width_ns / 1_000_000,
            }
        )
        # The insertion is known to occur in (L,U]. A controlled call is a
        # definite uncovered call only when it has returned by L. It is a
        # possible uncovered call when its immediately-preceding timestamp is
        # no later than U.
        row["successful_attempts_definitely_before_map_lower"] = sum(
            timestamp <= map_insert.lower_boottime_ns
            for timestamp in probe.attempt_after_boottime_ns
        )
        row["successful_attempts_ambiguous_in_map_interval"] = sum(
            after > map_insert.lower_boottime_ns
            and before <= map_insert.upper_boottime_ns
            for before, after in zip(
                probe.attempt_before_boottime_ns,
                probe.attempt_after_boottime_ns,
            )
        )
        if (
            len(probe.attempt_before_boottime_ns) != probe.attempts
            or len(probe.attempt_after_boottime_ns) != probe.attempts
        ):
            _append_invalid_reason(
                row,
                "probe attempt is missing syscall boundary CLOCK_BOOTTIME timestamp",
            )

    if hook_timeline is not None:
        row.update(
            {
                "oci_prestart_enter_realtime_ns": hook_timeline.prestart_enter_realtime_ns,
                "oci_prestart_enter_boottime_ns": hook_timeline.prestart_enter_boottime_ns,
                "oci_prestart_complete_realtime_ns": hook_timeline.prestart_complete_realtime_ns,
                "oci_prestart_complete_boottime_ns": hook_timeline.prestart_complete_boottime_ns,
                "prestart_trigger_realtime_ns": hook_timeline.prestart_enter_realtime_ns,
                "prestart_trigger_boottime_ns": hook_timeline.prestart_enter_boottime_ns,
            }
        )
        if (
            hook_timeline.prestart_enter_boottime_ns is not None
            and hook_timeline.prestart_complete_boottime_ns is not None
        ):
            hook_cost_ns = (
                hook_timeline.prestart_complete_boottime_ns
                - hook_timeline.prestart_enter_boottime_ns
            )
            if hook_cost_ns < 0:
                _append_invalid_reason(row, "oci_prestart_complete precedes oci_prestart_enter")
            else:
                _set_duration(row, "prestart_hook_duration", hook_cost_ns)
                if backend == "sygma":
                    # Deprecated compatibility alias.
                    _set_duration(row, "sygma_hook_cost", hook_cost_ns)

    ready_lower_boot: int | None = None
    ready_upper_boot: int | None = None
    ready_lower_real: int | None = None
    ready_upper_real: int | None = None
    if backend == "sygma" and hook_ready is not None:
        row["policy_ready_source"] = "sygma_direct_policy_ready"
        ready_lower_boot = ready_upper_boot = hook_ready.boottime_ns
        ready_lower_real = ready_upper_real = hook_ready.realtime_ns
    elif backend == "tetragon" and map_insert is not None:
        row["policy_ready_source"] = "tetragon_policy_filter_interval"
        ready_lower_boot = map_insert.lower_boottime_ns
        ready_upper_boot = map_insert.upper_boottime_ns
        ready_lower_real = map_insert.lower_realtime_ns
        ready_upper_real = map_insert.upper_realtime_ns
    else:
        _append_invalid_reason(row, f"{backend} policy readiness event was not observed")

    probe_start_boot = probe.start_boottime_ns

    row.update(
        {
            "policy_ready_lower_realtime_ns": ready_lower_real,
            "policy_ready_upper_realtime_ns": ready_upper_real,
            "policy_ready_lower_boottime_ns": ready_lower_boot,
            "policy_ready_upper_boottime_ns": ready_upper_boot,
        }
    )
    prestart_enter_boot = (
        hook_timeline.prestart_enter_boottime_ns
        if hook_timeline is not None
        else None
    )
    prestart_complete_boot = (
        hook_timeline.prestart_complete_boottime_ns
        if hook_timeline is not None
        else None
    )
    if prestart_enter_boot is not None and ready_lower_boot is not None:
        _set_duration(
            row,
            "policy_apply_from_prestart_lower",
            ready_lower_boot - prestart_enter_boot,
        )
    if prestart_enter_boot is not None and ready_upper_boot is not None:
        _set_duration(
            row,
            "policy_apply_from_prestart_upper",
            ready_upper_boot - prestart_enter_boot,
        )
    if (
        prestart_enter_boot is not None
        and ready_lower_boot is not None
        and ready_upper_boot is not None
    ):
        if ready_upper_boot <= prestart_enter_boot:
            row["policy_ready_at_prestart"] = "ready"
        elif ready_lower_boot >= prestart_enter_boot:
            row["policy_ready_at_prestart"] = "unavailable"
        else:
            row["policy_ready_at_prestart"] = "ambiguous"

    if ready_upper_boot is not None and probe_start_boot is not None:
        signed_ns = ready_upper_boot - probe_start_boot
        _set_duration(row, "signed_readiness_vs_probe_start", signed_ns)
        upper_gap_ns = max(0, signed_ns)
        _set_duration(row, "userland_exposure_upper", upper_gap_ns)
        _set_duration(row, "security_gap_upper", upper_gap_ns)
        # Backward-compatible point estimate: the conservative interval upper
        # bound for Tetragon and the exact marker for SYGMA.
        _set_duration(row, "security_gap", upper_gap_ns)
    if ready_lower_boot is not None and probe_start_boot is not None:
        lower_exposure_ns = max(0, ready_lower_boot - probe_start_boot)
        _set_duration(row, "userland_exposure_lower", lower_exposure_ns)
        _set_duration(
            row,
            "security_gap_lower",
            lower_exposure_ns,
        )

    uncovered_definite: int | None = None
    uncovered_possible: int | None = None
    if backend == "sygma" and ready_upper_boot is not None:
        # This zero follows from the publish-before-release ordering gate, not
        # from subtracting timestamps after application execution has begun.
        uncovered_definite = 0
        uncovered_possible = 0
    elif (
        backend == "tetragon"
        and ready_lower_boot is not None
        and ready_upper_boot is not None
    ):
        uncovered_definite = sum(
            timestamp <= ready_lower_boot
            for timestamp in probe.attempt_after_boottime_ns
        )
        uncovered_possible = sum(
            timestamp <= ready_upper_boot
            for timestamp in probe.attempt_before_boottime_ns
        )
    row.update(
        {
            "controlled_attempts_uncovered_definite": uncovered_definite,
            "controlled_attempts_uncovered_possible": uncovered_possible,
            # Deprecated compatibility aliases. These are not SYGMA's
            # internal observed_misses policy-decision counter.
            "missed_policy_calls_definite": uncovered_definite,
            "missed_policy_calls_possible": uncovered_possible,
            "missed_policy_calls": uncovered_possible,
        }
    )

    if prestart_complete_boot is not None and probe_start_boot is not None:
        if prestart_complete_boot > probe_start_boot:
            _append_invalid_reason(row, "prestart_complete_after_probe_start")
        if any(
            before < prestart_complete_boot
            for before in probe.attempt_before_boottime_ns
        ):
            _append_invalid_reason(row, "attempt_before_prestart_complete")

    first_eval_boot = _int_or_none(
        row.get("sygma_first_policy_evaluation_boottime_ns")
    )
    if backend == "sygma" and first_eval_boot is not None and ready_upper_boot is not None:
        ready_to_eval_ns = first_eval_boot - ready_upper_boot
        if ready_to_eval_ns < 0:
            _append_invalid_reason(
                row, "SYGMA first-policy-evaluation timestamp precedes hook ready"
            )
        else:
            _set_duration(row, "sygma_ready_to_first_evaluation", ready_to_eval_ns)

    if backend == "sygma":
        if hook_ready is not None and hook_ready.boottime_ns is None:
            _append_invalid_reason(row, "sygma_ready CLOCK_BOOTTIME timestamp is missing")
        if hook_ready is not None and hook_ready.boottime_ns is not None and probe_start_boot is not None:
            prestart_lead_ns = probe_start_boot - hook_ready.boottime_ns
            _set_duration(row, "sygma_prestart_lead", prestart_lead_ns)
            if prestart_lead_ns < 0:
                _append_invalid_reason(row, "sygma_ready_after_probe_start")
        event_boot: dict[str, int | None] = {}
        for event_name in (
            "target_release_begin",
            "target_release_signal_sent",
        ):
            matches = [
                record for record in hook_records
                if _event_name(record) == event_name
                and _container_matches(
                    _hook_event_container_id(record),
                    _string_or_none(row.get("container_id")),
                )
            ]
            event_boot[event_name] = (
                _explicit_boottime_ns(matches[0]) if len(matches) == 1 else None
            )
        atomicity_sequence = [
            prestart_enter_boot,
            hook_ready.boottime_ns if hook_ready is not None else None,
            event_boot.get("target_release_begin"),
            event_boot.get("target_release_signal_sent"),
            prestart_complete_boot,
            probe_start_boot,
        ]
        atomicity_valid = (
            all(value is not None for value in atomicity_sequence)
            and [int(value) for value in atomicity_sequence]
            == sorted(int(value) for value in atomicity_sequence)
            and all(
                before >= int(probe_start_boot)
                for before in probe.attempt_before_boottime_ns
            )
        )
        row["sygma_atomicity_order_valid"] = atomicity_valid
        if not atomicity_valid:
            _append_invalid_reason(row, "sygma_atomicity_invariant_violation")
        if (
            hook_ready is not None
            and hook_ready.boottime_ns is not None
            and prestart_complete_boot is not None
        ):
            margin_ns = prestart_complete_boot - hook_ready.boottime_ns
            if margin_ns < 0:
                _append_invalid_reason(row, "sygma_ready_after_prestart_complete")
            else:
                _set_duration(row, "sygma_ready_to_prestart_complete", margin_ns)
        if (
            prestart_complete_boot is not None
            and probe_start_boot is not None
            and prestart_complete_boot > probe_start_boot
        ):
            _append_invalid_reason(row, "oci_prestart_complete_after_probe_start")
        if hook_timeline is not None and row.get("sygma_hook_cost_ns") is None:
            _append_invalid_reason(row, "OCI prestart enter/complete boundary event is missing")

    row["warnings"] = "; ".join(warnings)
    return row


def percentile(values: Sequence[float | int], probability: float) -> float | None:
    """Type-7 linearly interpolated percentile (the common spreadsheet form)."""

    if not values:
        return None
    if not 0 <= probability <= 1:
        raise ValueError("probability must be in [0, 1]")
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def bootstrap_median_ci95(
    values: Sequence[float | int], *, resamples: int = BOOTSTRAP_RESAMPLES
) -> tuple[float | None, float | None]:
    """Return a deterministic percentile-bootstrap 95% CI for the median.

    The pseudo-random seed is derived from the sorted observations, so reruns
    over identical raw data are byte-for-byte reproducible and do not depend
    on process-global random state.
    """

    sample = sorted(float(value) for value in values)
    if not sample:
        return None, None
    if resamples < 1:
        raise ValueError("resamples must be positive")
    if len(sample) == 1 or sample[0] == sample[-1]:
        value = float(statistics.median(sample))
        return value, value

    seed_material = "startup-gap-bootstrap-v1|" + "|".join(value.hex() for value in sample)
    seed = int.from_bytes(hashlib.sha256(seed_material.encode("ascii")).digest()[:8], "big")
    generator = random.Random(seed)
    size = len(sample)
    medians = [
        float(statistics.median(sample[generator.randrange(size)] for _ in range(size)))
        for _ in range(resamples)
    ]
    return percentile(medians, 0.025), percentile(medians, 0.975)


def metric_statistics(values: Sequence[float | int]) -> dict[str, Any]:
    finite = [float(value) for value in values if math.isfinite(float(value))]
    q1 = percentile(finite, 0.25)
    q3 = percentile(finite, 0.75)
    ci_lower, ci_upper = bootstrap_median_ci95(finite)
    return {
        "n": len(finite),
        "median": percentile(finite, 0.50),
        "p95": percentile(finite, 0.95),
        "p99": percentile(finite, 0.99),
        "q1": q1,
        "q3": q3,
        "iqr": q3 - q1 if q1 is not None and q3 is not None else None,
        "mean": statistics.fmean(finite) if finite else None,
        "sample_stddev": statistics.stdev(finite) if len(finite) >= 2 else None,
        "bootstrap_median_ci95_lower": ci_lower,
        "bootstrap_median_ci95_upper": ci_upper,
        "bootstrap_resamples": BOOTSTRAP_RESAMPLES if finite else 0,
    }


def _summarize_group(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    warmup_count = sum(_bool(row.get("warmup")) for row in rows)
    measured = [row for row in rows if not _bool(row.get("warmup"))]
    valid = [row for row in measured if _bool(row.get("valid"))]
    invalid = len(measured) - len(valid)
    censored = sum(_bool(row.get("censored")) for row in valid)

    metrics: dict[str, Any] = {}
    for metric in METRICS:
        values: list[float | int] = []
        for row in valid:
            value = row.get(metric)
            if value is None or value == "":
                continue
            if isinstance(value, bool):
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(numeric):
                values.append(value)  # retain exact integers until statistics
        metrics[metric] = metric_statistics(values)

    exact_uncovered = [
        int(row["controlled_attempts_uncovered_possible"])
        for row in valid
        if row.get("controlled_attempts_uncovered_possible") is not None
    ]
    zero_count = sum(value == 0 for value in exact_uncovered)
    zero_n = len(exact_uncovered)
    all_zero = zero_n > 0 and zero_count == zero_n
    zero_uncovered = {
        "n": zero_n,
        "zero": zero_count,
        "rate": zero_count / zero_n if zero_n else None,
        "all_zero": all_zero,
        "rule_of_three_upper_bound": min(1.0, 3.0 / zero_n) if all_zero else None,
    }
    return {
        "total": len(measured),
        "n": len(valid),
        "invalid": invalid,
        "censored": censored,
        "warmup": warmup_count,
        "metrics": metrics,
        "zero_uncovered": zero_uncovered,
        # Deprecated compatibility alias.
        "zero_miss": zero_uncovered,
    }


def _pair_id(row: Mapping[str, Any]) -> str:
    """Derive the randomized block identifier shared by both backend arms."""

    trial_id = str(row.get("trial_id") or "").strip()
    backend = str(row.get("backend") or "").strip().lower()
    application = str(row.get("application") or "synthetic").strip().lower()
    canonical = re.fullmatch(r"([mw]\d+)[-_](sygma|tetragon)", trial_id, re.IGNORECASE)
    if canonical:
        return f"{application}:{canonical.group(1).lower()}"
    if backend:
        suffix = re.search(rf"[-_]{re.escape(backend)}$", trial_id, re.IGNORECASE)
        if suffix:
            return f"{application}:{trial_id[: suffix.start()]}"
    # Keeping an unrecognized ID as its own block makes the missing opposite
    # arm visible in the exclusion count instead of silently discarding it.
    return f"{application}:{trial_id}"


def summarize_paired_misses(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize paired ``Tetragon - SYGMA`` uncovered-call intervals."""

    measured = [row for row in rows if not _bool(row.get("warmup"))]
    warmup_ids = {_pair_id(row) for row in rows if _bool(row.get("warmup"))}
    blocks: dict[str, dict[str, list[Mapping[str, Any]]]] = {}
    for row in measured:
        pair_id = _pair_id(row)
        backend = str(row.get("backend") or "").strip().lower()
        blocks.setdefault(pair_id, {}).setdefault(backend, []).append(row)

    excluded_reasons = {
        "missing_arm": 0,
        "duplicate_arm": 0,
        "invalid_arm": 0,
        "censored_arm": 0,
        "missing_metric": 0,
    }
    observations: list[dict[str, Any]] = []
    for pair_id in sorted(blocks):
        arms = blocks[pair_id]
        sygma_rows = arms.get("sygma", [])
        tetragon_rows = arms.get("tetragon", [])
        if not sygma_rows or not tetragon_rows:
            excluded_reasons["missing_arm"] += 1
            continue
        if len(sygma_rows) != 1 or len(tetragon_rows) != 1:
            excluded_reasons["duplicate_arm"] += 1
            continue
        sygma = sygma_rows[0]
        tetragon = tetragon_rows[0]
        if not _bool(sygma.get("valid")) or not _bool(tetragon.get("valid")):
            excluded_reasons["invalid_arm"] += 1
            continue
        def uncovered(row: Mapping[str, Any], endpoint: str) -> int | None:
            value = _int_or_none(
                row.get(f"controlled_attempts_uncovered_{endpoint}")
            )
            if value is None:
                value = _int_or_none(row.get(f"missed_policy_calls_{endpoint}"))
            return value

        sygma_definite = uncovered(sygma, "definite")
        sygma_possible = uncovered(sygma, "possible")
        tetragon_definite = uncovered(tetragon, "definite")
        tetragon_possible = uncovered(tetragon, "possible")
        if None in {
            sygma_definite,
            sygma_possible,
            tetragon_definite,
            tetragon_possible,
        }:
            excluded_reasons["missing_metric"] += 1
            continue
        assert sygma_definite is not None and sygma_possible is not None
        assert tetragon_definite is not None and tetragon_possible is not None
        lower = tetragon_definite - sygma_possible
        upper = tetragon_possible - sygma_definite
        observations.append(
            {
                "pair_id": pair_id,
                "sygma_trial_id": str(sygma.get("trial_id") or ""),
                "tetragon_trial_id": str(tetragon.get("trial_id") or ""),
                "sygma_missed_policy_calls_definite": sygma_definite,
                "sygma_missed_policy_calls_possible": sygma_possible,
                "tetragon_missed_policy_calls_definite": tetragon_definite,
                "tetragon_missed_policy_calls_possible": tetragon_possible,
                "additional_missed_policy_calls_definite": lower,
                "additional_missed_policy_calls_possible": upper,
                # Compatibility alias for the conservative interval endpoint.
                "additional_missed_policy_calls": upper,
                "additional_uncovered_attempts_definite": lower,
                "additional_uncovered_attempts_possible": upper,
            }
        )

    lower_values = [
        item["additional_missed_policy_calls_definite"] for item in observations
    ]
    upper_values = [
        item["additional_missed_policy_calls_possible"] for item in observations
    ]
    excluded = sum(excluded_reasons.values())
    return {
        "definition": (
            "interval subtraction: lower=tetragon.definite-sygma.possible; "
            "upper=tetragon.possible-sygma.definite"
        ),
        "candidate_pairs": len(blocks),
        "n": len(observations),
        "excluded": excluded,
        "excluded_reasons": excluded_reasons,
        "warmup_pairs": len(warmup_ids),
        "statistics": metric_statistics(upper_values),
        "definite_statistics": metric_statistics(lower_values),
        "possible_statistics": metric_statistics(upper_values),
        "values": upper_values,
        "definite_values": lower_values,
        "possible_values": upper_values,
        "observations": observations,
    }


def summarize_sygma_atomicity(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    measured = [
        row
        for row in rows
        if not _bool(row.get("warmup"))
        and str(row.get("backend") or "").lower() == "sygma"
    ]
    proven: list[str] = []
    violations: list[dict[str, str]] = []
    unevaluable: list[dict[str, str]] = []
    for row in measured:
        trial_id = str(row.get("trial_id") or "")
        reason = str(row.get("invalid_reason") or "")
        if row.get("sygma_atomicity_order_valid") is True and _bool(row.get("valid")):
            proven.append(trial_id)
        elif (
            row.get("sygma_atomicity_order_valid") is False
            or "atomicity" in reason.lower()
        ):
            violations.append({"trial_id": trial_id, "reason": reason})
        else:
            unevaluable.append({"trial_id": trial_id, "reason": reason})
    return {
        "measured_trials": len(measured),
        "proven_trials": len(proven),
        "violation_trials": len(violations),
        "unevaluable_trials": len(unevaluable),
        "all_evaluable_trials_preserved_atomicity": bool(measured)
        and not violations
        and not unevaluable,
        "publication_eligible": bool(measured) and not violations and not unevaluable,
        "proven_trial_ids": proven,
        "violations": violations,
        "unevaluable": unevaluable,
    }


def summarize_trials(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    backends = sorted({str(row.get("backend") or "") for row in rows})
    applications = sorted(
        {str(row.get("application") or "synthetic") for row in rows}
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "target_syscall": {
            "nr": TARGET_SYSCALL_NR,
            "name": TARGET_SYSCALL_NAME,
        },
        "percentile_method": "linear_interpolation_type7",
        "bootstrap_method": (
            f"deterministic percentile bootstrap of median, 95% CI, "
            f"{BOOTSTRAP_RESAMPLES} resamples"
        ),
        "observation_mode": (
            "All timed calls must succeed. A denial or other syscall error invalidates "
            "the trial; readiness markers define policy coverage."
        ),
        "readiness_definition": (
            "Both arms use oci_prestart_enter as t0. SYGMA readiness is the exact "
            "sygma_direct_policy_ready marker; Tetragon enrollment lies in the "
            "map_insert interval (L,U]. Policy setup latency from t0 is distinct "
            "from userland exposure because SYGMA retains the prestart barrier."
        ),
        "attempt_bracket_definition": (
            "For Tetragon, a controlled call is definitely uncovered only when its "
            "post-syscall timestamp is <= L, and possibly uncovered when its "
            "pre-syscall timestamp is <= U. SYGMA uncovered calls are zero only when "
            "the publish-before-release ordering invariant passes."
        ),
        "sygma_prestart_lead_definition": (
            "probe_start boottime - sygma_direct_policy_ready boottime"
        ),
        "sygma_hook_cost_definition": (
            "oci_prestart_complete boottime - oci_prestart_enter boottime"
        ),
        "measurement_perturbation": (
            "The Tetragon arm includes a timestamp-only prestart hook. Its duration is "
            "reported and gives asynchronous enrollment additional time before user "
            "code starts, conservatively biasing uncovered-call counts downward."
        ),
        "sygma_atomicity": summarize_sygma_atomicity(rows),
        "overall": _summarize_group(rows),
        "by_backend": {
            backend: _summarize_group(
                [row for row in rows if str(row.get("backend") or "") == backend]
            )
            for backend in backends
        },
        "by_application": {
            application: {
                backend: _summarize_group(
                    [
                        row
                        for row in rows
                        if str(row.get("application") or "synthetic")
                        == application
                        and str(row.get("backend") or "") == backend
                    ]
                )
                for backend in backends
            }
            for application in applications
        },
        "paired_additional_missed_policy_calls": summarize_paired_misses(rows),
        "paired_additional_uncovered_attempts": summarize_paired_misses(rows),
        "paired_additional_missed_policy_calls_by_application": {
            application: summarize_paired_misses(
                [
                    row
                    for row in rows
                    if str(row.get("application") or "synthetic") == application
                ]
            )
            for application in applications
        },
        "paired_additional_uncovered_attempts_by_application": {
            application: summarize_paired_misses(
                [
                    row
                    for row in rows
                    if str(row.get("application") or "synthetic") == application
                ]
            )
            for application in applications
        },
    }


def _csv_text(columns: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> str:
    import io

    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(columns), extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: "" if row.get(key) is None else row.get(key) for key in columns})
    return stream.getvalue()


def _summary_csv_rows(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    groups: list[tuple[str, str, str, Mapping[str, Any]]] = [
        ("overall", "", "", summary["overall"])
    ]
    groups.extend(
        ("backend", "", backend, value)
        for backend, value in sorted(summary.get("by_backend", {}).items())
    )
    groups.extend(
        ("application_backend", application, backend, value)
        for application, backend_groups in sorted(
            summary.get("by_application", {}).items()
        )
        for backend, value in sorted(backend_groups.items())
    )
    output: list[dict[str, Any]] = []
    for scope, application, backend, group in groups:
        zero = group["zero_uncovered"]
        for metric in METRICS:
            stats = group["metrics"][metric]
            row = {
                "scope": scope,
                "application": application,
                "backend": backend,
                "total": group["total"],
                "n": group["n"],
                "invalid": group["invalid"],
                "censored": group["censored"],
                "warmup": group["warmup"],
                "metric": metric,
                "metric_n": stats["n"],
                "median": stats["median"],
                "p95": stats["p95"],
                "p99": stats["p99"],
                "q1": stats["q1"],
                "q3": stats["q3"],
                "iqr": stats["iqr"],
                "mean": stats["mean"],
                "sample_stddev": stats["sample_stddev"],
                "bootstrap_median_ci95_lower": stats["bootstrap_median_ci95_lower"],
                "bootstrap_median_ci95_upper": stats["bootstrap_median_ci95_upper"],
                "bootstrap_resamples": stats["bootstrap_resamples"],
            }
            if metric == "controlled_attempts_uncovered_possible":
                row.update(
                    {
                        "zero_miss_n": zero["n"],
                        "zero_miss_count": zero["zero"],
                        "zero_miss_rate": zero["rate"],
                        "zero_uncovered_n": zero["n"],
                        "zero_uncovered_count": zero["zero"],
                        "zero_uncovered_rate": zero["rate"],
                        "all_zero": zero["all_zero"],
                        "rule_of_three_upper_bound": zero["rule_of_three_upper_bound"],
                    }
                )
            output.append(row)

    paired = summary["paired_additional_uncovered_attempts"]
    for endpoint, paired_stats in (
        ("definite", paired["definite_statistics"]),
        ("possible", paired["possible_statistics"]),
    ):
        output.append({
            "scope": "paired",
            "application": "",
            "backend": "tetragon_minus_sygma",
            "total": paired["candidate_pairs"],
            "n": paired["n"],
            "invalid": paired["excluded_reasons"]["invalid_arm"],
            "censored": paired["excluded_reasons"]["censored_arm"],
            "excluded": paired["excluded"],
            "exclusion_reasons": json.dumps(
                paired["excluded_reasons"], sort_keys=True, separators=(",", ":")
            ),
            "warmup": paired["warmup_pairs"],
            "metric": f"additional_uncovered_attempts_{endpoint}",
            "metric_n": paired_stats["n"],
            "median": paired_stats["median"],
            "p95": paired_stats["p95"],
            "p99": paired_stats["p99"],
            "q1": paired_stats["q1"],
            "q3": paired_stats["q3"],
            "iqr": paired_stats["iqr"],
            "mean": paired_stats["mean"],
            "sample_stddev": paired_stats["sample_stddev"],
            "bootstrap_median_ci95_lower": paired_stats["bootstrap_median_ci95_lower"],
            "bootstrap_median_ci95_upper": paired_stats["bootstrap_median_ci95_upper"],
            "bootstrap_resamples": paired_stats["bootstrap_resamples"],
        })
    for application, application_paired in sorted(
        summary.get("paired_additional_uncovered_attempts_by_application", {}).items()
    ):
        for endpoint, paired_stats in (
            ("definite", application_paired["definite_statistics"]),
            ("possible", application_paired["possible_statistics"]),
        ):
            output.append({
                "scope": "paired_application",
                "application": application,
                "backend": "tetragon_minus_sygma",
                "total": application_paired["candidate_pairs"],
                "n": application_paired["n"],
                "invalid": application_paired["excluded_reasons"]["invalid_arm"],
                "censored": application_paired["excluded_reasons"]["censored_arm"],
                "excluded": application_paired["excluded"],
                "exclusion_reasons": json.dumps(
                    application_paired["excluded_reasons"],
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "warmup": application_paired["warmup_pairs"],
                "metric": f"additional_uncovered_attempts_{endpoint}",
                "metric_n": paired_stats["n"],
                "median": paired_stats["median"],
                "p95": paired_stats["p95"],
                "p99": paired_stats["p99"],
                "q1": paired_stats["q1"],
                "q3": paired_stats["q3"],
                "iqr": paired_stats["iqr"],
                "mean": paired_stats["mean"],
                "sample_stddev": paired_stats["sample_stddev"],
                "bootstrap_median_ci95_lower": paired_stats[
                    "bootstrap_median_ci95_lower"
                ],
                "bootstrap_median_ci95_upper": paired_stats[
                    "bootstrap_median_ci95_upper"
                ],
                "bootstrap_resamples": paired_stats["bootstrap_resamples"],
            })
    return output


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


APPLICATION_TRIAL_COLUMNS = [
    "trial_id",
    "backend",
    "application",
    "warmup",
    "valid",
    "invalid_reason",
    "prestart_trigger_boottime_ns",
    "policy_ready_lower_boottime_ns",
    "policy_ready_upper_boottime_ns",
    "policy_apply_from_prestart_lower_ms",
    "policy_apply_from_prestart_upper_ms",
    "first_application_syscall_boottime_ns",
    "policy_ready_to_first_application_syscall_lower_ms",
    "policy_ready_to_first_application_syscall_upper_ms",
    "application_syscalls_total",
    "application_syscalls_uncovered_definite",
    "application_syscalls_uncovered_possible",
    "application_syscalls_uncovered_definite_rate",
    "application_syscalls_uncovered_possible_rate",
    "application_distinct_syscall_types_uncovered_definite",
    "application_distinct_syscall_types_uncovered_possible",
    "application_syscall_histogram_json",
    "sygma_atomicity_order_valid",
    "map_interval_width_ms",
    "application_time_bucket_ns",
    "application_syscalls_jsonl",
    "mapwatch_jsonl",
    "hook_timeline_jsonl",
]

APPLICATION_METRICS = (
    "policy_apply_from_prestart_lower_ms",
    "policy_apply_from_prestart_upper_ms",
    "policy_ready_to_first_application_syscall_lower_ms",
    "policy_ready_to_first_application_syscall_upper_ms",
    "application_syscalls_total",
    "application_syscalls_uncovered_definite",
    "application_syscalls_uncovered_possible",
    "application_syscalls_uncovered_definite_rate",
    "application_syscalls_uncovered_possible_rate",
    "application_distinct_syscall_types_uncovered_definite",
    "application_distinct_syscall_types_uncovered_possible",
    "map_interval_width_ms",
)


def _raw_events_for_trial(
    trial: Mapping[str, Any], run_path: Path, key: str
) -> list[dict[str, Any]]:
    relative = trial.get("raw", {}).get(key)
    if not relative:
        return []
    path = Path(str(relative))
    if not path.is_absolute():
        path = run_path / path
    return read_jsonl(path) if path.exists() else []


def _single_event(
    events: Sequence[Mapping[str, Any]], event_name: str
) -> Mapping[str, Any] | None:
    matches = [event for event in events if event.get("event") == event_name]
    return matches[0] if len(matches) == 1 else None


def analyze_application_trial(
    trial: Mapping[str, Any], run_path: Path
) -> dict[str, Any]:
    backend = str(trial.get("backend", ""))
    row: dict[str, Any] = {
        "trial_id": trial.get("trial_id"),
        "backend": backend,
        "application": trial.get("application"),
        "warmup": bool(trial.get("warmup")),
        "valid": bool(trial.get("valid")),
        "invalid_reason": trial.get("invalid_reason"),
        "sygma_atomicity_order_valid": None,
    }
    raw = trial.get("raw", {})
    for field, key in (
        ("application_syscalls_jsonl", "application_syscalls_jsonl"),
        ("mapwatch_jsonl", "mapwatch_jsonl"),
        ("hook_timeline_jsonl", "hook_timeline_jsonl"),
    ):
        row[field] = raw.get(key)

    hooks = _raw_events_for_trial(trial, run_path, "hook_timeline_jsonl")
    maps = _raw_events_for_trial(trial, run_path, "mapwatch_jsonl")
    probes = _raw_events_for_trial(trial, run_path, "probe_jsonl")
    enter = _single_event(hooks, "oci_prestart_enter")
    complete = _single_event(hooks, "oci_prestart_complete")
    probe_start = _single_event(probes, "probe_start")
    snapshot = trial.get("application_syscall_snapshot")
    if not isinstance(snapshot, Mapping):
        snapshot = None

    try:
        prestart_ns = int(enter["boottime_ns"]) if enter else None
        complete_ns = int(complete["boottime_ns"]) if complete else None
        probe_start_ns = (
            int(probe_start["boottime_ns"]) if probe_start else None
        )
        first_app_ns = (
            int(snapshot["first_boottime_ns"]) if snapshot else None
        )
        total = int(snapshot["total"]) if snapshot else 0
    except (KeyError, TypeError, ValueError):
        prestart_ns = complete_ns = probe_start_ns = first_app_ns = None
        total = 0
    row["prestart_trigger_boottime_ns"] = prestart_ns
    row["first_application_syscall_boottime_ns"] = first_app_ns
    row["application_syscalls_total"] = total
    histogram = snapshot.get("syscalls", []) if snapshot else []
    if isinstance(histogram, list):
        histogram = sorted(
            histogram,
            key=lambda item: int(item.get("nr", -1))
            if isinstance(item, Mapping)
            else -1,
        )
    row["application_syscall_histogram_json"] = json.dumps(
        histogram, sort_keys=True, separators=(",", ":")
    )
    row["application_time_bucket_ns"] = (
        int(snapshot.get("bucket_ns", 0)) if snapshot else None
    )

    lower_ns: int | None = None
    upper_ns: int | None = None
    definite: int | None = None
    possible: int | None = None
    distinct_definite: int | None = None
    distinct_possible: int | None = None
    if backend == "sygma":
        ready = _single_event(hooks, "sygma_direct_policy_ready")
        release_begin = _single_event(hooks, "target_release_begin")
        release_signal = _single_event(hooks, "target_release_signal_sent")
        try:
            ready_ns = int(ready["boottime_ns"]) if ready else None
            release_begin_ns = (
                int(release_begin["boottime_ns"]) if release_begin else None
            )
            release_signal_ns = (
                int(release_signal["boottime_ns"]) if release_signal else None
            )
        except (KeyError, TypeError, ValueError):
            ready_ns = release_begin_ns = release_signal_ns = None
        lower_ns = upper_ns = ready_ns
        definite = possible = 0 if ready_ns is not None and first_app_ns is not None and ready_ns <= first_app_ns else None
        # If zero syscalls ran before policy-ready (definite == 0), then
        # trivially zero *distinct types* did either -- same atomicity
        # inference as definite/possible above, not a separate measurement.
        distinct_definite = distinct_possible = 0 if definite == 0 else None
        sequence = [
            prestart_ns,
            ready_ns,
            release_begin_ns,
            release_signal_ns,
            complete_ns,
            probe_start_ns,
            first_app_ns,
        ]
        atomic: bool | None
        if all(value is not None for value in sequence):
            ordered_sequence = [int(value) for value in sequence]
            atomic = ordered_sequence == sorted(ordered_sequence)
        else:
            atomic = None
        row["sygma_atomicity_order_valid"] = atomic
        if atomic is False:
            row["valid"] = False
            reason = "sygma_atomicity_invariant_violation"
            row["invalid_reason"] = "; ".join(
                value for value in (str(row.get("invalid_reason") or ""), reason) if value
            )
        elif atomic is None:
            row["valid"] = False
            reason = "sygma_atomicity_evidence_incomplete"
            row["invalid_reason"] = "; ".join(
                value for value in (str(row.get("invalid_reason") or ""), reason) if value
            )
    elif backend == "tetragon":
        insertion = _single_event(maps, "map_insert")
        try:
            lower_ns = int(insertion["last_absent_boottime_ns"]) if insertion else None
            upper_ns = int(insertion["first_present_boottime_ns"]) if insertion else None
            definite = int(
                insertion["application_syscalls_uncovered_definite"]
            ) if insertion else None
            possible = int(
                insertion["application_syscalls_uncovered_possible"]
            ) if insertion else None
            distinct_definite = int(
                insertion["application_distinct_syscall_types_uncovered_definite"]
            ) if insertion else None
            distinct_possible = int(
                insertion["application_distinct_syscall_types_uncovered_possible"]
            ) if insertion else None
            row["application_time_bucket_ns"] = int(
                insertion.get("application_time_bucket_ns", row.get("application_time_bucket_ns") or 0)
            ) if insertion else row.get("application_time_bucket_ns")
        except (KeyError, TypeError, ValueError):
            lower_ns = upper_ns = definite = possible = None
            distinct_definite = distinct_possible = None
    else:
        row["valid"] = False
        row["invalid_reason"] = "unknown_backend"

    row["policy_ready_lower_boottime_ns"] = lower_ns
    row["policy_ready_upper_boottime_ns"] = upper_ns
    row["application_syscalls_uncovered_definite"] = definite
    row["application_syscalls_uncovered_possible"] = possible
    row["application_distinct_syscall_types_uncovered_definite"] = distinct_definite
    row["application_distinct_syscall_types_uncovered_possible"] = distinct_possible
    row["application_syscalls_uncovered_definite_rate"] = (
        definite / total if definite is not None and total > 0 else None
    )
    row["application_syscalls_uncovered_possible_rate"] = (
        possible / total if possible is not None and total > 0 else None
    )
    if prestart_ns is not None and lower_ns is not None:
        row["policy_apply_from_prestart_lower_ms"] = (
            lower_ns - prestart_ns
        ) / 1_000_000
    if prestart_ns is not None and upper_ns is not None:
        row["policy_apply_from_prestart_upper_ms"] = (
            upper_ns - prestart_ns
        ) / 1_000_000
    if first_app_ns is not None and lower_ns is not None:
        row["policy_ready_to_first_application_syscall_lower_ms"] = (
            first_app_ns - upper_ns
        ) / 1_000_000 if upper_ns is not None else None
        row["policy_ready_to_first_application_syscall_upper_ms"] = (
            first_app_ns - lower_ns
        ) / 1_000_000
    row["map_interval_width_ms"] = (
        (upper_ns - lower_ns) / 1_000_000
        if lower_ns is not None and upper_ns is not None
        else None
    )
    if total <= 0 or definite is None or possible is None:
        row["valid"] = False
        reason = "application_syscall_measurement_incomplete"
        row["invalid_reason"] = "; ".join(
            value for value in (str(row.get("invalid_reason") or ""), reason) if value
        )
    return row


def _summarize_application_group(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    warmup = sum(bool(row.get("warmup")) for row in rows)
    measured = [row for row in rows if not bool(row.get("warmup"))]
    valid = [row for row in measured if bool(row.get("valid"))]
    metrics: dict[str, Any] = {}
    for metric in APPLICATION_METRICS:
        values = [
            row[metric]
            for row in valid
            if row.get(metric) is not None
            and not isinstance(row.get(metric), bool)
        ]
        metrics[metric] = metric_statistics(values)
    return {
        "total": len(measured),
        "n": len(valid),
        "invalid": len(measured) - len(valid),
        "censored": 0,
        "excluded": len(measured) - len(valid),
        "warmup": warmup,
        "metrics": metrics,
    }


def summarize_application_trials(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    applications = sorted({str(row.get("application", "unknown")) for row in rows})
    backends = ("sygma", "tetragon")
    by_backend = {
        backend: _summarize_application_group(
            [row for row in rows if row.get("backend") == backend]
        )
        for backend in backends
    }
    by_application = {
        application: {
            backend: _summarize_application_group(
                [
                    row
                    for row in rows
                    if row.get("application") == application
                    and row.get("backend") == backend
                ]
            )
            for backend in backends
        }
        for application in applications
    }
    measured = [row for row in rows if not bool(row.get("warmup"))]
    pairs: dict[str, dict[str, Mapping[str, Any]]] = {}
    for row in measured:
        trial_id = str(row.get("trial_id", ""))
        pair_id = re.sub(r"-(sygma|tetragon)$", "", trial_id)
        pairs.setdefault(pair_id, {})[str(row.get("backend"))] = row
    paired_values_definite: list[int] = []
    paired_values_possible: list[int] = []
    excluded = 0
    for pair in pairs.values():
        sygma = pair.get("sygma")
        tetragon = pair.get("tetragon")
        if not sygma or not tetragon or not sygma.get("valid") or not tetragon.get("valid"):
            excluded += 1
            continue
        paired_values_definite.append(
            int(tetragon["application_syscalls_uncovered_definite"])
            - int(sygma["application_syscalls_uncovered_definite"])
        )
        paired_values_possible.append(
            int(tetragon["application_syscalls_uncovered_possible"])
            - int(sygma["application_syscalls_uncovered_possible"])
        )
    paired = {
        "candidate_pairs": len(pairs),
        "n": len(paired_values_possible),
        "excluded": excluded,
        "definite": metric_statistics(paired_values_definite),
        "possible": metric_statistics(paired_values_possible),
    }
    sygma_measured = [
        row for row in measured if row.get("backend") == "sygma"
    ]
    proven = sum(
        bool(row.get("valid"))
        and row.get("sygma_atomicity_order_valid") is True
        and row.get("application_syscalls_uncovered_possible") == 0
        for row in sygma_measured
    )
    violations = sum(
        row.get("sygma_atomicity_order_valid") is False
        for row in sygma_measured
    )
    unevaluable = sum(
        row.get("sygma_atomicity_order_valid") is not False
        and not (
            bool(row.get("valid"))
            and row.get("sygma_atomicity_order_valid") is True
            and row.get("application_syscalls_uncovered_possible") == 0
        )
        for row in sygma_measured
    )
    atomicity = {
        "measured_trials": len(sygma_measured),
        "proven_trials": proven,
        "violation_trials": violations,
        "unevaluable_trials": unevaluable,
        "publication_eligible": proven == len(sygma_measured) and bool(sygma_measured),
    }
    return {
        "schema_version": 4,
        "measurement": "application_lineage_syscalls",
        "overall": _summarize_application_group(rows),
        "by_backend": by_backend,
        "by_application": by_application,
        "paired_additional_uncovered_application_syscalls": paired,
        # Compatibility key consumed by the campaign publication gate.
        "paired_additional_uncovered_attempts": paired,
        "sygma_atomicity": atomicity,
    }


def analyze_application_run(
    run_path: Path,
    trials: Sequence[Mapping[str, Any]],
    output_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = [analyze_application_trial(trial, run_path) for trial in trials]
    summary = summarize_application_trials(rows)
    _atomic_write(
        output_path / "trials.csv",
        _csv_text(APPLICATION_TRIAL_COLUMNS, rows),
    )
    _atomic_write(
        output_path / "summary.json",
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n",
    )
    summary_rows = []
    for backend, group in summary["by_backend"].items():
        summary_rows.append(
            {
                "scope": "backend",
                "backend": backend,
                "total": group["total"],
                "n": group["n"],
                "invalid": group["invalid"],
                "warmup": group["warmup"],
                "metrics_json": json.dumps(group["metrics"], sort_keys=True),
            }
        )
    _atomic_write(
        output_path / "summary.csv",
        _csv_text(
            ("scope", "backend", "total", "n", "invalid", "warmup", "metrics_json"),
            summary_rows,
        ),
    )
    return rows, summary


def analyze_run(
    run_dir: Path | str,
    *,
    trials_jsonl: Path | str | None = None,
    output_dir: Path | str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    run_path = Path(run_dir).resolve()
    trials_path = Path(trials_jsonl) if trials_jsonl is not None else run_path / "trials.jsonl"
    if not trials_path.is_absolute():
        trials_path = run_path / trials_path
    output_path = Path(output_dir).resolve() if output_dir is not None else run_path

    trials = read_jsonl(trials_path)
    if trials and all(int(trial.get("schema_version", 0)) >= 4 for trial in trials):
        return analyze_application_run(run_path, trials, output_path)
    rows = [analyze_trial(trial, run_path) for trial in trials]
    summary = summarize_trials(rows)
    _atomic_write(output_path / "trials.csv", _csv_text(TRIAL_COLUMNS, rows))
    _atomic_write(
        output_path / "summary.json",
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
    )
    _atomic_write(
        output_path / "summary.csv",
        _csv_text(SUMMARY_CSV_COLUMNS, _summary_csv_rows(summary)),
    )
    return rows, summary


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", nargs="?", help="run directory containing trials.jsonl")
    parser.add_argument("--run-dir", dest="run_dir_option", help="same as positional run_dir")
    parser.add_argument(
        "--trials-jsonl",
        help="trials JSONL path (default: RUN_DIR/trials.jsonl; relative paths use RUN_DIR)",
    )
    parser.add_argument("--output-dir", help="output directory (default: RUN_DIR)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if args.run_dir and args.run_dir_option:
        parser.error("specify run_dir either positionally or with --run-dir, not both")
    run_dir = args.run_dir_option or args.run_dir
    if not run_dir:
        parser.error("a run directory is required")
    try:
        rows, summary = analyze_run(
            run_dir,
            trials_jsonl=args.trials_jsonl,
            output_dir=args.output_dir,
        )
    except AnalysisError as exc:
        print(f"analyze.py: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "trials": len(rows),
                "valid": summary["overall"]["n"],
                "invalid": summary["overall"]["invalid"],
                "censored": summary["overall"]["censored"],
                "warmup": summary["overall"]["warmup"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
