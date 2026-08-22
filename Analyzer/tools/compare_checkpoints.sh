#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 BASELINE_SUMMARY_JSON CHECKPOINT_SYSCALL_DIR" >&2
  exit 2
fi

baseline=$1
checkpoint_dir=$2

if [[ ! -f "$baseline" ]]; then
  echo "baseline summary not found: $baseline" >&2
  exit 1
fi
if [[ ! -d "$checkpoint_dir" ]]; then
  echo "checkpoint directory not found: $checkpoint_dir" >&2
  exit 1
fi

shopt -s nullglob
checkpoint_files=("$checkpoint_dir"/*.json)
if [[ ${#checkpoint_files[@]} -eq 0 ]]; then
  echo "no syscall checkpoint JSON files found in: $checkpoint_dir" >&2
  exit 1
fi

jq -s --slurpfile baseline "$baseline" '
  ($baseline[0]
    | map({key: (.number | tostring), value: .})
    | from_entries) as $previous
  | map(
      . as $current
      | ($previous[$current.number | tostring] // {}) as $old
      | {
          number: $current.number,
          name: $current.name,
          lsm_before: ($old.lsm_classification // "missing"),
          lsm_after: $current.lsm_classification,
          lsm_changed:
            (($old.lsm_classification // "missing") !=
             $current.lsm_classification),
          sigkill_before: ($old.sigkill_classification // "missing"),
          sigkill_after: $current.sigkill_classification,
          sigkill_changed:
            (($old.sigkill_classification // "missing") !=
             $current.sigkill_classification),
          unresolved_edges_before:
            (($old.unresolved_edges_in_proof_cone // []) | length),
          unresolved_edges_after:
            (($current.unresolved_edges_in_proof_cone // []) | length),
          unresolved_delta:
            ((($current.unresolved_edges_in_proof_cone // []) | length) -
             (($old.unresolved_edges_in_proof_cone // []) | length))
        }
    )
  | sort_by(.number)
' "${checkpoint_files[@]}"
