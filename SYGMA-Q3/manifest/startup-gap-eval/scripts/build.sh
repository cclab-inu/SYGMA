#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd -- "${script_dir}/.." && pwd)"
output_dir="${OUT_DIR:-${root_dir}/build}"
compiler="${CC:-cc}"
stripper="${STRIP:-strip}"
max_bytes=$((1024 * 1024))

if [[ "$(uname -m)" != "x86_64" ]]; then
    echo "error: these measurement tools must be built for x86-64" >&2
    exit 1
fi

mkdir -p -- "${output_dir}"

build_one() {
    local source_file="$1"
    local output_name="$2"
    local temporary_file="${output_dir}/.${output_name}.tmp.$$"
    local output_file="${output_dir}/${output_name}"
    local byte_count

    trap 'rm -f -- "${temporary_file}"' RETURN

    "${compiler}" \
        -std=c11 -O2 -static \
        -Wall -Wextra -Werror \
        -o "${temporary_file}" "${source_file}"
    "${stripper}" --strip-all "${temporary_file}"

    byte_count="$(stat -c '%s' -- "${temporary_file}")"
    if (( byte_count > max_bytes )); then
        echo "error: ${output_name} is ${byte_count} bytes (limit ${max_bytes})" >&2
        exit 1
    fi

    chmod 0755 "${temporary_file}"
    mv -f -- "${temporary_file}" "${output_file}"
    trap - RETURN
    echo "built ${output_file} (${byte_count} bytes, static x86-64)"
}

build_one "${root_dir}/workload/gap_probe.c" gap-probe
build_one "${root_dir}/mapwatch/policy_map_watch.c" policy-map-watch
