#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"
repo_root="$(cd -- "${eval_root}/../.." && pwd)"
output_dir="${eval_root}/build"

for tool in go make gcc grep llvm-objdump sha256sum; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "error: required tool is missing: ${tool}" >&2
        exit 1
    fi
done

monitoring_source="${repo_root}/sygma_eBPF/monitoring.c"
tracer_source="${repo_root}/ocihook/ebpf/tracer/main.go"
wrapper_source="${repo_root}/ocihook/ebpf/wrapper/wrapper.c"

if grep -En \
    'bpf_send_signal(_thread)?[[:space:]]*\(|bpf_override_return[[:space:]]*\(|return[[:space:]]+-EPERM|PtraceSetRegs|PTRACE_POKEUSER' \
    "${monitoring_source}" "${tracer_source}" "${wrapper_source}"; then
    echo "error: an active SYGMA policy-blocking primitive is present" >&2
    exit 1
fi

(
    cd -- "${repo_root}/sygma_eBPF"
    make build
    go test ./...
    go vet ./...
)

if llvm-objdump -d "${repo_root}/sygma_eBPF/bpf_x86_bpfel.o" | \
    grep -Eq 'call[[:space:]]+(58|109|117)$'; then
    echo "error: generated BPF object calls an override/signal helper" >&2
    exit 1
fi

(
    cd -- "${repo_root}/ocihook/ebpf/hook"
    go test ./...
    go vet ./...
)

(
    cd -- "${repo_root}/ocihook/nri"
    go test ./...
    go vet ./...
    go build -buildvcs=false -o nri .
)

(
    cd -- "${repo_root}/ocihook/ebpf/tracer"
    go test ./...
    go vet ./...
    go build -buildvcs=false -o tracer .
)

mkdir -p -- "${repo_root}/ocihook/build" "${output_dir}"
gcc -static -O2 -Wall -Wextra -Werror \
    -o "${repo_root}/ocihook/build/sygma-wrapper" "${wrapper_source}"

stage_binary() {
    local source_path="$1"
    local output_name="$2"
    local temporary_path="${output_dir}/.${output_name}.tmp.$$"

    cp -- "${source_path}" "${temporary_path}"
    chmod 0755 "${temporary_path}"
    mv -f -- "${temporary_path}" "${output_dir}/${output_name}"
    sha256sum "${output_dir}/${output_name}"
}

stage_binary "${repo_root}/sygma_eBPF/core" sygma-core-current
stage_binary "${repo_root}/ocihook/ebpf/tracer/tracer" sygma-tracer-current
stage_binary "${repo_root}/ocihook/build/sygma-wrapper" sygma-wrapper-current
stage_binary "${repo_root}/ocihook/nri/nri" sygma-nri-current

echo "staged immutable observation-only trust anchors in ${output_dir}"
echo "install the staged host components with install_staged_observation_components.sh"
