#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly ARTIFACT_TAG="artifact-v1"
readonly ARTIFACT_VERSION="artifact-v1"
readonly ARTIFACT_BUILD_DATE="1970-01-01T00:00:00Z"
readonly DEFAULT_REDIS_ADDR="${REDIS_ADDR:-localhost:6379}"
readonly TARGET_PLATFORM="linux/amd64"
readonly UBUNTU_BASE_IMAGE="ubuntu@sha256:eb29ed27b0821dca09c2e28b39135e185fc1302036427d5f4d70a41ce8fd7659"
readonly REGENERATE_BPF_MODE="${REGENERATE_BPF:-0}"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_profile_environment() {
    local redis_port
    : "${SYGMA_LOCAL_PROFILE:?wrapper did not set SYGMA_LOCAL_PROFILE}"
    : "${SYGMA_LOCAL_PROFILE_ROOT:?wrapper did not set SYGMA_LOCAL_PROFILE_ROOT}"
    : "${SYGMA_LOCAL_PROFILE_DISPLAY:?wrapper did not set SYGMA_LOCAL_PROFILE_DISPLAY}"

    [[ "${SYGMA_LOCAL_PROFILE}" =~ ^[a-z0-9][a-z0-9-]*$ ]] || \
        die "invalid profile identifier: ${SYGMA_LOCAL_PROFILE}"
    case "${REGENERATE_BPF_MODE}" in
        0|1) ;;
        *) die "REGENERATE_BPF must be 0 or 1" ;;
    esac
    [[ "${DEFAULT_REDIS_ADDR}" =~ ^([^[:space:]:]+|\[[^]]+\]):([0-9]+)$ ]] || \
        die "REDIS_ADDR must be HOST:PORT (got '${DEFAULT_REDIS_ADDR}')"
    redis_port="${BASH_REMATCH[2]}"
    if (( ${#redis_port} > 5 )) || \
       (( 10#${redis_port} < 1 || 10#${redis_port} > 65535 )); then
        die "REDIS_ADDR port must be between 1 and 65535 (got '${redis_port}')"
    fi
    [[ -d "${SYGMA_LOCAL_PROFILE_ROOT}/sygma_eBPF" ]] || \
        die "missing core source directory under ${SYGMA_LOCAL_PROFILE_ROOT}"
    [[ -d "${SYGMA_LOCAL_PROFILE_ROOT}/ocihook" ]] || \
        die "missing OCI source directory under ${SYGMA_LOCAL_PROFILE_ROOT}"
    [[ -d "${SYGMA_LOCAL_PROFILE_ROOT}/sygma-operator" ]] || \
        die "missing operator source directory under ${SYGMA_LOCAL_PROFILE_ROOT}"
    [[ -f "${SYGMA_LOCAL_PROFILE_ROOT}/manifest/deploy.sh" ]] || \
        die "missing manifest/deploy.sh under ${SYGMA_LOCAL_PROFILE_ROOT}"
}

require_profile_environment

readonly PROFILE="${SYGMA_LOCAL_PROFILE}"
readonly PROFILE_ROOT="${SYGMA_LOCAL_PROFILE_ROOT}"
readonly PROFILE_DISPLAY="${SYGMA_LOCAL_PROFILE_DISPLAY}"
readonly CORE_DIR="${PROFILE_ROOT}/sygma_eBPF"
readonly OCI_DIR="${PROFILE_ROOT}/ocihook"
readonly OPERATOR_DIR="${PROFILE_ROOT}/sygma-operator"
readonly MANIFEST_DIR="${PROFILE_ROOT}/manifest"
readonly CORE_STAGE="${CORE_DIR}/.local-image"
readonly OPERATOR_STAGE="${OPERATOR_DIR}/.local-image"
readonly OUTPUT_DIR="${PROFILE_ROOT}/artifacts/local"
readonly IMAGE_ARCHIVE="${OUTPUT_DIR}/${PROFILE}-${ARTIFACT_TAG}-images.tar"
readonly IMAGE_ARCHIVE_SHA256="${IMAGE_ARCHIVE}.sha256"
readonly IMAGE_LOCK="${OUTPUT_DIR}/${PROFILE}-${ARTIFACT_TAG}-images.lock"
readonly IMAGE_REPOSITORY="localhost/${PROFILE}"
readonly CORE_IMAGE="${IMAGE_REPOSITORY}/core:${ARTIFACT_TAG}"
readonly OPERATOR_IMAGE="${IMAGE_REPOSITORY}/operator:${ARTIFACT_TAG}"
readonly INSTALLER_IMAGE="${IMAGE_REPOSITORY}/installer:${ARTIFACT_TAG}"
readonly BPF_CLANG_BIN="${BPF_CLANG:-clang-14}"
readonly CTR_BIN="${CTR_BIN:-ctr}"

readonly PAPER_ARCHIVE="${PROFILE_ROOT}/artifacts/sygma-eval-stack-performance-20260817.tar"
readonly PAPER_ARCHIVE_SHA256="2c8cfbd4fed8eb9edc6b8cc2c006eab83081417395ee94e3cf1f7c3fb04e1c6c"
readonly PAPER_CORE_SOURCE="docker.io/sygma-eval/core:state-machine-routes-20260817"
readonly PAPER_OPERATOR_SOURCE="docker.io/sygma-eval/operator:state-machine-20260817"
readonly PAPER_INSTALLER_SOURCE="docker.io/sygma-eval/installer:state-machine-20260817"
readonly PAPER_CORE_DIGEST="sha256:443cb3495a431e2053ddbe918a9ddb95597a03c96b1b18287966ae242046e0f4"
readonly PAPER_OPERATOR_DIGEST="sha256:8873096c63b6aee548407ed4de00b050f05f883880c17094c7f5dbc102fcf12a"
readonly PAPER_INSTALLER_DIGEST="sha256:ba3cb1c53e8d52154c58f6a2c41ca78ca5b833c9d48a97279131d7c477c4a911"
readonly PAPER_LOCK="${OUTPUT_DIR}/${PROFILE}-paper-images.lock"

usage() {
    cat <<EOF
Usage: ./local-images.sh COMMAND

Build and use the ${PROFILE_DISPLAY} images without publishing them.

Commands:
  build       Build host binaries and the three local container images, then
              create an archive, checksum, and config/manifest digest lock.
  load        Verify and import the generated archive into containerd's
              k8s.io namespace on this node.
  deploy      Verify the three local image references and run manifest/deploy.sh.
  all         Build, load, and deploy on a single-node cluster.
EOF
    if [[ "${PROFILE}" == "sygma-q4" ]]; then
        cat <<EOF
  load-paper  Verify/import a separately supplied post-acceptance Q4 paper
              archive and retag its images to neutral ${IMAGE_REPOSITORY} refs.
EOF
    fi
    cat <<EOF
  help        Show this help.

Fixed image references:
  ${CORE_IMAGE}
  ${OPERATOR_IMAGE}
  ${INSTALLER_IMAGE}

Generated files:
  ${IMAGE_ARCHIVE}
  ${IMAGE_ARCHIVE_SHA256}
  ${IMAGE_LOCK}

Build target: ${TARGET_PLATFORM}
The default build uses the checked-in bpf2go binding/object. Set
REGENERATE_BPF=1 to regenerate them; BPF_CLANG=/path/to/clang selects clang.
REDIS_ADDR defaults to localhost:6379 and is embedded as the host-binary
fallback. Set REDIS_ADDR=HOST:PORT explicitly for a multi-node build.
An initial build may fetch the pinned Ubuntu base and Go modules from public
sources; it never publishes the resulting images.
For more than one Kubernetes node, run 'load' with the same archive on every
schedulable node before running 'deploy'.
EOF
}

ensure_amd64_host() {
    local machine
    machine="$(uname -m)"
    case "${machine}" in
        x86_64|amd64) ;;
        *) die "host architecture ${machine} is unsupported; this artifact requires amd64" ;;
    esac
}

check_build_prerequisites() {
    ensure_amd64_host
    require_command go
    require_command docker
    require_command gcc
    require_command sha256sum
    require_command awk
    require_command grep
    require_command python3
    if [[ "${REGENERATE_BPF_MODE}" == "1" ]]; then
        require_command "${BPF_CLANG_BIN}"
    fi
    docker info >/dev/null 2>&1 || die "cannot access the Docker daemon"

    [[ -f "${CORE_DIR}/Dockerfile.local" ]] || die "missing ${CORE_DIR}/Dockerfile.local"
    [[ -f "${OCI_DIR}/Dockerfile.local" ]] || die "missing ${OCI_DIR}/Dockerfile.local"
    [[ -f "${OPERATOR_DIR}/Dockerfile.local" ]] || die "missing ${OPERATOR_DIR}/Dockerfile.local"
}

check_load_prerequisites() {
    require_command "${CTR_BIN}"
    if (( EUID != 0 )); then
        require_command sudo
    fi
}

run_ctr() {
    if (( EUID == 0 )); then
        "${CTR_BIN}" -n k8s.io "$@"
    else
        sudo "${CTR_BIN}" -n k8s.io "$@"
    fi
}

reset_stage_directory() {
    local stage_dir="$1"
    case "${stage_dir}" in
        "${CORE_DIR}/.local-image"|"${OPERATOR_DIR}/.local-image") ;;
        *) die "refusing to reset unexpected staging directory: ${stage_dir}" ;;
    esac
    rm -rf -- "${stage_dir}"
    mkdir -p -- "${stage_dir}"
}

build_core() {
    reset_stage_directory "${CORE_STAGE}"
    if [[ "${REGENERATE_BPF_MODE}" == "1" ]]; then
        local -a bpf_flags=(-O2 -g)
        local bpf_cflags="-O2 -g"
        if [[ "${PROFILE}" != "sygma-q2" ]]; then
            bpf_flags+=(-Wall -Werror)
            bpf_cflags+=" -Wall -Werror"
        fi

        note "Regenerating BPF bindings with ${BPF_CLANG_BIN}"
        (
            cd "${CORE_DIR}"
            export GOOS=linux
            export GOARCH=amd64
            export CGO_ENABLED=0
            export GOFLAGS=-mod=readonly
            export SOURCE_DATE_EPOCH=0
            export TZ=UTC
            export LC_ALL=C
            export BPF_CLANG="${BPF_CLANG_BIN}"
            export BPF_CFLAGS="${bpf_cflags}"

            go generate ./...
            "${BPF_CLANG_BIN}" "${bpf_flags[@]}" \
                -target bpf -D__TARGET_ARCH_X86 \
                -c monitoring.c -o monitoring.o
        )
    else
        note "Using the checked-in bpf2go binding/object"
        [[ -f "${CORE_DIR}/bpf_x86_bpfel.go" ]] || \
            die "missing checked-in bpf_x86_bpfel.go; use REGENERATE_BPF=1"
        [[ -f "${CORE_DIR}/bpf_x86_bpfel.o" ]] || \
            die "missing checked-in bpf_x86_bpfel.o; use REGENERATE_BPF=1"
    fi

    note "Building the amd64 core"
    (
        cd "${CORE_DIR}"
        export GOOS=linux
        export GOARCH=amd64
        export CGO_ENABLED=0
        export GOFLAGS=-mod=readonly
        export SOURCE_DATE_EPOCH=0
        export TZ=UTC
        export LC_ALL=C
        go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
            -o "${CORE_STAGE}/core" .

        if [[ -f cmd/route-snapshot/main.go ]]; then
            go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
                -o "${CORE_STAGE}/route-snapshot" ./cmd/route-snapshot
        else
            warn "${PROFILE_DISPLAY} has no cmd/route-snapshot source; packaging core only"
        fi
    )
    chmod 0755 "${CORE_STAGE}/core"
    if [[ -f "${CORE_STAGE}/route-snapshot" ]]; then
        chmod 0755 "${CORE_STAGE}/route-snapshot"
    fi
}

build_oci_components() {
    local fixed_metadata_ldflags
    local hook_ldflags
    local nri_ldflags

    note "Building the OCI hook, tracer, static wrapper, and NRI plugin"
    mkdir -p "${OCI_DIR}/build"
    rm -f -- \
        "${OCI_DIR}/build/sygma-hook" \
        "${OCI_DIR}/build/sygma-tracer" \
        "${OCI_DIR}/build/sygma-wrapper" \
        "${OCI_DIR}/build/00-sygma"

    fixed_metadata_ldflags="-X main.Version=${ARTIFACT_VERSION} -X main.BuildDate=${ARTIFACT_BUILD_DATE}"
    hook_ldflags="-s -w -buildid= ${fixed_metadata_ldflags} -X main.DefaultRedisAddr=${DEFAULT_REDIS_ADDR}"
    if grep -q '^var SYGMAPolicyEnabled' "${OCI_DIR}/ebpf/hook/main.go"; then
        hook_ldflags+=" -X main.SYGMAPolicyEnabled=false"
    fi
    nri_ldflags="-s -w -buildid= ${fixed_metadata_ldflags} -X main.DefaultRedisAddr=${DEFAULT_REDIS_ADDR}"

    (
        cd "${OCI_DIR}"
        export GOOS=linux
        export GOARCH=amd64
        export CGO_ENABLED=0
        export GOFLAGS=-mod=readonly
        export SOURCE_DATE_EPOCH=0
        export TZ=UTC
        export LC_ALL=C

        go build -trimpath -buildvcs=false -ldflags="${hook_ldflags}" \
            -o build/sygma-hook ./ebpf/hook
        go build -trimpath -buildvcs=false \
            -ldflags="-s -w -buildid= ${fixed_metadata_ldflags}" \
            -o build/sygma-tracer ./ebpf/tracer
        go build -trimpath -buildvcs=false -ldflags="${nri_ldflags}" \
            -o build/00-sygma ./nri

        gcc -static -O2 \
            -ffile-prefix-map="${PROFILE_ROOT}=." \
            -fdebug-prefix-map="${PROFILE_ROOT}=." \
            -Wl,--build-id=none \
            -o build/sygma-wrapper ebpf/wrapper/wrapper.c
    )
    chmod 0755 \
        "${OCI_DIR}/build/sygma-hook" \
        "${OCI_DIR}/build/sygma-tracer" \
        "${OCI_DIR}/build/sygma-wrapper" \
        "${OCI_DIR}/build/00-sygma"
}

build_operator() {
    note "Building the amd64 operator"
    reset_stage_directory "${OPERATOR_STAGE}"
    (
        cd "${OPERATOR_DIR}"
        export GOOS=linux
        export GOARCH=amd64
        export CGO_ENABLED=1
        export GOFLAGS=-mod=readonly
        export SOURCE_DATE_EPOCH=0
        export TZ=UTC
        export LC_ALL=C
        go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
            -o "${OPERATOR_STAGE}/manager" ./cmd
    )
    chmod 0755 "${OPERATOR_STAGE}/manager"
}

stage_q3_campaign_trust_anchors() {
    local output_dir
    local source_path
    local output_name
    local temporary_path
    local entry

    [[ "${PROFILE}" == "sygma-q3" ]] || return 0
    output_dir="${PROFILE_ROOT}/manifest/startup-gap-eval/build"
    [[ -d "${PROFILE_ROOT}/manifest/startup-gap-eval" ]] || \
        die "Q3 startup-gap evaluation directory is missing"
    mkdir -p -- "${output_dir}"

    for entry in \
        "${CORE_STAGE}/core:sygma-core-current" \
        "${OCI_DIR}/build/sygma-hook:sygma-hook" \
        "${OCI_DIR}/build/sygma-tracer:sygma-tracer-current" \
        "${OCI_DIR}/build/sygma-wrapper:sygma-wrapper-current" \
        "${OCI_DIR}/build/00-sygma:sygma-nri-current"; do
        source_path="${entry%%:*}"
        output_name="${entry##*:}"
        temporary_path="${output_dir}/.${output_name}.tmp.$$"
        [[ -f "${source_path}" ]] || die "missing Q3 trust-anchor source: ${source_path}"
        cp -- "${source_path}" "${temporary_path}"
        chmod 0755 "${temporary_path}"
        mv -f -- "${temporary_path}" "${output_dir}/${output_name}"
    done
    for output_name in core route-snapshot; do
        source_path="${CORE_STAGE}/${output_name}"
        [[ -f "${source_path}" ]] || continue
        temporary_path="${CORE_DIR}/.${output_name}.tmp.$$"
        cp -- "${source_path}" "${temporary_path}"
        chmod 0755 "${temporary_path}"
        mv -f -- "${temporary_path}" "${CORE_DIR}/${output_name}"
    done
    note "Staged the exact Q3 image binaries as campaign trust anchors"
}

build_container_images() {
    note "Packaging pinned-base local container images"
    SOURCE_DATE_EPOCH=0 docker build --platform "${TARGET_PLATFORM}" \
        --network none --pull=false \
        --build-arg SOURCE_DATE_EPOCH=0 \
        --tag "${CORE_IMAGE}" --file "${CORE_DIR}/Dockerfile.local" "${CORE_DIR}"
    SOURCE_DATE_EPOCH=0 docker build --platform "${TARGET_PLATFORM}" \
        --network none --pull=false \
        --build-arg SOURCE_DATE_EPOCH=0 \
        --tag "${INSTALLER_IMAGE}" --file "${OCI_DIR}/Dockerfile.local" "${OCI_DIR}"
    SOURCE_DATE_EPOCH=0 docker build --platform "${TARGET_PLATFORM}" \
        --network none --pull=false \
        --build-arg SOURCE_DATE_EPOCH=0 \
        --tag "${OPERATOR_IMAGE}" --file "${OPERATOR_DIR}/Dockerfile.local" "${OPERATOR_DIR}"
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

docker_image_id() {
    docker image inspect --format '{{.Id}}' "$1"
}

archive_manifest_metadata() {
    python3 - \
        "${IMAGE_ARCHIVE}" \
        "${CORE_IMAGE}" \
        "${OPERATOR_IMAGE}" \
        "${INSTALLER_IMAGE}" <<'PY'
import json
import re
import sys
import tarfile

archive_path = sys.argv[1]
expected = {
    "core": sys.argv[2],
    "operator": sys.argv[3],
    "installer": sys.argv[4],
}

with tarfile.open(archive_path, "r") as archive:
    stream = archive.extractfile("index.json")
    if stream is None:
        raise SystemExit("local image archive has no OCI index.json")
    index = json.load(stream)

descriptors = {}
for descriptor in index.get("manifests", []):
    annotations = descriptor.get("annotations") or {}
    reference = annotations.get("io.containerd.image.name")
    if reference:
        descriptors[reference] = descriptor

digest_pattern = re.compile(r"sha256:[0-9a-f]{64}")
allowed_media_types = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
for component, reference in expected.items():
    descriptor = descriptors.get(reference)
    if descriptor is None:
        raise SystemExit(f"OCI index has no descriptor for {reference}")
    digest = descriptor.get("digest", "")
    media_type = descriptor.get("mediaType", "")
    if not digest_pattern.fullmatch(digest):
        raise SystemExit(f"invalid OCI manifest digest for {reference}: {digest!r}")
    if media_type not in allowed_media_types:
        raise SystemExit(f"unsupported OCI media type for {reference}: {media_type!r}")
    repository = reference.rsplit(":", 1)[0]
    print(f"image.{component}.manifest_digest={digest}")
    print(f"image.{component}.digest_ref={repository}@{digest}")
PY
}

write_build_lock() {
    local archive_sha
    local lock_tmp="${IMAGE_LOCK}.tmp"
    archive_sha="$(file_sha256 "${IMAGE_ARCHIVE}")"

    {
        printf 'format_version=1\n'
        printf 'profile=%s\n' "${PROFILE}"
        printf 'artifact_version=%s\n' "${ARTIFACT_VERSION}"
        printf 'artifact_build_date=%s\n' "${ARTIFACT_BUILD_DATE}"
        printf 'redis_addr=%s\n' "${DEFAULT_REDIS_ADDR}"
        printf 'bpf.regenerated=%s\n' "${REGENERATE_BPF_MODE}"
        printf 'platform=%s\n' "${TARGET_PLATFORM}"
        printf 'base_image=%s\n' "${UBUNTU_BASE_IMAGE}"
        printf 'archive=%s\n' "$(basename "${IMAGE_ARCHIVE}")"
        printf 'archive_sha256=%s\n' "${archive_sha}"
        printf 'image.core.ref=%s\n' "${CORE_IMAGE}"
        printf 'image.core.id=%s\n' "$(docker_image_id "${CORE_IMAGE}")"
        printf 'image.operator.ref=%s\n' "${OPERATOR_IMAGE}"
        printf 'image.operator.id=%s\n' "$(docker_image_id "${OPERATOR_IMAGE}")"
        printf 'image.installer.ref=%s\n' "${INSTALLER_IMAGE}"
        printf 'image.installer.id=%s\n' "$(docker_image_id "${INSTALLER_IMAGE}")"
        archive_manifest_metadata
        printf 'binary.core.sha256=%s\n' "$(file_sha256 "${CORE_STAGE}/core")"
        printf 'binary.bpf_binding.sha256=%s\n' "$(file_sha256 "${CORE_DIR}/bpf_x86_bpfel.go")"
        printf 'binary.bpf_object.sha256=%s\n' "$(file_sha256 "${CORE_DIR}/bpf_x86_bpfel.o")"
        if [[ -f "${CORE_STAGE}/route-snapshot" ]]; then
            printf 'binary.route_snapshot.sha256=%s\n' "$(file_sha256 "${CORE_STAGE}/route-snapshot")"
        else
            printf 'binary.route_snapshot=absent\n'
        fi
        printf 'binary.hook.sha256=%s\n' "$(file_sha256 "${OCI_DIR}/build/sygma-hook")"
        printf 'binary.tracer.sha256=%s\n' "$(file_sha256 "${OCI_DIR}/build/sygma-tracer")"
        printf 'binary.wrapper.sha256=%s\n' "$(file_sha256 "${OCI_DIR}/build/sygma-wrapper")"
        printf 'binary.nri.sha256=%s\n' "$(file_sha256 "${OCI_DIR}/build/00-sygma")"
        printf 'binary.operator.sha256=%s\n' "$(file_sha256 "${OPERATOR_STAGE}/manager")"
        printf 'tool.go.core=%s\n' "$(cd "${CORE_DIR}" && go version)"
        printf 'tool.go.oci=%s\n' "$(cd "${OCI_DIR}" && go version)"
        printf 'tool.go.operator=%s\n' "$(cd "${OPERATOR_DIR}" && go version)"
        if [[ "${REGENERATE_BPF_MODE}" == "1" ]]; then
            printf 'tool.clang=%s\n' "$("${BPF_CLANG_BIN}" --version | awk 'NR == 1 {print; exit}')"
        else
            printf 'tool.clang=not-used\n'
        fi
        printf 'tool.gcc=%s\n' "$(gcc --version | awk 'NR == 1 {print; exit}')"
        printf 'tool.docker=%s\n' "$(docker version --format '{{.Client.Version}}')"
    } > "${lock_tmp}"
    mv -f -- "${lock_tmp}" "${IMAGE_LOCK}"
}

create_local_archive() {
    local archive_tmp="${IMAGE_ARCHIVE}.tmp"
    local sha_tmp="${IMAGE_ARCHIVE_SHA256}.tmp"

    note "Creating the local image archive and lock"
    mkdir -p "${OUTPUT_DIR}"
    docker save --output "${archive_tmp}" \
        "${CORE_IMAGE}" "${OPERATOR_IMAGE}" "${INSTALLER_IMAGE}"
    mv -f -- "${archive_tmp}" "${IMAGE_ARCHIVE}"
    (
        cd "${OUTPUT_DIR}"
        sha256sum "$(basename "${IMAGE_ARCHIVE}")" > "${sha_tmp}"
    )
    mv -f -- "${sha_tmp}" "${IMAGE_ARCHIVE_SHA256}"
    write_build_lock
    chmod 0644 "${IMAGE_ARCHIVE}" "${IMAGE_ARCHIVE_SHA256}" "${IMAGE_LOCK}"
}

build_local_images() {
    check_build_prerequisites
    build_core
    build_oci_components
    stage_q3_campaign_trust_anchors
    build_operator
    build_container_images
    create_local_archive
    note "Build complete: ${IMAGE_ARCHIVE}"
}

verify_generated_archive() {
    local expected
    local actual
    local lock_archive_sha
    [[ -f "${IMAGE_ARCHIVE}" ]] || die "generated archive not found; run 'build' first"
    [[ -f "${IMAGE_ARCHIVE_SHA256}" ]] || die "archive checksum not found; run 'build' first"
    [[ -f "${IMAGE_LOCK}" ]] || die "image lock not found; run 'build' first"
    expected="$(awk 'NF {print $1; exit}' "${IMAGE_ARCHIVE_SHA256}")"
    actual="$(file_sha256 "${IMAGE_ARCHIVE}")"
    [[ "${actual}" == "${expected}" ]] || \
        die "archive checksum mismatch: expected ${expected}, got ${actual}"
    lock_archive_sha="$(awk -F= '$1 == "archive_sha256" {print $2; exit}' "${IMAGE_LOCK}")"
    [[ "${actual}" == "${lock_archive_sha}" ]] || \
        die "image lock/archive checksum mismatch: ${lock_archive_sha:-missing} != ${actual}"
}

locked_digest_ref() {
    local component="$1"
    awk -F= -v expected="image.${component}.digest_ref" \
        '$1 == expected {sub(/^[^=]*=/, ""); print; exit}' "${IMAGE_LOCK}"
}

assert_locked_digest_refs_loaded() {
    local component
    local digest_ref
    for component in core operator installer; do
        digest_ref="$(locked_digest_ref "${component}")"
        [[ -n "${digest_ref}" ]] || die "missing ${component} digest reference in ${IMAGE_LOCK}"
        ctr_image_exists "${digest_ref}" || \
            die "containerd digest reference is missing from k8s.io: ${digest_ref}"
    done
}

assert_local_images_loaded() {
    local image_ref
    for image_ref in "${CORE_IMAGE}" "${OPERATOR_IMAGE}" "${INSTALLER_IMAGE}"; do
        ctr_image_exists "${image_ref}" || \
            die "containerd image is missing from k8s.io: ${image_ref}"
    done
}

ctr_image_exists() {
    local expected="$1"
    run_ctr images list --quiet |
        awk -v expected="${expected}" '
            $0 == expected { found = 1 }
            END { exit(found ? 0 : 1) }
        '
}

load_local_images() {
    check_load_prerequisites
    verify_generated_archive
    note "Importing ${IMAGE_ARCHIVE} into containerd namespace k8s.io"
    run_ctr images import --digests --platform "${TARGET_PLATFORM}" "${IMAGE_ARCHIVE}"
    assert_local_images_loaded
    assert_locked_digest_refs_loaded
    note "All three ${PROFILE_DISPLAY} image references are available to kubelet"
}

ctr_target_digest() {
    local image_ref="$1"
    run_ctr images list | \
        awk -v expected="${image_ref}" '
            NR > 1 && $1 == expected { print $3; exit }
        '
}

assert_ctr_digest() {
    local image_ref="$1"
    local expected="$2"
    local actual
    actual="$(ctr_target_digest "${image_ref}")"
    [[ -n "${actual}" ]] || die "could not read containerd target digest for ${image_ref}"
    [[ "${actual}" == "${expected}" ]] || \
        die "unexpected digest for ${image_ref}: expected ${expected}, got ${actual}"
}

write_paper_lock() {
    local lock_tmp="${PAPER_LOCK}.tmp"
    mkdir -p "${OUTPUT_DIR}"
    {
        printf 'format_version=1\n'
        printf 'profile=%s\n' "${PROFILE}"
        printf 'platform=%s\n' "${TARGET_PLATFORM}"
        printf 'archive=%s\n' "$(basename "${PAPER_ARCHIVE}")"
        printf 'archive_sha256=%s\n' "${PAPER_ARCHIVE_SHA256}"
        printf 'image.core.source=%s\n' "${PAPER_CORE_SOURCE}"
        printf 'image.core.ref=%s\n' "${CORE_IMAGE}"
        printf 'image.core.target_digest=%s\n' "${PAPER_CORE_DIGEST}"
        printf 'image.operator.source=%s\n' "${PAPER_OPERATOR_SOURCE}"
        printf 'image.operator.ref=%s\n' "${OPERATOR_IMAGE}"
        printf 'image.operator.target_digest=%s\n' "${PAPER_OPERATOR_DIGEST}"
        printf 'image.installer.source=%s\n' "${PAPER_INSTALLER_SOURCE}"
        printf 'image.installer.ref=%s\n' "${INSTALLER_IMAGE}"
        printf 'image.installer.target_digest=%s\n' "${PAPER_INSTALLER_DIGEST}"
    } > "${lock_tmp}"
    mv -f -- "${lock_tmp}" "${PAPER_LOCK}"
}

load_q4_paper_images() {
    local actual_archive_sha
    [[ "${PROFILE}" == "sygma-q4" ]] || die "load-paper is available only for SYGMA-Q4"
    [[ -f "${PAPER_ARCHIVE}" ]] || \
        die "post-acceptance-only Q4 paper archive is not distributed in this anonymous package: ${PAPER_ARCHIVE}"
    check_load_prerequisites
    require_command sha256sum
    require_command awk

    actual_archive_sha="$(file_sha256 "${PAPER_ARCHIVE}")"
    [[ "${actual_archive_sha}" == "${PAPER_ARCHIVE_SHA256}" ]] || \
        die "fixed paper archive checksum mismatch: expected ${PAPER_ARCHIVE_SHA256}, got ${actual_archive_sha}"

    note "Importing the verified Q4 paper archive into containerd namespace k8s.io"
    run_ctr images import --digests --platform "${TARGET_PLATFORM}" "${PAPER_ARCHIVE}"
    assert_ctr_digest "${PAPER_CORE_SOURCE}" "${PAPER_CORE_DIGEST}"
    assert_ctr_digest "${PAPER_OPERATOR_SOURCE}" "${PAPER_OPERATOR_DIGEST}"
    assert_ctr_digest "${PAPER_INSTALLER_SOURCE}" "${PAPER_INSTALLER_DIGEST}"

    run_ctr images tag --force "${PAPER_CORE_SOURCE}" "${CORE_IMAGE}"
    run_ctr images tag --force "${PAPER_OPERATOR_SOURCE}" "${OPERATOR_IMAGE}"
    run_ctr images tag --force "${PAPER_INSTALLER_SOURCE}" "${INSTALLER_IMAGE}"
    assert_ctr_digest "${CORE_IMAGE}" "${PAPER_CORE_DIGEST}"
    assert_ctr_digest "${OPERATOR_IMAGE}" "${PAPER_OPERATOR_DIGEST}"
    assert_ctr_digest "${INSTALLER_IMAGE}" "${PAPER_INSTALLER_DIGEST}"
    write_paper_lock
    note "Verified paper images are available under the neutral Q4 references"
}

deploy_profile() {
    local q3_core_digest_ref
    check_load_prerequisites
    require_command kubectl
    assert_local_images_loaded
    note "Running ${MANIFEST_DIR}/deploy.sh"
    (
        cd "${MANIFEST_DIR}"
        bash ./deploy.sh
    )
    if [[ "${PROFILE}" == "sygma-q3" ]]; then
        [[ -f "${IMAGE_LOCK}" ]] || die "Q3 digest lock is missing; run 'build' first"
        q3_core_digest_ref="$(locked_digest_ref core)"
        [[ -n "${q3_core_digest_ref}" ]] || die "Q3 core digest reference is missing from ${IMAGE_LOCK}"
        ctr_image_exists "${q3_core_digest_ref}" || \
            die "Q3 core digest reference is not loaded: ${q3_core_digest_ref}"
        note "Pinning the Q3 core DaemonSet to its imported OCI manifest digest"
        kubectl set image daemonset/core "core=${q3_core_digest_ref}" -n default
        kubectl rollout status daemonset/core -n default -w
    fi
}

run_all_single_node() {
    warn "'all' imports only into this node's containerd; use it only for a single-node cluster"
    build_local_images
    load_local_images
    deploy_profile
}

main() {
    local command="${1:-help}"
    [[ $# -le 1 ]] || die "expected exactly one command; see './local-images.sh help'"
    case "${command}" in
        build) build_local_images ;;
        load) load_local_images ;;
        deploy) deploy_profile ;;
        all) run_all_single_node ;;
        load-paper) load_q4_paper_images ;;
        help|-h|--help) usage ;;
        *) die "unknown command: ${command}; see './local-images.sh help'" ;;
    esac
}

main "$@"
