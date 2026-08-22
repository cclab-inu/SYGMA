#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly PROFILE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly EVAL_ROOT="${PROFILE_ROOT}/manifest/startup-gap-eval"
readonly BUILD_HELPER="${EVAL_ROOT}/scripts/build_application_image.sh"
readonly PROBE_BUILDER="${EVAL_ROOT}/scripts/build.sh"
readonly OUTPUT_DIR="${PROFILE_ROOT}/artifacts/local"
readonly ARCHIVE="${OUTPUT_DIR}/sygma-q3-workloads.tar"
readonly ARCHIVE_SHA256="${ARCHIVE}.sha256"
readonly IMAGE_LOCK="${OUTPUT_DIR}/sygma-q3-workloads.lock.json"
readonly SYSTEM_IMAGE_LOCK="${OUTPUT_DIR}/sygma-q3-artifact-v1-images.lock"
readonly LOCAL_PUBLICATION_DIR="${OUTPUT_DIR}/sygma-q3-local-publication"
readonly IMAGE_REPOSITORY="localhost/sygma-q3"
readonly IMAGE_TAG="artifact-v1"
readonly TARGET_PLATFORM="linux/amd64"
readonly CTR_BIN="${CTR_BIN:-ctr}"
readonly DRY_RUN_VALUE="${DRY_RUN:-0}"

readonly -a APPLICATIONS=(
    nginx
    redis
    httpd
    mysql
    hotel-frontend
    hotel-geo
    hotel-profile
    hotel-rate
    hotel-recommendation
    hotel-reservation
    hotel-search
    hotel-user
    boutique-ad
    boutique-cart
    boutique-checkout
    boutique-currency
    boutique-email
    boutique-frontend
    boutique-payment
    boutique-productcatalog
    boutique-recommendation
    boutique-shipping
    hotel-consul
    hotel-jaeger
    hotel-mongo-geo
    hotel-mongo-profile
    hotel-mongo-rate
    hotel-mongo-recommendation
    hotel-mongo-reservation
    hotel-mongo-user
    hotel-memcached-profile
    hotel-memcached-rate
    hotel-memcached-reserve
    boutique-redis-cart
)

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '==> %s\n' "$*"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

usage() {
    cat <<EOF
Usage: ./local-workloads.sh COMMAND

Build and distribute all 34 SYGMA-Q3 application images without publishing
them to a registry. This script never runs docker login or docker push.

Commands:
  build  Build every application image with build_application_image.sh, save
         one archive, and write its checksum, digest lock, and campaign env.
  load   Verify and import the archive into containerd's k8s.io namespace on
         this node. Run this command with the same files on every eligible
         Kubernetes node before starting a campaign.
  help   Show this help.

Generated files:
  ${ARCHIVE}
  ${ARCHIVE_SHA256}
  ${IMAGE_LOCK}
  ${LOCAL_PUBLICATION_DIR}/campaign-images.env

Image naming:
  localhost/sygma-q3/workload-<application>:artifact-v1

The build may anonymously pull the helper's pinned public base images when
they are absent from the local Docker cache. It never pushes derived images.

The Q3 publication harness requires IMAGE@sha256:DIGEST, not mutable tags.
Use each image's "digest_reference" and "environment_variable" from the JSON
lock, keep imagePullPolicy=Never, and import with --digests on every node.

Set DRY_RUN=1 to print the build or load operations without executing them.
Override only the containerd client path with CTR_BIN=/path/to/ctr if needed.
EOF
}

case "${DRY_RUN_VALUE}" in
    0|1) ;;
    *) die "DRY_RUN must be 0 or 1" ;;
esac

image_ref() {
    local application="$1"
    printf '%s/workload-%s:%s\n' \
        "${IMAGE_REPOSITORY}" "${application}" "${IMAGE_TAG}"
}

environment_variable() {
    local application="$1"
    local upper="${application^^}"
    printf '%s_IMAGE\n' "${upper//-/_}"
}

dockerfile_for() {
    printf '%s/images/Dockerfile.%s\n' "${EVAL_ROOT}" "$1"
}

base_image_for() {
    local application="$1"
    local dockerfile
    local base_image
    dockerfile="$(dockerfile_for "${application}")"
    base_image="$({
        awk -F= '/^ARG BASE_IMAGE=/ {sub(/^ARG BASE_IMAGE=/, ""); print; exit}' \
            "${dockerfile}"
    })"
    [[ "${base_image}" =~ @sha256:[0-9a-fA-F]{64}$ ]] || \
        die "${dockerfile} does not declare an immutable BASE_IMAGE digest"
    printf '%s\n' "${base_image}"
}

print_command() {
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
}

run_command() {
    if [[ "${DRY_RUN_VALUE}" == 1 ]]; then
        print_command "$@"
    else
        "$@"
    fi
}

run_ctr() {
    local -a command=("${CTR_BIN}" -n k8s.io "$@")
    if (( EUID != 0 )); then
        command=(sudo "${command[@]}")
    fi
    if [[ "${DRY_RUN_VALUE}" == 1 ]]; then
        print_command "${command[@]}"
    else
        "${command[@]}"
    fi
}

ctr_image_exists() {
    local expected="$1"
    run_ctr images list --quiet |
        awk -v expected="${expected}" '
            $0 == expected { found = 1 }
            END { exit(found ? 0 : 1) }
        '
}

validate_layout() {
    local application
    [[ -x "${BUILD_HELPER}" ]] || die "missing executable helper: ${BUILD_HELPER}"
    [[ -x "${PROBE_BUILDER}" ]] || die "missing executable probe builder: ${PROBE_BUILDER}"
    ((${#APPLICATIONS[@]} == 34)) || die "internal application list must contain 34 entries"

    for application in "${APPLICATIONS[@]}"; do
        [[ -f "$(dockerfile_for "${application}")" ]] || \
            die "missing Dockerfile for ${application}"
        base_image_for "${application}" >/dev/null
    done
}

ensure_amd64_host() {
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) die "this artifact is amd64-only; current host is $(uname -m)" ;;
    esac
}

check_build_prerequisites() {
    ensure_amd64_host
    require_command docker
    require_command python3
    require_command sha256sum
    require_command awk
    docker info >/dev/null 2>&1 || die "cannot access the Docker daemon"
}

check_load_prerequisites() {
    require_command "${CTR_BIN}"
    require_command python3
    require_command sha256sum
    if (( EUID != 0 )); then
        require_command sudo
    fi
}

assert_fresh_outputs_and_tags() {
    local application
    local path
    local ref

    for path in "${ARCHIVE}" "${ARCHIVE_SHA256}" "${IMAGE_LOCK}" \
        "${LOCAL_PUBLICATION_DIR}"; do
        [[ ! -e "${path}" ]] || \
            die "refusing to overwrite existing artifact: ${path}"
    done
    for application in "${APPLICATIONS[@]}"; do
        ref="$(image_ref "${application}")"
        if docker image inspect "${ref}" >/dev/null 2>&1; then
            die "refusing to overwrite existing local image: ${ref}"
        fi
    done
}

write_local_campaign_environment() {
    local workload_lock="$1"
    local publication_dir="$2"

    [[ -f "${SYSTEM_IMAGE_LOCK}" ]] || \
        die "system image lock is missing; run ./local-images.sh build first: ${SYSTEM_IMAGE_LOCK}"
    mkdir -- "${publication_dir}"
    python3 - \
        "${workload_lock}" \
        "${SYSTEM_IMAGE_LOCK}" \
        "${publication_dir}/campaign-images.env" <<'PY'
import json
import pathlib
import re
import shlex
import sys

workload_lock = pathlib.Path(sys.argv[1])
system_lock = pathlib.Path(sys.argv[2])
output = pathlib.Path(sys.argv[3])

workloads = json.loads(workload_lock.read_text(encoding="utf-8"))
system = {}
for line in system_lock.read_text(encoding="utf-8").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        system[key] = value

digest_pattern = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
observer = system.get("image.installer.digest_ref", "")
core = system.get("image.core.digest_ref", "")
if not digest_pattern.fullmatch(observer):
    raise SystemExit("system lock has no immutable installer digest reference")
if not digest_pattern.fullmatch(core):
    raise SystemExit("system lock has no immutable core digest reference")

images = workloads.get("images") or []
if len(images) != 34:
    raise SystemExit(f"expected 34 workload images, got {len(images)}")

exports = {
    "OBSERVER_IMAGE": observer,
    "SYGMA_CORE_IMAGE": core,
}
for image in images:
    variable = str(image.get("environment_variable", ""))
    reference = str(image.get("digest_reference", ""))
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*_IMAGE", variable):
        raise SystemExit(f"invalid workload environment variable: {variable!r}")
    if not digest_pattern.fullmatch(reference):
        raise SystemExit(f"invalid workload digest reference for {variable}")
    if variable in exports:
        raise SystemExit(f"duplicate environment variable: {variable}")
    exports[variable] = reference

lines = [
    "# Generated from the local system/workload digest locks; no registry publication.",
]
for key in ("OBSERVER_IMAGE", "SYGMA_CORE_IMAGE"):
    lines.append(f"export {key}={shlex.quote(exports.pop(key))}")
for key in sorted(exports):
    lines.append(f"export {key}={shlex.quote(exports[key])}")
output.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
    chmod 0644 "${publication_dir}/campaign-images.env"
    printf 'state=COMPLETE\nsource=local-archive-locks\n' \
        > "${publication_dir}/STATUS"
    chmod 0644 "${publication_dir}/STATUS"
}

prefetch_pinned_bases() {
    local application
    local base_image
    declare -A seen=()

    note "Checking the pinned public base images"
    for application in "${APPLICATIONS[@]}"; do
        base_image="$(base_image_for "${application}")"
        [[ -z "${seen[${base_image}]:-}" ]] || continue
        seen[${base_image}]=1

        if [[ "${DRY_RUN_VALUE}" == 1 ]]; then
            print_command docker pull --platform "${TARGET_PLATFORM}" "${base_image}"
        elif ! docker image inspect "${base_image}" >/dev/null 2>&1; then
            note "Pulling pinned base ${base_image}"
            docker pull --platform "${TARGET_PLATFORM}" "${base_image}"
        else
            note "Using cached pinned base ${base_image}"
        fi
    done
}

build_all_images() {
    local application
    local ref

    note "Building the shared static gap probe once"
    run_command "${PROBE_BUILDER}"

    for application in "${APPLICATIONS[@]}"; do
        ref="$(image_ref "${application}")"
        note "Building ${application} as ${ref}"
        run_command "${BUILD_HELPER}" \
            --application "${application}" \
            --image "${ref}" \
            --no-rebuild-probe
    done
}

write_lock_from_archive() {
    local archive_path="$1"
    local lock_path="$2"
    local archive_sha="$3"
    local metadata_path="$4"
    local probe_sha="$5"
    local helper_sha="$6"

    python3 - \
        "${archive_path}" "${lock_path}" "${archive_sha}" \
        "${metadata_path}" "${probe_sha}" "${helper_sha}" <<'PY'
import json
import pathlib
import re
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
lock_path = pathlib.Path(sys.argv[2])
archive_sha = sys.argv[3]
metadata_path = pathlib.Path(sys.argv[4])
probe_sha = sys.argv[5]
helper_sha = sys.argv[6]

records = []
for line_number, line in enumerate(metadata_path.read_text(encoding="utf-8").splitlines(), 1):
    fields = line.split("\t")
    if len(fields) != 5:
        raise SystemExit(f"invalid metadata line {line_number}")
    application, tag_ref, docker_id, base_image, env_var = fields
    records.append({
        "application": application,
        "tag_reference": tag_ref,
        "docker_image_id": docker_id,
        "base_image": base_image,
        "environment_variable": env_var,
    })

if len(records) != 34:
    raise SystemExit(f"expected 34 image records, got {len(records)}")

with tarfile.open(archive_path, "r") as archive:
    try:
        index = json.load(archive.extractfile("index.json"))
        docker_manifest = json.load(archive.extractfile("manifest.json"))
    except (KeyError, TypeError) as error:
        raise SystemExit(
            "docker save archive lacks OCI index.json/manifest.json; "
            "manifest digest locking is required by the Q3 harness"
        ) from error

descriptor_by_name = {}
for descriptor in index.get("manifests", []):
    annotations = descriptor.get("annotations") or {}
    name = annotations.get("io.containerd.image.name")
    digest = descriptor.get("digest")
    if name and digest:
        descriptor_by_name[name] = digest

config_by_name = {}
for item in docker_manifest:
    config_path = str(item.get("Config") or "")
    config_name = pathlib.PurePosixPath(config_path).name
    if not re.fullmatch(r"[0-9a-f]{64}", config_name):
        raise SystemExit(f"invalid image config path in archive: {config_path!r}")
    for repo_tag in item.get("RepoTags") or []:
        config_by_name[repo_tag] = "sha256:" + config_name

def lookup(mapping, reference):
    candidates = [reference]
    first = reference.split("/", 1)[0]
    if first != "localhost" and "." not in first and ":" not in first:
        candidates.append("docker.io/" + reference)
    for candidate in candidates:
        if candidate in mapping:
            return mapping[candidate]
    return None

digest_pattern = re.compile(r"sha256:[0-9a-f]{64}")
images = []
for record in records:
    tag_ref = record["tag_reference"]
    manifest_digest = lookup(descriptor_by_name, tag_ref)
    config_digest = lookup(config_by_name, tag_ref)
    if not manifest_digest or not digest_pattern.fullmatch(manifest_digest):
        raise SystemExit(f"missing OCI manifest digest for {tag_ref}")
    if not config_digest or not digest_pattern.fullmatch(config_digest):
        raise SystemExit(f"missing config digest for {tag_ref}")
    if record["docker_image_id"] != config_digest:
        raise SystemExit(
            f"Docker image ID/config digest mismatch for {tag_ref}: "
            f"{record['docker_image_id']} != {config_digest}"
        )
    repository = tag_ref.rsplit(":", 1)[0]
    images.append({
        **record,
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "digest_reference": repository + "@" + manifest_digest,
        "image_pull_policy": "Never",
    })

lock = {
    "format_version": 1,
    "profile": "sygma-q3",
    "artifact": "workloads",
    "artifact_tag": "artifact-v1",
    "platform": "linux/amd64",
    "archive": {
        "file": "sygma-q3-workloads.tar",
        "sha256": archive_sha,
    },
    "gap_probe_sha256": probe_sha,
    "build_helper_sha256": helper_sha,
    "harness_requirement": (
        "Set each environment_variable to digest_reference, import this exact "
        "archive with ctr --digests on every eligible node, and keep "
        "imagePullPolicy=Never. The Q3 publication harness rejects tag-only refs."
    ),
    "images": images,
}

lock_path.write_text(
    json.dumps(lock, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

create_archive_and_lock() {
    local archive_tmp="${ARCHIVE}.tmp.$$"
    local sha_tmp="${ARCHIVE_SHA256}.tmp.$$"
    local lock_tmp="${IMAGE_LOCK}.tmp.$$"
    local metadata_tmp="${OUTPUT_DIR}/.sygma-q3-workloads.metadata.$$"
    local publication_tmp="${LOCAL_PUBLICATION_DIR}.tmp.$$"
    local archive_sha
    local probe_sha
    local helper_sha
    local application
    local ref
    local image_id
    local base_image
    local env_var
    local -a image_refs=()

    if [[ "${DRY_RUN_VALUE}" == 1 ]]; then
        for application in "${APPLICATIONS[@]}"; do
            image_refs+=("$(image_ref "${application}")")
        done
        print_command mkdir -p "${OUTPUT_DIR}"
        print_command docker save --output "${ARCHIVE}" "${image_refs[@]}"
        printf 'DRY-RUN: generate %q and %q with OCI manifest/config digests\n' \
            "${ARCHIVE_SHA256}" "${IMAGE_LOCK}"
        printf 'DRY-RUN: generate local campaign environment under %q\n' \
            "${LOCAL_PUBLICATION_DIR}"
        return
    fi

    mkdir -p "${OUTPUT_DIR}"
    cleanup_archive_temps() {
        rm -f -- "${archive_tmp}" "${sha_tmp}" "${lock_tmp}" "${metadata_tmp}"
        rm -rf -- "${publication_tmp}"
    }
    trap cleanup_archive_temps RETURN

    : > "${metadata_tmp}"
    for application in "${APPLICATIONS[@]}"; do
        ref="$(image_ref "${application}")"
        image_refs+=("${ref}")
        image_id="$(docker image inspect --format '{{.Id}}' "${ref}")"
        base_image="$(base_image_for "${application}")"
        env_var="$(environment_variable "${application}")"
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "${application}" "${ref}" "${image_id}" "${base_image}" "${env_var}" \
            >> "${metadata_tmp}"
    done

    note "Saving all 34 workload images to ${ARCHIVE}"
    docker save --output "${archive_tmp}" "${image_refs[@]}"
    archive_sha="$(sha256sum "${archive_tmp}" | awk '{print $1}')"
    probe_sha="$(sha256sum "${EVAL_ROOT}/build/gap-probe" | awk '{print $1}')"
    helper_sha="$(sha256sum "${BUILD_HELPER}" | awk '{print $1}')"

    printf '%s  %s\n' "${archive_sha}" "$(basename "${ARCHIVE}")" > "${sha_tmp}"
    write_lock_from_archive \
        "${archive_tmp}" "${lock_tmp}" "${archive_sha}" \
        "${metadata_tmp}" "${probe_sha}" "${helper_sha}"
    write_local_campaign_environment "${lock_tmp}" "${publication_tmp}"

    mv -- "${archive_tmp}" "${ARCHIVE}"
    mv -- "${sha_tmp}" "${ARCHIVE_SHA256}"
    mv -- "${lock_tmp}" "${IMAGE_LOCK}"
    mv -- "${publication_tmp}" "${LOCAL_PUBLICATION_DIR}"
    chmod 0644 "${ARCHIVE}" "${ARCHIVE_SHA256}" "${IMAGE_LOCK}"
    trap - RETURN
    rm -f -- "${metadata_tmp}"
}

build_workloads() {
    validate_layout
    if [[ "${DRY_RUN_VALUE}" != 1 ]]; then
        check_build_prerequisites
        assert_fresh_outputs_and_tags
    fi
    prefetch_pinned_bases
    build_all_images
    create_archive_and_lock
    note "Workload bundle complete: ${ARCHIVE}"
    note "Use digest_reference values from ${IMAGE_LOCK} for publication runs"
}

verify_archive_files() {
    local expected
    local actual
    local lock_archive_sha

    [[ -f "${ARCHIVE}" ]] || die "archive not found; run 'build' first: ${ARCHIVE}"
    [[ -f "${ARCHIVE_SHA256}" ]] || \
        die "archive checksum not found: ${ARCHIVE_SHA256}"
    [[ -f "${IMAGE_LOCK}" ]] || die "image lock not found: ${IMAGE_LOCK}"

    expected="$(awk 'NF {print $1; exit}' "${ARCHIVE_SHA256}")"
    actual="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
    [[ "${actual}" == "${expected}" ]] || \
        die "archive checksum mismatch: expected ${expected}, got ${actual}"

    lock_archive_sha="$(python3 -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["archive"]["sha256"])' \
        "${IMAGE_LOCK}")"
    [[ "${actual}" == "${lock_archive_sha}" ]] || \
        die "lock/archive checksum mismatch: ${lock_archive_sha} != ${actual}"
}

lock_references() {
    python3 - "${IMAGE_LOCK}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    lock = json.load(stream)
images = lock.get("images") or []
if len(images) != 34:
    raise SystemExit(f"expected 34 locked images, got {len(images)}")
for image in images:
    print(image["tag_reference"] + "\t" + image["digest_reference"])
PY
}

verify_imported_images() {
    local tag_ref
    local digest_ref

    while IFS=$'\t' read -r tag_ref digest_ref; do
        ctr_image_exists "${tag_ref}" ||
            die "containerd tag reference is missing: ${tag_ref}"
        ctr_image_exists "${digest_ref}" ||
            die "containerd digest reference is missing: ${digest_ref}"
    done < <(lock_references)
}

load_workloads() {
    if [[ "${DRY_RUN_VALUE}" == 1 ]]; then
        print_command sha256sum -c "${ARCHIVE_SHA256}"
        run_ctr images import --digests --platform "${TARGET_PLATFORM}" "${ARCHIVE}"
        printf 'DRY-RUN: verify all 34 tag and digest references from %q\n' "${IMAGE_LOCK}"
        return
    fi

    check_load_prerequisites
    verify_archive_files
    note "Importing the workload archive into containerd namespace k8s.io"
    run_ctr images import --digests --platform "${TARGET_PLATFORM}" "${ARCHIVE}"
    verify_imported_images
    note "All 34 workload tag and digest references are available on this node"
    note "Repeat 'load' with the same archive, checksum, and lock on every eligible node"
}

main() {
    local command="${1:-help}"
    [[ $# -le 1 ]] || die "expected exactly one command; see './local-workloads.sh help'"
    case "${command}" in
        build) build_workloads ;;
        load) load_workloads ;;
        help|-h|--help) usage ;;
        *) die "unknown command: ${command}; see './local-workloads.sh help'" ;;
    esac
}

main "$@"
