#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"
repo_root="$(cd -- "${eval_root}/../.." && pwd)"

default_repository_prefix="localhost/sygma-q3"
system_image_lock="${SYSTEM_IMAGE_LOCK:-${repo_root}/artifacts/local/sygma-q3-artifact-v1-images.lock}"
default_base_image=""
if [[ -f "${system_image_lock}" ]]; then
    while IFS='=' read -r key value; do
        if [[ "${key}" == "image.installer.digest_ref" ]]; then
            default_base_image="${value}"
            break
        fi
    done < "${system_image_lock}"
fi

base_image="${default_base_image}"
repository_prefix="${default_repository_prefix}"
image_tag="observation-$(date -u +%Y%m%dT%H%M%SZ)-${BASHPID}-${RANDOM}"
output_image=""
output_dir=""
build_only=false
dry_run=false

docker_bin="${DOCKER_BIN:-docker}"

temporary_dir=""
container_id=""
environment_tmp=""
output_dir_created=false
completed=false

usage() {
    cat >&2 <<'EOF'
Usage:
  build_observation_core_image.sh [OPTIONS]

Build, verify, push, resolve, and pull back the audited observation-only SYGMA
core image. By default it publishes a unique linux/amd64 tag to:

  localhost/sygma-q3/sygma-core-observation

Options:
  --base-image IMAGE@sha256:DIGEST
  --repository-prefix REGISTRY/NAMESPACE
  --image-tag UNIQUE_TAG
  --image FULLY_QUALIFIED_OUTPUT_TAG
  --output-dir DIR
  --build-only                 Build and verify locally without pushing
  --dry-run                    Print resolved settings without Docker access
  -h, --help

--image overrides --repository-prefix and --image-tag. The default immutable
base defaults to the installer digest recorded by the canonical local system
build. Run ../../local-images.sh build first or pass --base-image explicitly.
This legacy publisher is not used by the anonymous archive workflow.
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

timestamp() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

cleanup() {
    local status="$?"

    if [[ -n "${container_id}" ]]; then
        "${docker_bin}" container rm -f "${container_id}" \
            >/dev/null 2>&1 || true
    fi
    if [[ -n "${temporary_dir}" && -d "${temporary_dir}" ]]; then
        rm -rf -- "${temporary_dir}"
    fi
    if [[ -n "${environment_tmp}" && -e "${environment_tmp}" ]]; then
        rm -f -- "${environment_tmp}"
    fi
    if [[ "${output_dir_created}" == true ]]; then
        if [[ "${completed}" == true && ${status} -eq 0 ]]; then
            printf 'state=COMPLETE\nfinished_at=%s\n' "$(timestamp)" \
                >"${output_dir}/STATUS"
        else
            printf 'state=FAILED\nexit_code=%d\nfinished_at=%s\n' \
                "${status}" "$(timestamp)" >"${output_dir}/STATUS"
        fi
    fi
}

trap cleanup EXIT

while (($#)); do
    case "$1" in
        --base-image)
            (($# >= 2)) || fail "--base-image requires a value"
            base_image="$2"
            shift 2
            ;;
        --repository-prefix)
            (($# >= 2)) || fail "--repository-prefix requires a value"
            repository_prefix="$2"
            shift 2
            ;;
        --image-tag)
            (($# >= 2)) || fail "--image-tag requires a value"
            image_tag="$2"
            shift 2
            ;;
        --image)
            (($# >= 2)) || fail "--image requires a value"
            output_image="$2"
            shift 2
            ;;
        --output-dir)
            (($# >= 2)) || fail "--output-dir requires a value"
            output_dir="$2"
            shift 2
            ;;
        --build-only)
            build_only=true
            shift
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

repository_prefix="${repository_prefix%/}"
if [[ -z "${output_image}" ]]; then
    output_image="${repository_prefix}/sygma-core-observation:${image_tag}"
else
    image_tag="${output_image##*:}"
fi

if [[ ! "${base_image}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    fail "--base-image must use an immutable lowercase sha256 digest; run the profile local-images.sh build first"
fi
if [[ ! "${image_tag}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
    fail "output image tag is not a valid Docker tag"
fi
if [[ ! "${output_image}" =~ ^[^[:space:]@]+:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
    fail "--image must be a non-digest image tag without whitespace"
fi
output_registry="${output_image%%/*}"
if [[ "${output_image}" != */* ||
      ( "${output_registry}" != "localhost" &&
        "${output_registry}" != *.* && "${output_registry}" != *:* ) ]]; then
    fail "output image must include an explicit registry host such as docker.io"
fi

if [[ -z "${output_dir}" ]]; then
    output_dir="${eval_root}/published-core-images/${image_tag}"
fi

if [[ "${dry_run}" == true ]]; then
    printf 'base_image=%s\noutput_image=%s\nmode=%s\noutput_dir=%s\n' \
        "${base_image}" "${output_image}" \
        "$([[ "${build_only}" == true ]] && printf build-only || printf publish)" \
        "${output_dir}"
    exit 0
fi

for tool in "${docker_bin}" awk cmp mktemp sed sha256sum sort tee; do
    command -v "${tool}" >/dev/null 2>&1 || \
        fail "required tool is missing: ${tool}"
done

audited_core="${eval_root}/build/sygma-core-current"
source_core="${repo_root}/sygma_eBPF/core"
if [[ ! -f "${audited_core}" ]] || ! cmp -s "${audited_core}" "${source_core}"; then
    fail "staged core does not match sygma_eBPF/core; run stage_observation_stack.sh"
fi

if [[ "${build_only}" != true ]]; then
    if [[ -e "${output_dir}" ]]; then
        fail "output directory already exists: ${output_dir}"
    fi
    mkdir -p -- "$(dirname -- "${output_dir}")"
    mkdir -- "${output_dir}"
    output_dir_created=true
    printf 'state=RUNNING\nstarted_at=%s\n' "$(timestamp)" \
        >"${output_dir}/STATUS"

    # A unique default tag makes collisions extremely unlikely. If an explicit
    # tag already resolves, fail instead of overwriting registry provenance.
    if "${docker_bin}" buildx imagetools inspect "${output_image}" \
        --format '{{.Manifest.Digest}}' >/dev/null 2>&1; then
        fail "destination tag already exists in the registry: ${output_image}"
    fi
fi

"${docker_bin}" build \
    --platform linux/amd64 \
    --build-arg "BASE_IMAGE=${base_image}" \
    -f "${repo_root}/sygma_eBPF/Dockerfile.observation-eval" \
    -t "${output_image}" \
    "${repo_root}/sygma_eBPF"

local_platform="$(
    "${docker_bin}" image inspect --format '{{.Os}}/{{.Architecture}}' \
        "${output_image}"
)"
[[ "${local_platform}" == "linux/amd64" ]] || \
    fail "core image must be linux/amd64, got ${local_platform}"
local_image_id="$(
    "${docker_bin}" image inspect --format '{{.Id}}' "${output_image}"
)"
[[ "${local_image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    fail "core image has an invalid local config digest"

temporary_dir="$(mktemp -d /tmp/sygma-core-publish.XXXXXX)"
container_id="$("${docker_bin}" container create --platform linux/amd64 "${output_image}")"

"${docker_bin}" container cp \
    "${container_id}:/usr/daemon/core" "${temporary_dir}/core"
if ! cmp -s "${audited_core}" "${temporary_dir}/core"; then
    fail "image core differs from the audited trust anchor"
fi

# The campaign runner hashes the live binary with `kubectl exec ... sha256sum`.
# Reject a base image that cannot satisfy that runtime attestation contract.
audited_hash="$(sha256sum "${audited_core}" | awk '{print $1}')"
image_hash="$(
    "${docker_bin}" run --rm --platform linux/amd64 --entrypoint sha256sum \
        "${output_image}" /usr/daemon/core | awk 'NF {print $1; exit}'
)"
if [[ "${image_hash}" != "${audited_hash}" ]]; then
    fail "image cannot attest /usr/daemon/core with sha256sum, or hash differs"
fi

printf 'verified byte-identical observation core in %s\n' "${output_image}"
sha256sum "${audited_core}" "${temporary_dir}/core"

if [[ "${build_only}" == true ]]; then
    printf 'build-only complete; no image was pushed\n'
    exit 0
fi

push_log="${output_dir}/push.log"
"${docker_bin}" image push --platform linux/amd64 "${output_image}" \
    2>&1 | tee "${push_log}"

mapfile -t push_digests < <(
    sed -nE 's/.*digest: (sha256:[0-9a-f]{64}).*/\1/p' \
        "${push_log}" | sort -u
)
if ((${#push_digests[@]} != 1)); then
    fail "expected one push-reported manifest digest, found ${#push_digests[@]}"
fi
push_digest="${push_digests[0]}"

manifest_metadata="$(
    "${docker_bin}" buildx imagetools inspect "${output_image}" \
        --format '{{printf "%s|%s\n" .Manifest.MediaType .Manifest.Digest}}'
)"
IFS='|' read -r media_type registry_digest <<<"${manifest_metadata}"
case "${media_type}" in
    application/vnd.oci.image.manifest.v1+json|\
    application/vnd.docker.distribution.manifest.v2+json)
        ;;
    *)
        fail "registry returned a non-single-platform media type: ${media_type:-<missing>}"
        ;;
esac
[[ "${registry_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    fail "registry returned an invalid core manifest digest"
[[ "${registry_digest}" == "${push_digest}" ]] || \
    fail "registry digest differs from the push-reported digest"

canonical_image="${output_image%:*}@${registry_digest}"
canonical_metadata="$(
    "${docker_bin}" buildx imagetools inspect "${canonical_image}" \
        --format '{{printf "%s|%s\n" .Manifest.MediaType .Manifest.Digest}}'
)"
[[ "${canonical_metadata}" == "${media_type}|${registry_digest}" ]] || \
    fail "canonical digest reference did not resolve to the pushed manifest"

"${docker_bin}" image pull --platform linux/amd64 "${canonical_image}" \
    2>&1 | tee "${output_dir}/roundtrip-pull.log"
roundtrip_image_id="$(
    "${docker_bin}" image inspect --format '{{.Id}}' "${canonical_image}"
)"
roundtrip_platform="$(
    "${docker_bin}" image inspect --format '{{.Os}}/{{.Architecture}}' \
        "${canonical_image}"
)"
[[ "${roundtrip_image_id}" == "${local_image_id}" ]] || \
    fail "registry round trip changed the core image config digest"
[[ "${roundtrip_platform}" == "linux/amd64" ]] || \
    fail "registry round trip changed the core image platform"

environment_tmp="$(mktemp "${output_dir}/.core-image.env.XXXXXX")"
{
    printf '# Generated by build_observation_core_image.sh at %s\n' "$(timestamp)"
    printf 'export SYGMA_CORE_IMAGE=%q\n' "${canonical_image}"
    printf 'export SYGMA_CORE_LOCAL_CONFIG_ID=%q\n' "${local_image_id}"
    printf 'export SYGMA_CORE_BINARY_SHA256=%q\n' "sha256:${audited_hash}"
} >"${environment_tmp}"
chmod 0644 "${environment_tmp}"
mv -- "${environment_tmp}" "${output_dir}/core-image.env"
environment_tmp=""

{
    printf 'tagged_reference=%s\n' "${output_image}"
    printf 'canonical_reference=%s\n' "${canonical_image}"
    printf 'manifest_media_type=%s\n' "${media_type}"
    printf 'local_config_digest=%s\n' "${local_image_id}"
    printf 'core_binary_sha256=sha256:%s\n' "${audited_hash}"
    printf 'base_image=%s\n' "${base_image}"
} >"${output_dir}/publication.txt"

completed=true
printf 'published and verified observation core\n'
printf 'CORE_IMAGE=%s\n' "${canonical_image}"
printf 'Environment file: %s\n' "${output_dir}/core-image.env"
printf 'Publication:      %s\n' "${output_dir}/publication.txt"
