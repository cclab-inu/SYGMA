#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"

publication_dir="${PUBLICATION_DIR:-}"
preflight_only=false

usage() {
    cat <<'EOF'
Usage:
  launch_application_campaign_nohup.sh [--publication-dir DIR] [--preflight-only]

The SYGMA observation-only stack must already be deployed. This launcher
starts an evaluation campaign under nohup for the applications selected via
APPLICATIONS (default: nginx redis httpd mysql; also supports the
hotel-{...} and boutique-{...} profiles -- see scripts/run_experiment.py's
APPLICATIONS list). If --publication-dir is omitted, the local archive-lock
environment is preferred, then the newest legacy STATUS=COMPLETE publication.

Optional environment variables:
  CAMPAIGN_ID NODE_NAME NAMESPACE REDIS_ADDR RESULTS_ROOT APPLICATIONS
  TRIALS WARMUPS DURATION_MS EVIDENCE_HOLD_MS INTERVAL_US MAP_POLL_US
  INFRASTRUCTURE_RETRIES SEED
  NOHUP_LOG_ROOT STARTUP_CHECK_SECONDS KUBECTL_BIN
  SYGMA_CORE_NAMESPACE SYGMA_CORE_DAEMONSET
  SYGMA_HOST_ROOT SYGMA_CORE_READY_TIMEOUT_SECONDS
EOF
}

while (($#)); do
    case "$1" in
        --publication-dir)
            publication_dir="${2:-}"
            shift 2
            ;;
        --preflight-only)
            preflight_only=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "${publication_dir}" ]]; then
    local_publication="${eval_root}/../../artifacts/local/sygma-q3-local-publication"
    if grep -qx 'state=COMPLETE' "${local_publication}/STATUS" 2>/dev/null &&
       [[ -f "${local_publication}/campaign-images.env" ]]; then
        publication_dir="${local_publication}"
    else
        publication_root="${eval_root}/published-images"
        if [[ -d "${publication_root}" ]]; then
            while IFS= read -r candidate_record; do
                candidate="${candidate_record#*|}"
                if grep -qx 'state=COMPLETE' "${candidate}/STATUS" 2>/dev/null &&
                   [[ -f "${candidate}/campaign-images.env" ]]; then
                    publication_dir="${candidate}"
                    break
                fi
            done < <(
                find "${publication_root}" -mindepth 2 -maxdepth 2 \
                    -type f -name STATUS -printf '%T@|%h\n' | sort -nr
            )
        fi
    fi
    if [[ -z "${publication_dir}" ]]; then
        echo "error: no COMPLETE local or legacy application image environment was found" >&2
        exit 1
    fi
fi
if [[ ! -d "${publication_dir}" ]]; then
    echo "error: publication directory does not exist: ${publication_dir}" >&2
    exit 1
fi
publication_dir="$(cd -- "${publication_dir}" && pwd)"

status_file="${publication_dir}/STATUS"
environment_file="${publication_dir}/campaign-images.env"
if ! grep -qx 'state=COMPLETE' "${status_file}" 2>/dev/null; then
    echo "error: publication is not COMPLETE: ${status_file}" >&2
    exit 1
fi
if [[ ! -f "${environment_file}" ]]; then
    echo "error: missing campaign image environment: ${environment_file}" >&2
    exit 1
fi

# The publication file contains only export statements produced by the
# audited image publisher.
# shellcheck disable=SC1090
source "${environment_file}"

export CAMPAIGN_ID="${CAMPAIGN_ID:-atomicity-apps-$(date -u +%Y%m%dT%H%M%SZ)-${BASHPID}-${RANDOM}}"
export NODE_NAME="${NODE_NAME:-master}"
export NAMESPACE="${NAMESPACE:-sygma-gap-eval}"
export REDIS_ADDR="${REDIS_ADDR:-172.16.0.120:6379}"
export RESULTS_ROOT="${RESULTS_ROOT:-${eval_root}/results}"
export APPLICATIONS="${APPLICATIONS:-nginx redis httpd mysql}"
export TRIALS="${TRIALS:-100}"
export WARMUPS="${WARMUPS:-20}"
export DURATION_MS="${DURATION_MS:-5000}"
export EVIDENCE_HOLD_MS="${EVIDENCE_HOLD_MS:-5000}"
export INTERVAL_US="${INTERVAL_US:-1000}"
export MAP_POLL_US="${MAP_POLL_US:-200}"
export INFRASTRUCTURE_RETRIES="${INFRASTRUCTURE_RETRIES:-2}"
export SEED="${SEED:-20260802}"
export IMAGE_PULL_POLICY=Never
export KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"

if [[ ! "${CAMPAIGN_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "error: invalid CAMPAIGN_ID: ${CAMPAIGN_ID}" >&2
    exit 2
fi

command -v "${KUBECTL_BIN}" >/dev/null 2>&1 || {
    echo "error: kubectl executable not found: ${KUBECTL_BIN}" >&2
    exit 1
}

read -r -a campaign_applications <<<"${APPLICATIONS}"
if ((${#campaign_applications[@]} == 0)); then
    echo "error: APPLICATIONS must select at least one application" >&2
    exit 2
fi
# Keep in sync with APPLICATIONS in scripts/run_experiment.py.
known_applications=(
    nginx redis httpd mysql
    hotel-frontend hotel-geo hotel-profile hotel-rate hotel-recommendation
    hotel-reservation hotel-search hotel-user
    boutique-ad boutique-cart boutique-checkout boutique-currency
    boutique-email boutique-frontend boutique-payment boutique-productcatalog
    boutique-recommendation boutique-shipping
    hotel-consul hotel-jaeger
    hotel-mongo-geo hotel-mongo-profile hotel-mongo-rate hotel-mongo-recommendation
    hotel-mongo-reservation hotel-mongo-user
    hotel-memcached-profile hotel-memcached-rate hotel-memcached-reserve
    boutique-redis-cart
)
declare -A is_known_application=()
for application in "${known_applications[@]}"; do
    is_known_application[${application}]=1
done

declare -A selected_applications=()
for application in "${campaign_applications[@]}"; do
    if [[ -z "${is_known_application[${application}]:-}" ]]; then
        echo "error: unsupported application in APPLICATIONS: ${application}" >&2
        exit 2
    fi
    if [[ -n "${selected_applications[${application}]:-}" ]]; then
        echo "error: duplicate application in APPLICATIONS: ${application}" >&2
        exit 2
    fi
    selected_applications[${application}]=1
done

# Fail before creating a nohup process or result directory when the node still
# runs the historical mutable/legacy core. The full runner repeats these gates
# through its privileged observer and records the detailed map ABI metadata.
core_namespace="${SYGMA_CORE_NAMESPACE:-default}"
core_daemonset="${SYGMA_CORE_DAEMONSET:-core}"
printf 'preflight: checking SYGMA core %s/%s on node %s\n' \
    "${core_namespace}" "${core_daemonset}" "${NODE_NAME}"
"${KUBECTL_BIN}" rollout status "daemonset/${core_daemonset}" \
    -n "${core_namespace}" --timeout=60s

core_image="$(
    "${KUBECTL_BIN}" get daemonset "${core_daemonset}" \
        -n "${core_namespace}" \
        -o jsonpath='{.spec.template.spec.containers[?(@.name=="core")].image}'
)"
if [[ ! "${core_image}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "error: SYGMA core image is not pinned by digest: ${core_image:-<missing>}" >&2
    exit 1
fi

core_pod="$(
    "${KUBECTL_BIN}" get pods -n "${core_namespace}" \
        -l container=core --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}'
)"
if [[ -z "${core_pod}" ]]; then
    echo "error: no running SYGMA core Pod was found" >&2
    exit 1
fi
core_node="$(
    "${KUBECTL_BIN}" get pod "${core_pod}" -n "${core_namespace}" \
        -o jsonpath='{.spec.nodeName}'
)"
if [[ "${core_node}" != "${NODE_NAME}" ]]; then
    echo "error: SYGMA core Pod is on ${core_node}, expected ${NODE_NAME}" >&2
    exit 1
fi
core_image_id="$(
    "${KUBECTL_BIN}" get pod "${core_pod}" -n "${core_namespace}" \
        -o jsonpath='{.status.containerStatuses[?(@.name=="core")].imageID}'
)"
requested_core_digest="${core_image##*@}"
if [[ "${core_image_id}" != *"${requested_core_digest}"* ]]; then
    echo "error: running core imageID does not match ${requested_core_digest}: ${core_image_id}" >&2
    exit 1
fi

core_ready_timeout="${SYGMA_CORE_READY_TIMEOUT_SECONDS:-90}"
if [[ ! "${core_ready_timeout}" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: SYGMA_CORE_READY_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 2
fi
core_ready_deadline=$((SECONDS + core_ready_timeout))
core_ready_marker='SYGMA observation mode ready'
core_post_ready_marker='dedicated policy-entry probes'
core_observation_ready() {
    local logs="$1"
    grep -Fq "${core_ready_marker}" <<<"${logs}" ||
        grep -Fq "${core_post_ready_marker}" <<<"${logs}"
}
core_logs="$(
    "${KUBECTL_BIN}" logs -n "${core_namespace}" "${core_pod}" \
        -c core 2>/dev/null || true
)"
if ! core_observation_ready "${core_logs}"; then
    printf 'preflight: waiting up to %ss for SYGMA observation readiness\n' \
        "${core_ready_timeout}"
fi
while ! core_observation_ready "${core_logs}" &&
      ((SECONDS < core_ready_deadline)); do
    sleep 1
    core_logs="$(
        "${KUBECTL_BIN}" logs -n "${core_namespace}" "${core_pod}" \
            -c core --tail=400 2>/dev/null || true
    )"
done
if ! core_observation_ready "${core_logs}"; then
    echo "error: SYGMA core did not expose startup or post-ready activity within ${core_ready_timeout}s" >&2
    printf '%s\n' "${core_logs}" | tail -n 40 >&2
    exit 1
fi
if grep -Fq "${core_ready_marker}" <<<"${core_logs}"; then
    printf 'preflight: SYGMA startup readiness marker observed\n'
else
    # The one-time startup line may be removed by kubelet log rotation. The
    # Analyzer ticker is constructed only after all observation kprobes are
    # attached and the readiness gate is enabled, so its current-container log
    # is durable evidence that the same core process crossed that boundary.
    printf 'preflight: SYGMA post-ready activity observed (startup log rotated)\n'
fi

audited_core="${eval_root}/build/sygma-core-current"
if [[ ! -f "${audited_core}" ]]; then
    echo "error: missing audited core: ${audited_core}" >&2
    exit 1
fi
expected_core_hash="$(sha256sum "${audited_core}" | awk '{print $1}')"
live_core_hash="$(
    "${KUBECTL_BIN}" exec -n "${core_namespace}" "${core_pod}" -c core -- \
        sha256sum /usr/daemon/core | awk 'NF {print $1; exit}'
)"
if [[ "${live_core_hash}" != "${expected_core_hash}" ]]; then
    echo "error: running core hash ${live_core_hash:-<missing>} does not match audited ${expected_core_hash}" >&2
    exit 1
fi

# Keep in sync with SYGMA_LEGACY_REQUIRED_PINNED_MAPS / SYGMA_TYPED_POLICY_
# PINNED_MAPS / APPLICATION_SYSCALL_PINNED_MAPS in scripts/run_experiment.py.
required_core_maps=(
    syscall_graph_map execution_time_map pid_mount_ns_map
    process_state_map tid_to_namespace collection_mode_map
    collection_graph_map transition_check_count
    blocked_history observed_transition_map policy_config_map policy_state_rule_map
    policy_state_transition_map
    app_cgroups app_tids app_sc_bins app_sc_counts app_sc_meta
)
"${KUBECTL_BIN}" exec -n "${core_namespace}" "${core_pod}" -c core -- \
    /bin/sh -ceu '
        missing=0
        for map_name in "$@"; do
            map_path="/sys/fs/bpf/sygma/${map_name}"
            if [ ! -e "${map_path}" ]; then
                echo "missing required SYGMA map: ${map_path}" >&2
                missing=1
            fi
        done
        exit "${missing}"
    ' sh "${required_core_maps[@]}"

host_root="${SYGMA_HOST_ROOT:-/}"
if [[ "${host_root}" != /* ]]; then
    echo "error: SYGMA_HOST_ROOT must be an absolute path: ${host_root}" >&2
    exit 2
fi
host_prefix="${host_root%/}"

component_names=(hook tracer wrapper nri_plugin)
local_component_paths=(
    "${eval_root}/build/sygma-hook"
    "${eval_root}/build/sygma-tracer-current"
    "${eval_root}/build/sygma-wrapper-current"
    "${eval_root}/build/sygma-nri-current"
)
host_component_paths=(
    "${host_prefix}/usr/local/bin/sygma-hook"
    "${host_prefix}/usr/local/bin/sygma-tracer"
    "${host_prefix}/opt/sygma/wrapper"
    "${host_prefix}/opt/nri/plugins/00-sygma"
)

for index in "${!component_names[@]}"; do
    component="${component_names[${index}]}"
    local_path="${local_component_paths[${index}]}"
    host_path="${host_component_paths[${index}]}"
    if [[ ! -f "${local_path}" ]]; then
        echo "error: missing audited ${component}: ${local_path}" >&2
        exit 1
    fi
    if [[ ! -f "${host_path}" ]]; then
        echo "error: missing installed ${component}: ${host_path}" >&2
        exit 1
    fi
    local_hash="$(sha256sum "${local_path}" | awk '{print $1}')"
    host_hash="$(sha256sum "${host_path}" | awk '{print $1}')"
    if [[ "${host_hash}" != "${local_hash}" ]]; then
        echo "error: ${component} hash mismatch: audited=${local_hash} installed=${host_hash}" >&2
        echo "error: run scripts/install_staged_observation_components.sh and restart containerd" >&2
        exit 1
    fi
done

printf 'preflight: SYGMA core image/hash/maps and host component hashes PASS\n'
printf 'publication: %s\n' "${publication_dir}"

if [[ "${preflight_only}" == true ]]; then
    exit 0
fi

for application in "${campaign_applications[@]}"; do
    run_dir="${RESULTS_ROOT}/${application}-${CAMPAIGN_ID}"
    if [[ -e "${run_dir}" ]]; then
        echo "error: result directory already exists: ${run_dir}" >&2
        exit 1
    fi
done

log_root="${NOHUP_LOG_ROOT:-${eval_root}/nohup-logs}"
log_dir="${log_root}/${CAMPAIGN_ID}"
startup_check_seconds="${STARTUP_CHECK_SECONDS:-2}"
if [[ ! "${startup_check_seconds}" =~ ^[0-9]+$ ]]; then
    echo "error: STARTUP_CHECK_SECONDS must be a non-negative integer" >&2
    exit 2
fi
if [[ -e "${log_dir}" ]]; then
    echo "error: log directory already exists: ${log_dir}" >&2
    exit 1
fi
mkdir -p -- "${log_dir}"

nohup "${eval_root}/scripts/run_application_campaigns.sh" \
    >"${log_dir}/campaign.log" 2>&1 </dev/null &

campaign_pid=$!
printf '%s\n' "${campaign_pid}" >"${log_dir}/pid"
printf '%s\n' "${CAMPAIGN_ID}" >"${log_dir}/campaign-id"

sleep "${startup_check_seconds}"

if kill -0 "${campaign_pid}" 2>/dev/null; then
    # Publish latest only after the child survives its startup gates. A second
    # launcher rejected by the campaign flock must not hide the active run's
    # log behind a failed latest link.
    ln -sfn -- "${log_dir}" "${log_root}/latest"
    printf 'STARTED\nCAMPAIGN_ID=%s\nPID=%s\nLOG=%s\nRESULTS=%s\n' \
        "${CAMPAIGN_ID}" \
        "${campaign_pid}" \
        "${log_dir}/campaign.log" \
        "${RESULTS_ROOT}"
    exit 0
fi

echo "error: campaign exited during startup; last log lines follow" >&2
tail -n 120 "${log_dir}/campaign.log" >&2
exit 1
