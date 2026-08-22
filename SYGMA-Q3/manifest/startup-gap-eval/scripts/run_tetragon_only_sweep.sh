#!/usr/bin/env bash
# Lightweight, non-publication sweep: one Tetragon-only trial (no warmup, no
# SYGMA arm) per application, across all 30 Hotel Reservation/Online Boutique
# profiles, purely to harvest application_distinct_syscall_types_uncovered_*
# for every container with the current core (app_sc_first_seen-enabled).
# Bypasses run_application_campaigns.sh's dual-arm publication gate on
# purpose -- this is a diagnostic sweep, not a publication-quality run.
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"

campaign_id="${CAMPAIGN_ID:-tetragon-only-sweep-$(date -u +%Y%m%dT%H%M%SZ)}"
results_root="${RESULTS_ROOT:-${eval_root}/results}"
namespace="${NAMESPACE:-sygma-gap-eval}"
node_name="${NODE_NAME:-master}"
redis_addr="${REDIS_ADDR:-172.16.0.120:6379}"

applications=(
    hotel-frontend hotel-geo hotel-profile hotel-rate hotel-recommendation
    hotel-reservation hotel-search hotel-user hotel-consul hotel-jaeger
    hotel-mongo-geo hotel-mongo-profile hotel-mongo-rate hotel-mongo-recommendation
    hotel-mongo-reservation hotel-mongo-user
    hotel-memcached-profile hotel-memcached-rate hotel-memcached-reserve
    boutique-ad boutique-cart boutique-checkout boutique-currency boutique-email
    boutique-frontend boutique-payment boutique-productcatalog
    boutique-recommendation boutique-shipping boutique-redis-cart
)

publication_dir="${eval_root}/../../artifacts/local/sygma-q3-local-publication"
if ! grep -qx 'state=COMPLETE' "${publication_dir}/STATUS" 2>/dev/null ||
   [[ ! -f "${publication_dir}/campaign-images.env" ]]; then
    publication_root="${eval_root}/published-images"
    publication_dir=""
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
[[ -n "${publication_dir}" ]] || { echo "error: no COMPLETE local or legacy application image environment found" >&2; exit 1; }
# shellcheck disable=SC1091
source "${publication_dir}/campaign-images.env"
echo "using publication: ${publication_dir}"

image_for_application() {
    local upper="${1^^}"
    local var_name="${upper//-/_}_IMAGE"
    printf '%s\n' "${!var_name}"
}

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] building native measurement tools once"
"${eval_root}/scripts/build.sh"

completed=0
for application in "${applications[@]}"; do
    carrier_image="$(image_for_application "${application}")"
    run_id="${application}-${campaign_id}"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] starting ${application} (run-id=${run_id})"
    python3 "${eval_root}/scripts/run_experiment.py" \
        --application "${application}" \
        --run-id "${run_id}" \
        --trials 1 --warmups 0 --arms tetragon \
        --duration-ms 5000 --evidence-hold-ms 5000 \
        --interval-us 1000 --map-poll-us 200 \
        --infrastructure-retries 2 --seed 20260802 \
        --namespace "${namespace}" --node "${node_name}" \
        --carrier-image "${carrier_image}" \
        --observer-image "${OBSERVER_IMAGE}" \
        --image-pull-policy Never \
        --redis-addr "${redis_addr}" \
        --kubectl kubectl \
        --results-root "${results_root}" \
        --skip-build
    completed=$((completed + 1))
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] completed ${application} (${completed}/${#applications[@]})"
done

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] sweep ${campaign_id} completed (${completed}/${#applications[@]} applications)"
