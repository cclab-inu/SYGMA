#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"

campaign_id="${CAMPAIGN_ID:-atomicity-$(date -u +%Y%m%dT%H%M%SZ)}"
results_root="${RESULTS_ROOT:-${eval_root}/results}"
namespace="${NAMESPACE:-sygma-gap-eval}"
node_name="${NODE_NAME:-master}"
redis_addr="${REDIS_ADDR:-172.16.0.120:6379}"
trials="${TRIALS:-100}"
warmups="${WARMUPS:-20}"
duration_ms="${DURATION_MS:-5000}"
evidence_hold_ms="${EVIDENCE_HOLD_MS:-5000}"
interval_us="${INTERVAL_US:-1000}"
map_poll_us="${MAP_POLL_US:-200}"
infrastructure_retries="${INFRASTRUCTURE_RETRIES:-2}"
seed="${SEED:-20260802}"
image_pull_policy="${IMAGE_PULL_POLICY:-Never}"
python_bin="${PYTHON_BIN:-python3}"
kubectl_bin="${KUBECTL_BIN:-kubectl}"
lock_file="${LOCK_FILE:-/tmp/sygma-startup-gap-eval.application-campaign.lock}"
application_list="${APPLICATIONS:-nginx redis httpd mysql}"

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

read -r -a campaign_applications <<<"${application_list}"
if ((${#campaign_applications[@]} == 0)); then
    printf 'error: APPLICATIONS must select at least one application\n' >&2
    exit 2
fi
declare -A selected_applications=()
for application in "${campaign_applications[@]}"; do
    if [[ -z "${is_known_application[${application}]:-}" ]]; then
        printf 'error: unsupported application in APPLICATIONS: %s\n' \
            "${application}" >&2
        exit 2
    fi
    if [[ -n "${selected_applications[${application}]:-}" ]]; then
        printf 'error: duplicate application in APPLICATIONS: %s\n' \
            "${application}" >&2
        exit 2
    fi
    selected_applications[${application}]=1
done
application_count="${#campaign_applications[@]}"

current_child_pid=""
current_application=""
current_run_dir=""
completed_applications=0

timestamp() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

require_digest_image() {
    local variable_name="$1"
    local image_reference="${!variable_name:-}"

    [[ -n "${image_reference}" ]] || \
        fail "${variable_name} must be set to IMAGE@sha256:DIGEST"
    [[ "${image_reference}" =~ ^.+@sha256:[[:xdigit:]]{64}$ ]] || \
        fail "${variable_name} must end in @sha256:<64 hex characters>"
}

require_unsigned_integer() {
    local name="$1"
    local value="$2"
    local minimum="$3"

    [[ "${value}" =~ ^[0-9]+$ ]] || fail "${name} must be an integer"
    (( 10#${value} >= minimum )) || fail "${name} must be >= ${minimum}"
}

application_image_variable() {
    # hotel-frontend -> HOTEL_FRONTEND_IMAGE
    local upper="${1^^}"
    printf '%s_IMAGE\n' "${upper//-/_}"
}

image_for_application() {
    [[ -n "${is_known_application[$1]:-}" ]] || fail "unsupported application: $1"
    local variable_name
    variable_name="$(application_image_variable "$1")"
    printf '%s\n' "${!variable_name}"
}

print_command() {
    printf 'command:'
    printf ' %q' "$@"
    printf '\n'
}

check_publication_result() {
    local run_dir="$1"
    local application="$2"
    local summary_path="${run_dir}/summary.json"

    if [[ -e "${run_dir}/RUN_FAILED.txt" ]]; then
        printf 'error: %s exists\n' "${run_dir}/RUN_FAILED.txt" >&2
        return 1
    fi
    if [[ -e "${run_dir}/CLEANUP_FAILED.txt" ]]; then
        printf 'error: %s exists\n' "${run_dir}/CLEANUP_FAILED.txt" >&2
        return 1
    fi
    if [[ ! -f "${summary_path}" ]]; then
        printf 'error: missing campaign summary: %s\n' "${summary_path}" >&2
        return 1
    fi

    "${python_bin}" - "${summary_path}" "${trials}" "${warmups}" \
        "${application}" <<'PY'
import json
import pathlib
import sys

summary_path = pathlib.Path(sys.argv[1])
expected_trials = int(sys.argv[2])
expected_warmups = int(sys.argv[3])
application = sys.argv[4]

with summary_path.open(encoding="utf-8") as stream:
    summary = json.load(stream)

metadata_path = summary_path.parent / "metadata.json"
with metadata_path.open(encoding="utf-8") as stream:
    metadata = json.load(stream)

infrastructure_path = summary_path.parent / "infrastructure-failures.jsonl"
infrastructure_failures = []
if infrastructure_path.exists():
    with infrastructure_path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                infrastructure_failures.append(json.loads(line))

failures = []


def require(condition, message):
    if not condition:
        failures.append(message)


overall = summary.get("overall", {})
by_backend = summary.get("by_backend", {})
paired = summary.get("paired_additional_uncovered_attempts", {})
atomicity = summary.get("sygma_atomicity", {})
by_application = summary.get("by_application", {})
retry_observation = metadata.get("infrastructure_retry_observation", {})

require(summary.get("schema_version") == 4, "summary schema is not v4")
require(
    summary.get("measurement") == "application_lineage_syscalls",
    "summary is not application-lineage syscall measurement",
)
require(overall.get("total") == 2 * expected_trials, "measured arm count mismatch")
require(overall.get("n") == 2 * expected_trials, "not all measured trials are valid")
require(overall.get("invalid") == 0, "invalid measured trials are present")
require(overall.get("censored") == 0, "censored trials are present")
require(overall.get("warmup") == 2 * expected_warmups, "warm-up arm count mismatch")

for backend in ("sygma", "tetragon"):
    group = by_backend.get(backend, {})
    require(group.get("total") == expected_trials, f"{backend} measured count mismatch")
    require(group.get("n") == expected_trials, f"{backend} valid count mismatch")
    require(group.get("invalid") == 0, f"{backend} has invalid trials")
    require(group.get("censored") == 0, f"{backend} has censored trials")
    require(group.get("warmup") == expected_warmups, f"{backend} warm-up count mismatch")

require(set(by_application) == {application}, "summary application grouping mismatch")
application_group = by_application.get(application, {})
for backend in ("sygma", "tetragon"):
    group = application_group.get(backend, {})
    require(group.get("total") == expected_trials, f"{application}/{backend} measured count mismatch")
    require(group.get("n") == expected_trials, f"{application}/{backend} valid count mismatch")
    require(group.get("invalid") == 0, f"{application}/{backend} has invalid trials")
require(paired.get("candidate_pairs") == expected_trials, "candidate pair count mismatch")
require(paired.get("n") == expected_trials, "not all measured pairs are usable")
require(paired.get("excluded") == 0, "one or more measured pairs were excluded")
require(atomicity.get("measured_trials") == expected_trials, "SYGMA atomicity trial count mismatch")
require(atomicity.get("proven_trials") == expected_trials, "not every SYGMA trial proves atomicity")
require(atomicity.get("violation_trials") == 0, "SYGMA atomicity violation detected")
require(atomicity.get("unevaluable_trials") == 0, "unevaluable SYGMA atomicity trial detected")
require(atomicity.get("publication_eligible") is True, "SYGMA atomicity publication gate failed")
require(
    retry_observation.get("failure_attempts", 0) == len(infrastructure_failures),
    "infrastructure failure provenance count mismatch",
)
require(
    all(
        trial.get("failure_class")
        == "sygma_prestart_start_error_before_application"
        for trial in infrastructure_failures
    ),
    "infrastructure failure log contains a non-retryable class",
)

if failures:
    print("publication gate: FAIL", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    raise SystemExit(1)

print(
    "publication gate: PASS "
    f"({application}, {expected_trials} valid pairs, "
    f"{expected_trials} SYGMA atomicity proofs, "
    f"{len(infrastructure_failures)} retained infrastructure failures, "
    f"{retry_observation.get('replacement_attempts_started', 0)} replacements)"
)
PY
}

handle_signal() {
    local signal_name="$1"
    local exit_code="$2"

    trap - INT TERM
    printf '[%s] received %s while running %s; stopping the active runner\n' \
        "$(timestamp)" "${signal_name}" "${current_application:-setup}" >&2
    if [[ -n "${current_child_pid}" ]] && kill -0 "${current_child_pid}" 2>/dev/null; then
        # SIGINT lets Python unwind through run_experiment.py's cleanup block.
        kill -INT "${current_child_pid}" 2>/dev/null || true
        wait "${current_child_pid}" 2>/dev/null || true
    fi
    if [[ -n "${current_run_dir}" && -d "${current_run_dir}" ]]; then
        printf 'signal=%s\ninterrupted_at=%s\n' \
            "${signal_name}" "$(timestamp)" \
            >"${current_run_dir}/WRAPPER_INTERRUPTED.txt"
    fi
    exit "${exit_code}"
}

report_exit() {
    local status="$?"

    if (( status == 0 )); then
        printf '[%s] campaign %s completed (%d/%d applications)\n' \
            "$(timestamp)" "${campaign_id}" "${completed_applications}" \
            "${application_count}"
    else
        printf '[%s] campaign %s stopped with status %d (%d/%d applications completed)\n' \
            "$(timestamp)" "${campaign_id}" "${status}" \
            "${completed_applications}" "${application_count}" >&2
    fi
}

trap 'handle_signal INT 130' INT
trap 'handle_signal TERM 143' TERM
trap report_exit EXIT

require_digest_image OBSERVER_IMAGE
for application in "${campaign_applications[@]}"; do
    require_digest_image "$(application_image_variable "${application}")"
done

[[ "${campaign_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
    fail "CAMPAIGN_ID may contain only letters, digits, dot, underscore, and hyphen"
[[ -n "${namespace}" ]] || fail "NAMESPACE must not be empty"
[[ -n "${node_name}" ]] || fail "NODE_NAME must not be empty"
[[ -n "${redis_addr}" ]] || fail "REDIS_ADDR must not be empty"
[[ "${seed}" =~ ^-?[0-9]+$ ]] || fail "SEED must be an integer"

require_unsigned_integer TRIALS "${trials}" 1
require_unsigned_integer WARMUPS "${warmups}" 0
require_unsigned_integer DURATION_MS "${duration_ms}" 100
require_unsigned_integer EVIDENCE_HOLD_MS "${evidence_hold_ms}" 100
require_unsigned_integer INTERVAL_US "${interval_us}" 1
require_unsigned_integer MAP_POLL_US "${map_poll_us}" 1
require_unsigned_integer INFRASTRUCTURE_RETRIES "${infrastructure_retries}" 0

[[ "${image_pull_policy}" == "Never" ]] || \
    fail "IMAGE_PULL_POLICY must be Never for a publication campaign"

command -v "${python_bin}" >/dev/null 2>&1 || fail "Python executable not found: ${python_bin}"
command -v "${kubectl_bin}" >/dev/null 2>&1 || fail "kubectl executable not found: ${kubectl_bin}"
command -v flock >/dev/null 2>&1 || fail "flock is required for campaign serialization"

exec 9>"${lock_file}"
flock -n 9 || fail "another application campaign holds ${lock_file}"

export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"

printf '[%s] campaign=%s node=%s namespace=%s results=%s\n' \
    "$(timestamp)" "${campaign_id}" "${node_name}" "${namespace}" "${results_root}"
printf '[%s] applications=%s\n' "$(timestamp)" "${campaign_applications[*]}"
printf '[%s] building native measurement tools once\n' "$(timestamp)"
"${eval_root}/scripts/build.sh"

for application in "${campaign_applications[@]}"; do
    current_application="${application}"
    carrier_image="$(image_for_application "${application}")"
    run_id="${application}-${campaign_id}"
    current_run_dir="${results_root}/${run_id}"
    command=(
        "${python_bin}" "${eval_root}/scripts/run_experiment.py"
        --application "${application}"
        --run-id "${run_id}"
        --trials "${trials}"
        --warmups "${warmups}"
        --duration-ms "${duration_ms}"
        --evidence-hold-ms "${evidence_hold_ms}"
        --interval-us "${interval_us}"
        --map-poll-us "${map_poll_us}"
        --infrastructure-retries "${infrastructure_retries}"
        --seed "${seed}"
        --namespace "${namespace}"
        --node "${node_name}"
        --carrier-image "${carrier_image}"
        --observer-image "${OBSERVER_IMAGE}"
        --image-pull-policy "${image_pull_policy}"
        --redis-addr "${redis_addr}"
        --kubectl "${kubectl_bin}"
        --results-root "${results_root}"
        --skip-build
    )

    printf '[%s] starting %s (run-id=%s)\n' \
        "$(timestamp)" "${application}" "${run_id}"
    print_command "${command[@]}"

    # Bash normally ignores SIGINT for asynchronous children. Reset it in the
    # child so the wrapper's graceful-stop path reaches Python's finally block.
    (
        trap - INT TERM
        exec "${command[@]}"
    ) &
    current_child_pid="$!"
    set +e
    wait "${current_child_pid}"
    child_status="$?"
    set -e
    current_child_pid=""

    if (( child_status != 0 )); then
        printf '[%s] %s failed with status %d; later applications were not started\n' \
            "$(timestamp)" "${application}" "${child_status}" >&2
        exit "${child_status}"
    fi

    if ! check_publication_result "${current_run_dir}" "${application}"; then
        printf '[%s] %s failed the publication gate; later applications were not started\n' \
            "$(timestamp)" "${application}" >&2
        exit 1
    fi

    ((completed_applications += 1))
    printf '[%s] completed %s (%d/%d)\n' \
        "$(timestamp)" "${application}" "${completed_applications}" \
        "${application_count}"
    current_run_dir=""
done

current_application=""
