#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"
profile_root="$(cd -- "${eval_root}/../.." && pwd)"

node_name="${NODE_NAME:-master}"
namespace="${INSTALL_NAMESPACE:-default}"
redis_addr="${REDIS_ADDR:-}"
carrier_image="${CARRIER_IMAGE:-}"
system_image_lock="${SYSTEM_IMAGE_LOCK:-${profile_root}/artifacts/local/sygma-q3-artifact-v1-images.lock}"
installer_pod="sygma-observation-component-installer"

usage() {
    cat >&2 <<'EOF'
Usage:
  install_staged_observation_components.sh [OPTIONS]

Build the Redis-addressed observation hook, then atomically install the exact
audited hook, tracer, wrapper, and NRI plugin binaries on the target node.

Options:
  --redis-addr HOST:PORT
  --node NODE
  --namespace NAMESPACE
  --carrier-image IMAGE@sha256:DIGEST
  -h, --help

The script does not restart containerd. Restart containerd after a successful
install so the newly installed NRI plugin process is loaded.
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

while (($#)); do
    case "$1" in
        --redis-addr)
            (($# >= 2)) || fail "--redis-addr requires a value"
            redis_addr="$2"
            shift 2
            ;;
        --node)
            (($# >= 2)) || fail "--node requires a value"
            node_name="$2"
            shift 2
            ;;
        --namespace)
            (($# >= 2)) || fail "--namespace requires a value"
            namespace="$2"
            shift 2
            ;;
        --carrier-image)
            (($# >= 2)) || fail "--carrier-image requires a value"
            carrier_image="$2"
            shift 2
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

if [[ -z "${carrier_image}" && -f "${system_image_lock}" ]]; then
    carrier_image="$(
        awk -F= '$1 == "image.installer.digest_ref" {sub(/^[^=]*=/, ""); print; exit}' \
            "${system_image_lock}"
    )"
fi

for tool in kubectl sha256sum awk; do
    command -v "${tool}" >/dev/null 2>&1 || fail "required tool is missing: ${tool}"
done
if [[ ! "${carrier_image}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    fail "--carrier-image must use an immutable lowercase sha256 digest"
fi
if [[ -z "${redis_addr}" ]]; then
    redis_addr="$(
        kubectl get configmap sygma-config -n default \
            -o jsonpath='{.data.redis-addr}'
    )"
fi
if [[ -z "${redis_addr}" || "${redis_addr}" =~ [[:space:]] ]]; then
    fail "invalid Redis address; pass --redis-addr HOST:PORT"
fi

"${script_dir}/install_instrumented_hook.sh" \
    --redis-addr "${redis_addr}" --build-only

declare -A local_paths=(
    [hook]="${eval_root}/build/sygma-hook"
    [tracer]="${eval_root}/build/sygma-tracer-current"
    [wrapper]="${eval_root}/build/sygma-wrapper-current"
    [nri_plugin]="${eval_root}/build/sygma-nri-current"
)
declare -A installed_paths=(
    [hook]="/host-usr-local-bin/sygma-hook"
    [tracer]="/host-usr-local-bin/sygma-tracer"
    [wrapper]="/host-opt/sygma/wrapper"
    [nri_plugin]="/host-opt/nri/plugins/00-sygma"
)
declare -A expected_hashes=()

for component in hook tracer wrapper nri_plugin; do
    local_path="${local_paths[${component}]}"
    [[ -f "${local_path}" ]] || fail "missing staged ${component}: ${local_path}"
    expected_hashes[${component}]="$(sha256sum "${local_path}" | awk '{print $1}')"
done

cleanup_installer() {
    kubectl delete pod "${installer_pod}" -n "${namespace}" \
        --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
}
cleanup_installer
trap cleanup_installer EXIT

kubectl create -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${installer_pod}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/part-of: sygma-startup-gap-eval
spec:
  nodeName: ${node_name}
  automountServiceAccountToken: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 1
  containers:
    - name: installer
      image: ${carrier_image}
      imagePullPolicy: Never
      command: ["/bin/sh", "-ceu"]
      args:
        - |
          install_exact() {
              source_path="\$1"
              destination_path="\$2"
              temporary_path="\${destination_path}.startup-gap-eval.new"
              mkdir -p "\$(dirname -- "\${destination_path}")"
              cp "\${source_path}" "\${temporary_path}"
              chmod 0755 "\${temporary_path}"
              mv -f "\${temporary_path}" "\${destination_path}"
          }

          if [ -f /host-usr-local-bin/sygma-hook ] &&
             [ ! -e /host-usr-local-bin/sygma-hook.pre-startup-gap-eval ]; then
              cp -p /host-usr-local-bin/sygma-hook \
                  /host-usr-local-bin/sygma-hook.pre-startup-gap-eval
          fi

          install_exact /source/sygma-hook \
              /host-usr-local-bin/sygma-hook
          install_exact /source/sygma-tracer-current \
              /host-usr-local-bin/sygma-tracer
          install_exact /source/sygma-wrapper-current \
              /host-opt/sygma/wrapper
          install_exact /source/sygma-nri-current \
              /host-opt/nri/plugins/00-sygma

          sha256sum \
              /host-usr-local-bin/sygma-hook \
              /host-usr-local-bin/sygma-tracer \
              /host-opt/sygma/wrapper \
              /host-opt/nri/plugins/00-sygma
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
      volumeMounts:
        - name: source
          mountPath: /source
          readOnly: true
        - name: host-usr-local-bin
          mountPath: /host-usr-local-bin
        - name: host-opt
          mountPath: /host-opt
  volumes:
    - name: source
      hostPath:
        path: ${eval_root}/build
        type: Directory
    - name: host-usr-local-bin
      hostPath:
        path: /usr/local/bin
        type: Directory
    - name: host-opt
      hostPath:
        path: /opt
        type: Directory
EOF

if ! kubectl wait pod "${installer_pod}" -n "${namespace}" \
    --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s; then
    kubectl describe pod "${installer_pod}" -n "${namespace}" >&2 || true
    kubectl logs "${installer_pod}" -n "${namespace}" >&2 || true
    exit 1
fi

pod_logs="$(kubectl logs "${installer_pod}" -n "${namespace}")"
printf '%s\n' "${pod_logs}"

for component in hook tracer wrapper nri_plugin; do
    installed_path="${installed_paths[${component}]}"
    installed_hash="$(
        printf '%s\n' "${pod_logs}" |
            awk -v path="${installed_path}" '$2 == path { print $1 }'
    )"
    if [[ "${installed_hash}" != "${expected_hashes[${component}]}" ]]; then
        fail "installed ${component} hash mismatch: expected ${expected_hashes[${component}]}, got ${installed_hash:-<missing>}"
    fi
done

printf 'installed and verified staged observation components on node %s\n' \
    "${node_name}"
printf 'required next step: sudo systemctl restart containerd\n'
