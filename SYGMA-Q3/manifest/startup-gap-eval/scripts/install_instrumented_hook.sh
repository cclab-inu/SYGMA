#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"
repo_root="$(cd -- "${eval_root}/../.." && pwd)"
hook_dir="${repo_root}/ocihook/ebpf/hook"
output_dir="${eval_root}/build"
output_hook="${output_dir}/sygma-hook"
installed_hook="/usr/local/bin/sygma-hook"
backup_hook="/usr/local/bin/sygma-hook.pre-startup-gap-eval"
redis_addr="${REDIS_ADDR:-}"
build_only=false
node_name="${NODE_NAME:-master}"
namespace="${INSTALL_NAMESPACE:-default}"
carrier_image="${CARRIER_IMAGE:-}"
system_image_lock="${SYSTEM_IMAGE_LOCK:-${repo_root}/artifacts/local/sygma-q3-artifact-v1-images.lock}"
installer_pod="sygma-hook-eval-installer"

usage() {
    echo "Usage: $0 [--redis-addr HOST:PORT] [--node NODE] [--namespace NS]" >&2
    echo "          [--carrier-image IMAGE] [--build-only]" >&2
}

while (($#)); do
    case "$1" in
        --redis-addr)
            if (($# < 2)); then
                usage
                exit 2
            fi
            redis_addr="$2"
            shift 2
            ;;
        --build-only)
            build_only=true
            shift
            ;;
        --node)
            node_name="$2"
            shift 2
            ;;
        --namespace)
            namespace="$2"
            shift 2
            ;;
        --carrier-image)
            carrier_image="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [[ "${build_only}" != true && -z "${carrier_image}" && -f "${system_image_lock}" ]]; then
    carrier_image="$(
        awk -F= '$1 == "image.installer.digest_ref" {sub(/^[^=]*=/, ""); print; exit}' \
            "${system_image_lock}"
    )"
fi
if [[ "${build_only}" != true && ! "${carrier_image}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "error: --carrier-image must be a loaded immutable digest; run the profile local-images.sh build/load first" >&2
    exit 1
fi

if [[ -z "${redis_addr}" ]]; then
    redis_addr="$(kubectl get configmap sygma-config -n default \
        -o jsonpath='{.data.redis-addr}')"
fi
if [[ -z "${redis_addr}" || "${redis_addr}" =~ [[:space:]] ]]; then
    echo "error: invalid Redis address; pass --redis-addr HOST:PORT" >&2
    exit 1
fi
for tool in go grep sha256sum awk; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "error: required tool is missing: ${tool}" >&2
        exit 1
    fi
done

mkdir -p -- "${output_dir}"
temporary_hook="${output_dir}/.sygma-hook.tmp.$$"
trap 'rm -f -- "${temporary_hook}"' EXIT

(
    cd -- "${hook_dir}"
    go build -buildvcs=false \
        -ldflags "-s -w -X main.DefaultRedisAddr=${redis_addr}" \
        -o "${temporary_hook}" .
)
chmod 0755 "${temporary_hook}"
mv -f -- "${temporary_hook}" "${output_hook}"
trap - EXIT

if ! grep -aFq 'sygma_direct_policy_ready' "${output_hook}"; then
    echo "error: built hook does not contain the evaluation marker" >&2
    exit 1
fi
local_hash="$(sha256sum "${output_hook}" | awk '{print $1}')"
echo "built ${output_hook} (sha256=${local_hash}, Redis=${redis_addr})"

if [[ "${build_only}" == true ]]; then
    exit 0
fi

if ! command -v kubectl >/dev/null 2>&1; then
    echo "error: kubectl is required for the privileged node install" >&2
    exit 1
fi

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
          if [ -f /host-bin/sygma-hook ] && [ ! -e /host-bin/sygma-hook.pre-startup-gap-eval ]; then
            cp -p /host-bin/sygma-hook /host-bin/sygma-hook.pre-startup-gap-eval
          fi
          cp /source/sygma-hook /host-bin/.sygma-hook.startup-gap-eval.new
          chmod 0755 /host-bin/.sygma-hook.startup-gap-eval.new
          mv -f /host-bin/.sygma-hook.startup-gap-eval.new /host-bin/sygma-hook
          sha256sum /host-bin/sygma-hook
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
      volumeMounts:
        - name: source
          mountPath: /source
          readOnly: true
        - name: host-bin
          mountPath: /host-bin
  volumes:
    - name: source
      hostPath:
        path: ${output_dir}
        type: Directory
    - name: host-bin
      hostPath:
        path: /usr/local/bin
        type: Directory
EOF

if ! kubectl wait pod "${installer_pod}" -n "${namespace}" \
    --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s; then
    kubectl describe pod "${installer_pod}" -n "${namespace}" >&2 || true
    kubectl logs "${installer_pod}" -n "${namespace}" >&2 || true
    exit 1
fi
pod_logs="$(kubectl logs "${installer_pod}" -n "${namespace}")"
echo "${pod_logs}"
installed_hash="$(printf '%s\n' "${pod_logs}" | awk 'NF >= 2 {value=$1} END {print value}')"
if [[ "${installed_hash}" != "${local_hash}" ]]; then
    echo "error: installed hook hash mismatch" >&2
    exit 1
fi

echo "installed ${installed_hook} (sha256=${installed_hash})"
echo "containerd/NRI restart is not required; future container creates resolve this path."
