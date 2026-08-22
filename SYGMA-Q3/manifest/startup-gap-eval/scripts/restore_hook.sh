#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"
profile_root="$(cd -- "${eval_root}/../.." && pwd)"
node_name="${NODE_NAME:-master}"
namespace="${INSTALL_NAMESPACE:-default}"
carrier_image="${CARRIER_IMAGE:-}"
system_image_lock="${SYSTEM_IMAGE_LOCK:-${profile_root}/artifacts/local/sygma-q3-artifact-v1-images.lock}"
restore_pod="sygma-hook-eval-restorer"

usage() {
    echo "Usage: $0 [--node NODE] [--namespace NS] [--carrier-image IMAGE]" >&2
}

while (($#)); do
    case "$1" in
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

if [[ -z "${carrier_image}" && -f "${system_image_lock}" ]]; then
    carrier_image="$(
        awk -F= '$1 == "image.installer.digest_ref" {sub(/^[^=]*=/, ""); print; exit}' \
            "${system_image_lock}"
    )"
fi
if [[ ! "${carrier_image}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "error: --carrier-image must be a loaded immutable digest; run the profile local-images.sh build/load first" >&2
    exit 1
fi

cleanup_restorer() {
    kubectl delete pod "${restore_pod}" -n "${namespace}" \
        --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
}
cleanup_restorer
trap cleanup_restorer EXIT

kubectl create -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${restore_pod}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/part-of: sygma-startup-gap-eval
spec:
  nodeName: ${node_name}
  automountServiceAccountToken: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 1
  containers:
    - name: restorer
      image: ${carrier_image}
      imagePullPolicy: Never
      command: ["/bin/sh", "-ceu"]
      args:
        - |
          test -f /host-bin/sygma-hook.pre-startup-gap-eval
          cp /host-bin/sygma-hook.pre-startup-gap-eval /host-bin/.sygma-hook.restore.new
          chmod 0755 /host-bin/.sygma-hook.restore.new
          mv -f /host-bin/.sygma-hook.restore.new /host-bin/sygma-hook
          sha256sum /host-bin/sygma-hook
      securityContext:
        privileged: true
        runAsUser: 0
        allowPrivilegeEscalation: true
      volumeMounts:
        - name: host-bin
          mountPath: /host-bin
  volumes:
    - name: host-bin
      hostPath:
        path: /usr/local/bin
        type: Directory
EOF

if ! kubectl wait pod "${restore_pod}" -n "${namespace}" \
    --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s; then
    kubectl describe pod "${restore_pod}" -n "${namespace}" >&2 || true
    kubectl logs "${restore_pod}" -n "${namespace}" >&2 || true
    exit 1
fi
pod_logs="$(kubectl logs "${restore_pod}" -n "${namespace}")"
echo "${pod_logs}"
echo "restored /usr/local/bin/sygma-hook; the backup is retained for audit/recovery."
