#!/bin/bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
crd_dir="${script_dir}/../sygma-operator/config/crd/bases"

kubectl apply \
  -f "${crd_dir}/security.security.io_sygmaconfigs.yaml" \
  -f "${crd_dir}/security.security.io_sygmapolicies.yaml"
kubectl wait --for=condition=Established --timeout=60s \
  crd/sygmaconfigs.security.security.io \
  crd/sygmapolicies.security.security.io

# The former policy store was deployment/redis and reserved hostPort 6379.
# Never delete it implicitly: it may contain the only copy of published policy
# data. Refuse the rollout until the operator has backed it up and performed
# the documented migration, otherwise the renamed store cannot schedule.
if kubectl get deployment/redis -n default >/dev/null 2>&1; then
  legacy_host_ports="$(kubectl get deployment/redis -n default \
    -o jsonpath='{range .spec.template.spec.containers[*].ports[*]}{.hostPort}{"\n"}{end}')"
  if [[ $'\n'"${legacy_host_ports}"$'\n' == *$'\n6379\n'* ]]; then
    echo "error: legacy deployment/redis still reserves hostPort 6379" >&2
    echo "back up/republish its policy data, then remove that legacy Deployment before retrying" >&2
    exit 1
  fi
fi

kubectl apply -f "${script_dir}/redis_sygma.yaml"
kubectl rollout status deployment/sygma-policy-redis -n default -w

redis_host="$(kubectl get pods -n default -l app.kubernetes.io/name=sygma-policy-redis --field-selector=status.phase=Running -o jsonpath='{.items[0].status.hostIP}')"
if [[ -z "${redis_host}" && -z "${REDIS_ADDR:-}" ]]; then
  echo "error: ready Redis Pod has no status.hostIP; set REDIS_ADDR=HOST:PORT explicitly" >&2
  exit 1
fi
if [[ -n "${REDIS_ADDR:-}" ]]; then
  redis_endpoint="${REDIS_ADDR}"
elif [[ "${redis_host}" == *:* ]]; then
  redis_endpoint="[${redis_host}]:6379"
else
  redis_endpoint="${redis_host}:6379"
fi
SYGMA_RESTART_CONSUMERS=false \
  "${script_dir}/config_set.sh" "${redis_endpoint}"

core_generation="$(kubectl get daemonset/core -n default -o jsonpath='{.metadata.generation}' 2>/dev/null || true)"
kubectl apply -f "${script_dir}/core.yaml"
if [[ -n "${core_generation}" && \
      "$(kubectl get daemonset/core -n default -o jsonpath='{.metadata.generation}')" == "${core_generation}" ]]; then
  kubectl rollout restart daemonset/core -n default
fi
kubectl rollout status daemonset/core -n default -w

operator_generation="$(kubectl get deployment/sygma-config-operator -n default -o jsonpath='{.metadata.generation}' 2>/dev/null || true)"
kubectl apply -f "${script_dir}/sygma-config-operator.yaml"
if [[ -n "${operator_generation}" && \
      "$(kubectl get deployment/sygma-config-operator -n default -o jsonpath='{.metadata.generation}')" == "${operator_generation}" ]]; then
  kubectl rollout restart deployment/sygma-config-operator -n default
fi
kubectl rollout status deployment/sygma-config-operator -n default -w

installer_generation="$(kubectl get daemonset/sygma-policy-agent -n default -o jsonpath='{.metadata.generation}' 2>/dev/null || true)"
kubectl apply -f "${script_dir}/sygma-policy-agent.yaml"
if [[ -n "${installer_generation}" && \
      "$(kubectl get daemonset/sygma-policy-agent -n default -o jsonpath='{.metadata.generation}')" == "${installer_generation}" ]]; then
  kubectl rollout restart daemonset/sygma-policy-agent -n default
fi
kubectl rollout status daemonset/sygma-policy-agent -n default -w
