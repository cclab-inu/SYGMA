#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
crd_dir="${script_dir}/../sygma-operator/config/crd/bases"

kubectl apply \
  -f "${crd_dir}/security.security.io_sygmaconfigs.yaml" \
  -f "${crd_dir}/security.security.io_sygmapolicies.yaml"
kubectl wait --for=condition=Established --timeout=60s \
  crd/sygmaconfigs.security.security.io \
  crd/sygmapolicies.security.security.io

kubectl apply -f "${script_dir}/redis_sygma.yaml"
kubectl rollout status deployment/redis -n default -w

redis_host="$(kubectl get pods -n default -l app=redis \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].status.hostIP}')"
if [[ -n "${REDIS_ADDR:-}" ]]; then
  redis_endpoint="${REDIS_ADDR}"
elif [[ -z "${redis_host}" ]]; then
  echo "error: Redis Pod has no host IP; set REDIS_ADDR=HOST:PORT" >&2
  exit 1
elif [[ "${redis_host}" == *:* ]]; then
  redis_endpoint="[${redis_host}]:6379"
else
  redis_endpoint="${redis_host}:6379"
fi
"${script_dir}/config_set.sh" "${redis_endpoint}"

kubectl apply -f "${script_dir}/core.yaml"
kubectl rollout status daemonset/core -n default -w

kubectl apply -f "${script_dir}/sygma-config-operator.yaml"
kubectl rollout status deployment/sygma-config-operator -n default -w

kubectl apply -f "${script_dir}/sygma-policy-agent.yaml"
kubectl rollout status daemonset/sygma-policy-agent -n default -w
