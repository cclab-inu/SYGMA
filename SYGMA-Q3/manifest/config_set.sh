#!/bin/bash

set -euo pipefail

redis_addr="${1:-${REDIS_ADDR:-}}"
if [[ -z "${redis_addr}" ]]; then
  redis_host="$(hostname -I | awk '{print $1}')"
  if [[ "${redis_host}" == *:* ]]; then
    redis_addr="[${redis_host}]:6379"
  else
    redis_addr="${redis_host}:6379"
  fi
fi

if [[ ! "${redis_addr}" =~ ^([^[:space:]:]+|\[[^]]+\]):([0-9]+)$ ]]; then
  echo "error: Redis address must be HOST:PORT (got '${redis_addr}')" >&2
  exit 1
fi
redis_port="${BASH_REMATCH[2]}"
if (( ${#redis_port} > 5 )) || (( 10#${redis_port} < 1 || 10#${redis_port} > 65535 )); then
  echo "error: Redis port must be between 1 and 65535 (got '${redis_port}')" >&2
  exit 1
fi

echo "Configuring SYGMA Redis endpoint: ${redis_addr}"

# ConfigMap 
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: sygma-config
  namespace: default
data:
  redis-addr: "${redis_addr}"
EOF

# The ConfigMap value is consumed as Pod environment and copied into the
# host-side NRI configuration by the installer initContainer. Restart existing
# consumers so a standalone endpoint update cannot leave different components
# using different Redis servers. Fresh installs simply skip these resources.
restart_if_present() {
  local resource="$1"
  if kubectl get "${resource}" -n default >/dev/null 2>&1; then
    kubectl rollout restart "${resource}" -n default
    kubectl rollout status "${resource}" -n default -w
  fi
}

case "${SYGMA_RESTART_CONSUMERS:-true}" in
  true)
    restart_if_present deployment/sygma-config-operator
    restart_if_present daemonset/sygma-policy-agent
    ;;
  false) ;;
  *)
    echo "error: SYGMA_RESTART_CONSUMERS must be true or false" >&2
    exit 1
    ;;
esac
