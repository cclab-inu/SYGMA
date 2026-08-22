#!/usr/bin/env bash

set -euo pipefail

redis_endpoint="${1:-${REDIS_ADDR:-}}"
if [[ -z "${redis_endpoint}" ]]; then
  echo "error: pass Redis as HOST:PORT or set REDIS_ADDR" >&2
  exit 1
fi

kubectl create configmap sygma-config \
  --namespace default \
  --from-literal="redis-addr=${redis_endpoint}" \
  --dry-run=client \
  -o yaml |
  kubectl apply -f -

printf 'configured Redis endpoint: %s\n' "${redis_endpoint}"
