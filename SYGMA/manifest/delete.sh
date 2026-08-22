#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

kubectl delete -f "${script_dir}/core.yaml"
kubectl delete -f "${script_dir}/sygma-config-operator.yaml"
kubectl delete -f "${script_dir}/sygma-policy-agent.yaml"
kubectl delete -f "${script_dir}/redis_sygma.yaml"
