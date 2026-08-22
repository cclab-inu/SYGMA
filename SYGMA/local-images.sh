#!/usr/bin/env bash

set -Eeuo pipefail

profile_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
export SYGMA_LOCAL_PROFILE="sygma"
export SYGMA_LOCAL_PROFILE_DISPLAY="SYGMA"
export SYGMA_LOCAL_PROFILE_ROOT="${profile_root}"
exec bash "${profile_root}/scripts/local-images-common.sh" "$@"
