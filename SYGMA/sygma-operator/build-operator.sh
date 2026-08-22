#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
profile_root="$(cd -- "${script_dir}/.." && pwd)"

if [[ ${1:-build} != "build" ]]; then
  echo "error: registry push commands are disabled in the anonymous artifact" >&2
  echo "use: ${profile_root}/local-images.sh build" >&2
  exit 2
fi

echo "delegating to the registry-free profile builder" >&2
exec "${profile_root}/local-images.sh" build
