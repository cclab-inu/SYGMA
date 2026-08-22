#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"

application=""
output_image=""
base_image=""
rebuild_probe=true

declare -A default_base_images=(
    [nginx]="docker.io/library/nginx@sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2"
    [redis]="docker.io/library/redis@sha256:a7cee7c8178ff9b5297cb109e6240f5072cdaaafd775ce6b586c3c704b06458e"
    [httpd]="docker.io/library/httpd@sha256:374766f5bc5977c9b72fdb8ae3ed05b7fc89060e7edc88fcbf142d6988e58eeb"
    [mysql]="docker.io/library/mysql@sha256:c6812f0dcd978b589d9d3b90c20bd5e4a799deab4fd492985e0a076c5be1ee40"

    # DeathStarBench Hotel Reservation: one shared multi-service source/build
    # image; every core microservice binary lives under /go/bin.
    [hotel-frontend]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-geo]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-profile]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-rate]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-recommendation]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-reservation]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-search]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-user]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"

    # Google Online Boutique v0.10.3, one published image per service.
    [boutique-ad]="us-central1-docker.pkg.dev/google-samples/microservices-demo/adservice@sha256:ff1a059bb8f1226b77b42a9102344cfc4b669a04696eb44aeed3db8ae2b04e9e"
    [boutique-cart]="us-central1-docker.pkg.dev/google-samples/microservices-demo/cartservice@sha256:598efe871d0251cbd35729972acb23c0723cb7aca451503ba10fb8116aecb958"
    [boutique-checkout]="us-central1-docker.pkg.dev/google-samples/microservices-demo/checkoutservice@sha256:6688da8718a92373cc149c8423936b342123060e86705804f9ffbc421bd2ae8f"
    [boutique-currency]="us-central1-docker.pkg.dev/google-samples/microservices-demo/currencyservice@sha256:f7d6e530d10ecbf8a10408bd6e114ed6d7670130bb28d22309bb66fcb99ebdb9"
    [boutique-email]="us-central1-docker.pkg.dev/google-samples/microservices-demo/emailservice@sha256:59558f8e668e4edec7b40a928c2368696474a8da85ef912e278f8abb3200ecbe"
    [boutique-frontend]="us-central1-docker.pkg.dev/google-samples/microservices-demo/frontend@sha256:83f44050fc5ea5999ea04a940e687d7bd5ad357fcf6e6f5944e5e32de006bbdb"
    [boutique-payment]="us-central1-docker.pkg.dev/google-samples/microservices-demo/paymentservice@sha256:d95567da89a5e7c3c819f1b742c12a3bf4a2ad35af0ddbcbd06eb908252e67d9"
    [boutique-productcatalog]="us-central1-docker.pkg.dev/google-samples/microservices-demo/productcatalogservice@sha256:c358001d318f6bec85f49119653f19bbc235a0a323e45c936dc74460701fd129"
    [boutique-recommendation]="us-central1-docker.pkg.dev/google-samples/microservices-demo/recommendationservice@sha256:2f3eae327b743160033cec8662362e2190f9aa9a04a1ace1bd05f19106ed4bd3"
    [boutique-shipping]="us-central1-docker.pkg.dev/google-samples/microservices-demo/shippingservice@sha256:b0125be448f9eb042214fec6eebda79a900a1a4c307f8e1bdb56f35e403969dd"

    # DeathStarBench Hotel Reservation supporting infrastructure (consul,
    # jaeger, per-service MongoDB/memcached) and Online Boutique's
    # redis-cart. Added alongside the app-only profiles above so every
    # container in either benchmark can be measured, not only the ones
    # carrying custom application code.
    [hotel-consul]="docker.io/hashicorp/consul@sha256:56a8d0fdbfcb35836c4ce2fc8a5d34eac48594ef067bbe4af7d5ceb9fb08c28d"
    [hotel-jaeger]="docker.io/jaegertracing/all-in-one@sha256:ab6f1a1f0fb49ea08bcd19f6b84f6081d0d44b364b6de148e1798eb5816bacac"
    [hotel-mongo-geo]="docker.io/library/mongo@sha256:6efa052039903e731e4a5550c68a13c4869ddc93742c716332883fd9c77eb79b"
    [hotel-mongo-profile]="docker.io/library/mongo@sha256:6efa052039903e731e4a5550c68a13c4869ddc93742c716332883fd9c77eb79b"
    [hotel-mongo-rate]="docker.io/library/mongo@sha256:6efa052039903e731e4a5550c68a13c4869ddc93742c716332883fd9c77eb79b"
    [hotel-mongo-recommendation]="docker.io/library/mongo@sha256:6efa052039903e731e4a5550c68a13c4869ddc93742c716332883fd9c77eb79b"
    [hotel-mongo-reservation]="docker.io/library/mongo@sha256:6efa052039903e731e4a5550c68a13c4869ddc93742c716332883fd9c77eb79b"
    [hotel-mongo-user]="docker.io/library/mongo@sha256:6efa052039903e731e4a5550c68a13c4869ddc93742c716332883fd9c77eb79b"
    [hotel-memcached-profile]="docker.io/library/memcached@sha256:eeb9eaa939ffaa2304899674c9e88a9247ec8e5e40e424a892df7b09914bd2ec"
    [hotel-memcached-rate]="docker.io/library/memcached@sha256:eeb9eaa939ffaa2304899674c9e88a9247ec8e5e40e424a892df7b09914bd2ec"
    [hotel-memcached-reserve]="docker.io/library/memcached@sha256:eeb9eaa939ffaa2304899674c9e88a9247ec8e5e40e424a892df7b09914bd2ec"
    [boutique-redis-cart]="docker.io/library/redis@sha256:978f0e01593e65eed801f2402944efcd936d43b5027e4908a7897baf88ed6241"
)

declare -A expected_base_entrypoints=(
    [nginx]='["/docker-entrypoint.sh"]'
    [redis]='["docker-entrypoint.sh"]'
    [httpd]='null'
    [mysql]='["docker-entrypoint.sh"]'

    [hotel-frontend]='null'
    [hotel-geo]='null'
    [hotel-profile]='null'
    [hotel-rate]='null'
    [hotel-recommendation]='null'
    [hotel-reservation]='null'
    [hotel-search]='null'
    [hotel-user]='null'

    [boutique-ad]='["/app/build/install/hipstershop/bin/AdService"]'
    [boutique-cart]='["/app/cartservice"]'
    [boutique-checkout]='["/src/checkoutservice"]'
    [boutique-currency]='["node","server.js"]'
    [boutique-email]='["python","email_server.py"]'
    [boutique-frontend]='["/src/server"]'
    [boutique-payment]='["node","index.js"]'
    [boutique-productcatalog]='["/src/server"]'
    [boutique-recommendation]='["python","recommendation_server.py"]'
    [boutique-shipping]='["/src/shippingservice"]'

    [hotel-consul]='["docker-entrypoint.sh"]'
    [hotel-jaeger]='["/go/bin/all-in-one-linux"]'
    [hotel-mongo-geo]='["docker-entrypoint.sh"]'
    [hotel-mongo-profile]='["docker-entrypoint.sh"]'
    [hotel-mongo-rate]='["docker-entrypoint.sh"]'
    [hotel-mongo-recommendation]='["docker-entrypoint.sh"]'
    [hotel-mongo-reservation]='["docker-entrypoint.sh"]'
    [hotel-mongo-user]='["docker-entrypoint.sh"]'
    [hotel-memcached-profile]='["docker-entrypoint.sh"]'
    [hotel-memcached-rate]='["docker-entrypoint.sh"]'
    [hotel-memcached-reserve]='["docker-entrypoint.sh"]'
    [boutique-redis-cart]='["docker-entrypoint.sh"]'
)

declare -A expected_derived_entrypoints=(
    [nginx]='["/opt/gap/gap-launch","--application","nginx","--","/docker-entrypoint.sh"]'
    [redis]='["/opt/gap/gap-launch","--application","redis","--","docker-entrypoint.sh"]'
    [httpd]='["/opt/gap/gap-launch","--application","httpd","--"]'
    [mysql]='["/opt/gap/gap-launch","--application","mysql","--","docker-entrypoint.sh"]'

    [hotel-frontend]='["/opt/gap/gap-launch","--application","hotel-frontend","--","/go/bin/frontend"]'
    [hotel-geo]='["/opt/gap/gap-launch","--application","hotel-geo","--","/go/bin/geo"]'
    [hotel-profile]='["/opt/gap/gap-launch","--application","hotel-profile","--","/go/bin/profile"]'
    [hotel-rate]='["/opt/gap/gap-launch","--application","hotel-rate","--","/go/bin/rate"]'
    [hotel-recommendation]='["/opt/gap/gap-launch","--application","hotel-recommendation","--","/go/bin/recommendation"]'
    [hotel-reservation]='["/opt/gap/gap-launch","--application","hotel-reservation","--","/go/bin/reservation"]'
    [hotel-search]='["/opt/gap/gap-launch","--application","hotel-search","--","/go/bin/search"]'
    [hotel-user]='["/opt/gap/gap-launch","--application","hotel-user","--","/go/bin/user"]'

    [boutique-ad]='["/opt/gap/gap-launch","--application","boutique-ad","--","/app/build/install/hipstershop/bin/AdService"]'
    [boutique-cart]='["/opt/gap/gap-launch","--application","boutique-cart","--","/app/cartservice"]'
    [boutique-checkout]='["/opt/gap/gap-launch","--application","boutique-checkout","--","/src/checkoutservice"]'
    [boutique-currency]='["/opt/gap/gap-launch","--application","boutique-currency","--","node","server.js"]'
    [boutique-email]='["/opt/gap/gap-launch","--application","boutique-email","--","python","email_server.py"]'
    [boutique-frontend]='["/opt/gap/gap-launch","--application","boutique-frontend","--","/src/server"]'
    [boutique-payment]='["/opt/gap/gap-launch","--application","boutique-payment","--","node","index.js"]'
    [boutique-productcatalog]='["/opt/gap/gap-launch","--application","boutique-productcatalog","--","/src/server"]'
    [boutique-recommendation]='["/opt/gap/gap-launch","--application","boutique-recommendation","--","python","recommendation_server.py"]'
    [boutique-shipping]='["/opt/gap/gap-launch","--application","boutique-shipping","--","/src/shippingservice"]'

    [hotel-consul]='["/opt/gap/gap-launch","--application","hotel-consul","--","docker-entrypoint.sh"]'
    [hotel-jaeger]='["/opt/gap/gap-launch","--application","hotel-jaeger","--","/go/bin/all-in-one-linux"]'
    [hotel-mongo-geo]='["/opt/gap/gap-launch","--application","hotel-mongo-geo","--","docker-entrypoint.sh"]'
    [hotel-mongo-profile]='["/opt/gap/gap-launch","--application","hotel-mongo-profile","--","docker-entrypoint.sh"]'
    [hotel-mongo-rate]='["/opt/gap/gap-launch","--application","hotel-mongo-rate","--","docker-entrypoint.sh"]'
    [hotel-mongo-recommendation]='["/opt/gap/gap-launch","--application","hotel-mongo-recommendation","--","docker-entrypoint.sh"]'
    [hotel-mongo-reservation]='["/opt/gap/gap-launch","--application","hotel-mongo-reservation","--","docker-entrypoint.sh"]'
    [hotel-mongo-user]='["/opt/gap/gap-launch","--application","hotel-mongo-user","--","docker-entrypoint.sh"]'
    [hotel-memcached-profile]='["/opt/gap/gap-launch","--application","hotel-memcached-profile","--","docker-entrypoint.sh"]'
    [hotel-memcached-rate]='["/opt/gap/gap-launch","--application","hotel-memcached-rate","--","docker-entrypoint.sh"]'
    [hotel-memcached-reserve]='["/opt/gap/gap-launch","--application","hotel-memcached-reserve","--","docker-entrypoint.sh"]'
    [boutique-redis-cart]='["/opt/gap/gap-launch","--application","boutique-redis-cart","--","docker-entrypoint.sh"]'
)

# Most profiles keep the base CMD unchanged (Docker appends it after the
# fixed ENTRYPOINT args). The Hotel Reservation profiles have no meaningful
# per-service base CMD (base CMD is the placeholder ["bash"]); baking the
# selected binary directly into ENTRYPOINT resets the derived CMD to null
# instead, matching every already-null-CMD Boutique base.
declare -A expected_derived_cmds=(
    [hotel-frontend]='null'
    [hotel-geo]='null'
    [hotel-profile]='null'
    [hotel-rate]='null'
    [hotel-recommendation]='null'
    [hotel-reservation]='null'
    [hotel-search]='null'
    [hotel-user]='null'
)

usage() {
    cat >&2 <<'EOF'
Usage: build_application_image.sh --application NAME --image OUTPUT_TAG
                                  [--base-image IMAGE@sha256:DIGEST]
                                  [--no-rebuild-probe]

NAME is one of the keys of default_base_images in this script: nginx, redis,
httpd, mysql, hotel-{frontend,geo,profile,rate,recommendation,reservation,
search,user}, or boutique-{ad,cart,checkout,currency,email,frontend,payment,
productcatalog,recommendation,shipping}.
The default base for each application is pinned by sha256 digest in this script
and its Dockerfile. The helper builds and verifies one local image only; it does
not push, import into a CRI runtime, or deploy the image.
EOF
}

while (($#)); do
    case "$1" in
        --application)
            if (($# < 2)); then
                usage
                exit 2
            fi
            application="$2"
            shift 2
            ;;
        --image)
            if (($# < 2)); then
                usage
                exit 2
            fi
            output_image="$2"
            shift 2
            ;;
        --base-image)
            if (($# < 2)); then
                usage
                exit 2
            fi
            base_image="$2"
            shift 2
            ;;
        --no-rebuild-probe)
            rebuild_probe=false
            shift
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

if [[ -z "${application}" || -z "${default_base_images[${application}]:-}" ]]; then
    echo "error: --application must be a known profile (see --help)" >&2
    exit 2
fi
if [[ -z "${output_image}" ]]; then
    echo "error: --image is required" >&2
    exit 2
fi
if [[ "${output_image}" == -* || "${output_image}" == *@sha256:* ||
      "${output_image}" =~ [[:space:]] ]]; then
    echo "error: --image must be a non-digest image tag without whitespace" >&2
    exit 2
fi
if [[ -z "${base_image}" ]]; then
    base_image="${default_base_images[${application}]}"
fi
if [[ ! "${base_image}" =~ @sha256:[0-9a-fA-F]{64}$ ]]; then
    echo "error: --base-image must use an immutable sha256 digest" >&2
    exit 2
fi

for tool in cmp docker file readelf sha256sum stat; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "error: required tool is missing: ${tool}" >&2
        exit 1
    fi
done

if docker image inspect "${output_image}" >/dev/null 2>&1; then
    echo "error: output image already exists locally: ${output_image}" >&2
    echo "error: choose a fresh tag so this helper does not retag an existing image" >&2
    exit 1
fi

if [[ "${rebuild_probe}" == true ]]; then
    "${script_dir}/build.sh"
fi

probe_binary="${eval_root}/build/gap-probe"
if [[ ! -f "${probe_binary}" || ! -x "${probe_binary}" ]]; then
    echo "error: executable probe is missing: ${probe_binary}" >&2
    echo "error: run ${script_dir}/build.sh or omit --no-rebuild-probe" >&2
    exit 1
fi
if [[ "$(stat -c '%s' -- "${probe_binary}")" -gt $((1024 * 1024)) ]]; then
    echo "error: probe exceeds the OCI-hook staging limit of 1 MiB" >&2
    exit 1
fi
if ! file "${probe_binary}" | grep -Eq 'ELF 64-bit.*x86-64.*statically linked'; then
    echo "error: probe must be a static x86-64 ELF executable" >&2
    exit 1
fi
if readelf -l "${probe_binary}" | grep -q 'INTERP'; then
    echo "error: probe unexpectedly contains a dynamic interpreter" >&2
    exit 1
fi

if ! docker image inspect "${base_image}" >/dev/null 2>&1; then
    echo "error: exact base image is not present in the local Docker cache: ${base_image}" >&2
    echo "error: load or pull it explicitly before running this offline build helper" >&2
    exit 1
fi

base_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${base_image}")"
base_entrypoint="$(docker image inspect --format '{{json .Config.Entrypoint}}' "${base_image}")"
base_cmd="$(docker image inspect --format '{{json .Config.Cmd}}' "${base_image}")"
if [[ "${base_platform}" != "linux/amd64" ]]; then
    echo "error: base platform must be linux/amd64, got ${base_platform}" >&2
    exit 1
fi
if [[ "${base_entrypoint}" != "${expected_base_entrypoints[${application}]}" ]]; then
    echo "error: base ENTRYPOINT is incompatible with the ${application} wrapper" >&2
    echo "error: expected ${expected_base_entrypoints[${application}]}, got ${base_entrypoint}" >&2
    exit 1
fi

dockerfile="${eval_root}/images/Dockerfile.${application}"
docker build \
    --pull=false \
    --build-arg "BASE_IMAGE=${base_image}" \
    --file "${dockerfile}" \
    --tag "${output_image}" \
    "${eval_root}"

derived_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${output_image}")"
derived_entrypoint="$(docker image inspect --format '{{json .Config.Entrypoint}}' "${output_image}")"
derived_cmd="$(docker image inspect --format '{{json .Config.Cmd}}' "${output_image}")"
if [[ "${derived_platform}" != "${base_platform}" ]]; then
    echo "error: derived platform changed: ${base_platform} -> ${derived_platform}" >&2
    exit 1
fi
if [[ "${derived_entrypoint}" != "${expected_derived_entrypoints[${application}]}" ]]; then
    echo "error: derived ENTRYPOINT does not match the audited launcher chain" >&2
    exit 1
fi
expected_derived_cmd="${expected_derived_cmds[${application}]:-${base_cmd}}"
if [[ "${derived_cmd}" != "${expected_derived_cmd}" ]]; then
    echo "error: derived image CMD does not match the expected value for ${application}" >&2
    echo "error: expected ${expected_derived_cmd}, got ${derived_cmd}" >&2
    exit 1
fi

temporary_dir="$(mktemp -d)"
container_id=""
cleanup() {
    if [[ -n "${container_id}" ]]; then
        docker rm -f "${container_id}" >/dev/null 2>&1 || true
    fi
    rm -rf -- "${temporary_dir}"
}
trap cleanup EXIT
container_id="$(docker create "${output_image}")"

docker cp "${container_id}:/opt/gap/gap-launch" "${temporary_dir}/gap-launch"
if ! cmp -s "${probe_binary}" "${temporary_dir}/gap-launch"; then
    echo "error: image launcher differs from the locally built gap-probe" >&2
    exit 1
fi

probe_hash="$(sha256sum "${probe_binary}" | awk '{print $1}')"
image_id="$(docker image inspect --format '{{.Id}}' "${output_image}")"
echo "built and verified local ${application} evaluation image: ${output_image}"
echo "image id: ${image_id}"
echo "gap launcher sha256: ${probe_hash}"
echo "base image: ${base_image}"
echo "no image was pushed, imported into a CRI runtime, or deployed"
