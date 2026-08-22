#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
eval_root="$(cd -- "${script_dir}/.." && pwd)"

repository_prefix="localhost/sygma-q3"
image_set_id=""
observer_image=""
output_dir=""
rebuild=false
dry_run=false
source_override=false
allow_unconfirmed_remote_absence=false
applications_override=""

docker_bin="${DOCKER_BIN:-docker}"
python_bin="${PYTHON_BIN:-python3}"
lock_file="${LOCK_FILE:-/tmp/sygma-startup-gap-eval.image-publish.lock}"

applications=(
    nginx redis httpd mysql
    hotel-frontend hotel-geo hotel-profile hotel-rate hotel-recommendation
    hotel-reservation hotel-search hotel-user
    boutique-ad boutique-cart boutique-checkout boutique-currency
    boutique-email boutique-frontend boutique-payment boutique-productcatalog
    boutique-recommendation boutique-shipping
    hotel-consul hotel-jaeger
    hotel-mongo-geo hotel-mongo-profile hotel-mongo-rate hotel-mongo-recommendation
    hotel-mongo-reservation hotel-mongo-user
    hotel-memcached-profile hotel-memcached-rate hotel-memcached-reserve
    boutique-redis-cart
)

declare -A source_images=(
    [nginx]="sygma-startup-gap-eval/nginx:packaging-check-v2-20260802"
    [redis]="sygma-startup-gap-eval/redis:packaging-check-20260802"
    [httpd]="sygma-startup-gap-eval/httpd:packaging-check-20260802"
    [mysql]="sygma-startup-gap-eval/mysql:packaging-check-20260802"
)

# Full local image config digests captured from the four attached images. These
# are source trust anchors, never registry manifest digests. Together with the
# launcher-byte check they prevent an arbitrary extra layer or inherited
# runtime-config change from being published under the audited defaults.
# Only meaningful in non-rebuild mode; every profile below is publication-only
# reachable via --rebuild, so these entries are dead but must still satisfy
# the sha256-format precondition below.
declare -A expected_source_image_ids=(
    [nginx]="sha256:19f018fc2ad78f40a2aa698a966e3fc88ad89a8d2f40ffcf5ca47674f5c7c194"
    [redis]="sha256:c663dc1ca7c8625fda6ed794dbdf75505a8526493b10ad1cd8f7cd3aba76dbfe"
    [httpd]="sha256:529c0838dc7d66f00c2fca7b46280040bf9cbe149d7cc4ddf4594a7e265da3ef"
    [mysql]="sha256:bd1bfc1bacefbc6462155462ca07c6d4e4ef910bfceac011e14656b2c67e0d46"

    [hotel-frontend]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-geo]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-profile]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-rate]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-recommendation]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-reservation]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-search]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-user]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-ad]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-cart]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-checkout]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-currency]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-email]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-frontend]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-payment]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-productcatalog]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-recommendation]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-shipping]="sha256:0000000000000000000000000000000000000000000000000000000000000000"

    [hotel-consul]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-jaeger]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-mongo-geo]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-mongo-profile]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-mongo-rate]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-mongo-recommendation]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-mongo-reservation]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-mongo-user]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-memcached-profile]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-memcached-rate]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [hotel-memcached-reserve]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    [boutique-redis-cart]="sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

declare -A source_reference_overrides=()
declare -A source_id_overrides=()

declare -A base_images=(
    [nginx]="docker.io/library/nginx@sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2"
    [redis]="docker.io/library/redis@sha256:a7cee7c8178ff9b5297cb109e6240f5072cdaaafd775ce6b586c3c704b06458e"
    [httpd]="docker.io/library/httpd@sha256:374766f5bc5977c9b72fdb8ae3ed05b7fc89060e7edc88fcbf142d6988e58eeb"
    [mysql]="docker.io/library/mysql@sha256:c6812f0dcd978b589d9d3b90c20bd5e4a799deab4fd492985e0a076c5be1ee40"

    [hotel-frontend]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-geo]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-profile]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-rate]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-recommendation]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-reservation]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-search]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"
    [hotel-user]="docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436"

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

declare -A expected_entrypoints=(
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

declare -A expected_commands=(
    [nginx]='["nginx","-g","daemon off;"]'
    [redis]='["redis-server"]'
    [httpd]='["httpd-foreground"]'
    [mysql]='["mysqld"]'

    [hotel-frontend]='null'
    [hotel-geo]='null'
    [hotel-profile]='null'
    [hotel-rate]='null'
    [hotel-recommendation]='null'
    [hotel-reservation]='null'
    [hotel-search]='null'
    [hotel-user]='null'

    [boutique-ad]='null'
    [boutique-cart]='null'
    [boutique-checkout]='null'
    [boutique-currency]='null'
    [boutique-email]='null'
    [boutique-frontend]='null'
    [boutique-payment]='null'
    [boutique-productcatalog]='null'
    [boutique-recommendation]='null'
    [boutique-shipping]='null'

    [hotel-consul]='["agent","-dev","-client","0.0.0.0"]'
    [hotel-jaeger]='null'
    [hotel-mongo-geo]='["mongod"]'
    [hotel-mongo-profile]='["mongod"]'
    [hotel-mongo-rate]='["mongod"]'
    [hotel-mongo-recommendation]='["mongod"]'
    [hotel-mongo-reservation]='["mongod"]'
    [hotel-mongo-user]='["mongod"]'
    [hotel-memcached-profile]='["memcached"]'
    [hotel-memcached-rate]='["memcached"]'
    [hotel-memcached-reserve]='["memcached"]'
    [boutique-redis-cart]='["redis-server"]'
)

declare -A tagged_images=()
declare -A local_image_ids=()
declare -A manifest_media_types=()
declare -A canonical_images=()

temporary_dir=""
temporary_container=""
environment_tmp=""
provenance_tmp=""
output_dir_created=false
completed=false

usage() {
    cat >&2 <<'EOF'
Usage:
  publish_application_images.sh \
    [--repository-prefix REGISTRY/NAMESPACE] \
    --image-set-id UNIQUE_TAG \
    --observer-image IMAGE@sha256:DIGEST \
    [--output-dir DIR] [--rebuild] [--dry-run] \
    [--applications "app1 app2 ..."] \
    [--nginx-source IMAGE] [--redis-source IMAGE] \
    [--httpd-source IMAGE] [--mysql-source IMAGE] \
    [--nginx-source-id sha256:CONFIG_DIGEST] [...] \
    [--allow-unconfirmed-remote-absence]

By default, every profile in the applications array (the four original
packaging-check images plus every hotel-*/boutique-* profile) is published in
one campaign. The four legacy applications are verified, retagged, pushed as
linux/amd64 single-platform manifests, resolved through the registry, and
pulled back by digest from their already-built packaging-check images; every
other profile has no such pre-built local artifact and requires --rebuild.
--rebuild creates fresh images from the pinned Dockerfile bases for every
selected application before publishing them (this is the only supported mode
for hotel-*/boutique-* profiles). Use --applications to publish a subset, for
example --applications "hotel-frontend hotel-geo" or the original
--applications "nginx redis httpd mysql" existing-image flow.

The default destination is localhost/sygma-q3. An override must be fully
qualified, for example:
  localhost/sygma-q3
  registry.example.com/research/sygma

The script never logs in, deletes a local/remote image, overwrites an existing
local destination tag, or creates the final campaign-images.env until all four
registry round trips have succeeded. It also refuses a destination tag that is
already resolvable in the registry. Use a globally unique image-set ID because
the remote existence check and push cannot be one atomic registry operation.
If registry errors prevent distinguishing a missing tag from an authorization
or network failure, the script stops unless --allow-unconfirmed-remote-absence
is explicitly supplied. A custom --APP-source requires its exact
--APP-source-id config digest.
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

timestamp() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

cleanup() {
    local status="$?"

    if [[ -n "${temporary_container}" ]]; then
        "${docker_bin}" container rm -f "${temporary_container}" \
            >/dev/null 2>&1 || true
    fi
    if [[ -n "${temporary_dir}" && -d "${temporary_dir}" ]]; then
        rm -rf -- "${temporary_dir}"
    fi
    if [[ -n "${environment_tmp}" && -e "${environment_tmp}" ]]; then
        rm -f -- "${environment_tmp}"
    fi
    if [[ -n "${provenance_tmp}" && -e "${provenance_tmp}" ]]; then
        rm -f -- "${provenance_tmp}"
    fi
    if [[ "${output_dir_created}" == true ]]; then
        if [[ "${completed}" == true && ${status} -eq 0 ]]; then
            printf 'state=COMPLETE\nfinished_at=%s\n' "$(timestamp)" \
                >"${output_dir}/STATUS"
        else
            printf 'state=FAILED\nexit_code=%d\nfinished_at=%s\n' \
                "${status}" "$(timestamp)" >"${output_dir}/STATUS"
        fi
    fi
}

trap cleanup EXIT

while (($#)); do
    case "$1" in
        --repository-prefix)
            (($# >= 2)) || fail "--repository-prefix requires a value"
            repository_prefix="$2"
            shift 2
            ;;
        --image-set-id)
            (($# >= 2)) || fail "--image-set-id requires a value"
            image_set_id="$2"
            shift 2
            ;;
        --observer-image)
            (($# >= 2)) || fail "--observer-image requires a value"
            observer_image="$2"
            shift 2
            ;;
        --applications)
            (($# >= 2)) || fail "--applications requires a value"
            applications_override="$2"
            shift 2
            ;;
        --output-dir)
            (($# >= 2)) || fail "--output-dir requires a value"
            output_dir="$2"
            shift 2
            ;;
        --nginx-source|--redis-source|--httpd-source|--mysql-source)
            (($# >= 2)) || fail "$1 requires a value"
            application="${1#--}"
            application="${application%-source}"
            source_images[${application}]="$2"
            source_reference_overrides[${application}]=true
            source_override=true
            shift 2
            ;;
        --nginx-source-id|--redis-source-id|--httpd-source-id|--mysql-source-id)
            (($# >= 2)) || fail "$1 requires a value"
            application="${1#--}"
            application="${application%-source-id}"
            expected_source_image_ids[${application}]="$2"
            source_id_overrides[${application}]=true
            source_override=true
            shift 2
            ;;
        --rebuild)
            rebuild=true
            shift
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        --allow-unconfirmed-remote-absence)
            allow_unconfirmed_remote_absence=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[[ -n "${image_set_id}" ]] || fail "--image-set-id is required"
[[ -n "${observer_image}" ]] || fail "--observer-image is required"

if [[ -n "${applications_override}" ]]; then
    read -r -a selected_applications <<<"${applications_override}"
    ((${#selected_applications[@]})) || fail "--applications must select at least one application"
    declare -A known_application=()
    for application in "${applications[@]}"; do
        known_application[${application}]=1
    done
    for application in "${selected_applications[@]}"; do
        [[ -n "${known_application[${application}]:-}" ]] || \
            fail "unsupported application in --applications: ${application}"
    done
    applications=("${selected_applications[@]}")
fi

repository_prefix="${repository_prefix%/}"
if [[ "${repository_prefix}" == *://* || "${repository_prefix}" == *@* ||
      "${repository_prefix}" =~ [[:space:]] || "${repository_prefix}" != */* ]]; then
    fail "--repository-prefix must be a fully qualified REGISTRY/NAMESPACE without a scheme"
fi
registry_host="${repository_prefix%%/*}"
if [[ "${registry_host}" != "localhost" && "${registry_host}" != *.* &&
      "${registry_host}" != *:* ]]; then
    fail "--repository-prefix must include an explicit registry host (use docker.io for Docker Hub)"
fi
if [[ ! "${repository_prefix}" =~ ^[a-z0-9][a-z0-9._:/-]*[a-z0-9]$ ]]; then
    fail "--repository-prefix contains unsupported characters"
fi
repository_path="${repository_prefix#*/}"
if [[ "${repository_path}" == *:* || "${repository_path}" == *//* ||
      "${repository_path}" == .* || "${repository_path}" == -* ||
      "${repository_path}" == _* ]]; then
    fail "--repository-prefix contains an invalid repository namespace"
fi
if [[ ! "${image_set_id}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
    fail "--image-set-id is not a valid Docker tag"
fi
if [[ ! "${observer_image}" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]]; then
    fail "--observer-image must be an immutable lowercase sha256 digest reference"
fi
if [[ "${rebuild}" == true && "${source_override}" == true ]]; then
    fail "source-image overrides cannot be combined with --rebuild"
fi

if [[ -z "${output_dir}" ]]; then
    output_dir="${eval_root}/published-images/${image_set_id}"
fi

for application in "${applications[@]}"; do
    repository="${repository_prefix}/sygma-gap-${application}"
    tagged_images[${application}]="${repository}:${image_set_id}"
    if [[ "${rebuild}" == true ]]; then
        source_images[${application}]="${tagged_images[${application}]}"
    fi
    if [[ "${source_images[${application}]:-}" =~ [[:space:]] ||
          -z "${source_images[${application}]:-}" ]]; then
        fail "invalid ${application} source image"
    fi
    if [[ ! "${expected_source_image_ids[${application}]}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        fail "${application} source config digest must be lowercase sha256"
    fi
    if [[ "${rebuild}" != true ]]; then
        reference_was_overridden="${source_reference_overrides[${application}]:-false}"
        id_was_overridden="${source_id_overrides[${application}]:-false}"
        if [[ "${reference_was_overridden}" != "${id_was_overridden}" ]]; then
            fail "custom --${application}-source and --${application}-source-id must be supplied together"
        fi
    fi
done

if [[ "${dry_run}" == true ]]; then
    printf 'mode=%s\n' "$([[ "${rebuild}" == true ]] && printf rebuild || printf existing)"
    printf 'observer=%s\n' "${observer_image}"
    printf 'output_dir=%s\n' "${output_dir}"
    for application in "${applications[@]}"; do
        printf '%s source=%s destination=%s\n' \
            "${application}" "${source_images[${application}]}" \
            "${tagged_images[${application}]}"
    done
    exit 0
fi

for tool in "${docker_bin}" "${python_bin}" awk cmp file flock readelf sha256sum stat tee; do
    command -v "${tool}" >/dev/null 2>&1 || fail "required tool is missing: ${tool}"
done

exec 9>"${lock_file}"
flock -n 9 || fail "another image publication holds ${lock_file}"

if [[ -e "${output_dir}" ]]; then
    fail "output directory already exists: ${output_dir}"
fi
mkdir -p -- "$(dirname -- "${output_dir}")"
mkdir -- "${output_dir}"
output_dir_created=true
printf 'state=RUNNING\nstarted_at=%s\n' "$(timestamp)" >"${output_dir}/STATUS"

temporary_dir="$(mktemp -d /tmp/sygma-application-publish.XXXXXX)"

resolve_manifest() {
    local reference="$1"
    local metadata
    local media_type
    local digest

    metadata="$(
        "${docker_bin}" buildx imagetools inspect "${reference}" \
            --format '{{printf "%s|%s\n" .Manifest.MediaType .Manifest.Digest}}'
    )"
    IFS='|' read -r media_type digest <<<"${metadata}"
    case "${media_type}" in
        application/vnd.oci.image.manifest.v1+json|\
        application/vnd.docker.distribution.manifest.v2+json)
            ;;
        *)
            printf 'error: %s resolved to non-single-platform media type %s\n' \
                "${reference}" "${media_type:-<missing>}" >&2
            return 1
            ;;
    esac
    if [[ ! "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        printf 'error: registry returned an invalid digest for %s: %s\n' \
            "${reference}" "${digest:-<missing>}" >&2
        return 1
    fi
    printf '%s|%s\n' "${media_type}" "${digest}"
}

verify_local_application_image() {
    local application="$1"
    local image_reference="$2"
    local platform
    local entrypoint
    local command_json
    local base_layers
    local derived_layers
    local image_id

    if ! "${docker_bin}" image inspect "${image_reference}" >/dev/null; then
        fail "local ${application} image is missing: ${image_reference}"
    fi
    platform="$(
        "${docker_bin}" image inspect --format '{{.Os}}/{{.Architecture}}' \
            "${image_reference}"
    )"
    [[ "${platform}" == "linux/amd64" ]] || \
        fail "${application} image must be linux/amd64, got ${platform}"

    entrypoint="$(
        "${docker_bin}" image inspect --format '{{json .Config.Entrypoint}}' \
            "${image_reference}"
    )"
    command_json="$(
        "${docker_bin}" image inspect --format '{{json .Config.Cmd}}' \
            "${image_reference}"
    )"
    [[ "${entrypoint}" == "${expected_entrypoints[${application}]}" ]] || \
        fail "${application} image has an unexpected ENTRYPOINT"
    [[ "${command_json}" == "${expected_commands[${application}]}" ]] || \
        fail "${application} image has an unexpected CMD"

    if ! "${docker_bin}" image inspect \
        "${base_images[${application}]}" >/dev/null; then
        fail "pinned ${application} base is missing locally: ${base_images[${application}]}"
    fi
    base_layers="$(
        "${docker_bin}" image inspect --format '{{json .RootFS.Layers}}' \
            "${base_images[${application}]}"
    )"
    derived_layers="$(
        "${docker_bin}" image inspect --format '{{json .RootFS.Layers}}' \
            "${image_reference}"
    )"
    "${python_bin}" - "${application}" "${base_layers}" "${derived_layers}" <<'PY'
import json
import sys

application = sys.argv[1]
base = json.loads(sys.argv[2])
derived = json.loads(sys.argv[3])
if derived[: len(base)] != base or len(derived) != len(base) + 1:
    raise SystemExit(
        f"error: {application} image is not the pinned base plus exactly one launcher layer"
    )
PY

    temporary_container="$("${docker_bin}" container create "${image_reference}")"
    "${docker_bin}" container cp \
        "${temporary_container}:/opt/gap/gap-launch" \
        "${temporary_dir}/${application}-gap-launch"
    "${docker_bin}" container rm "${temporary_container}" >/dev/null
    temporary_container=""
    if ! cmp -s "${eval_root}/build/gap-probe" \
        "${temporary_dir}/${application}-gap-launch"; then
        fail "${application} image launcher differs from the current audited gap-probe; rerun with --rebuild"
    fi

    image_id="$(
        "${docker_bin}" image inspect --format '{{.Id}}' "${image_reference}"
    )"
    [[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || \
        fail "${application} has an invalid local image config ID"
    if [[ "${rebuild}" != true &&
          "${image_id}" != "${expected_source_image_ids[${application}]}" ]]; then
        fail "${application} source image config digest differs from its declared trust anchor"
    fi
    local_image_ids[${application}]="${image_id}"
}

verify_repo_digest_cross_reference() {
    local tagged_reference="$1"
    local canonical_reference="$2"
    local expected_digest="${canonical_reference##*@}"
    local expected_repository="${canonical_reference%@*}"
    local repo_digest
    local repository
    local digest
    local found=false

    while IFS= read -r repo_digest; do
        [[ -n "${repo_digest}" && "${repo_digest}" == *@sha256:* ]] || continue
        repository="${repo_digest%@*}"
        digest="${repo_digest##*@}"
        if [[ "${repository}" == index.docker.io/* ]]; then
            repository="docker.io/${repository#index.docker.io/}"
        elif [[ "${repository}" == registry-1.docker.io/* ]]; then
            repository="docker.io/${repository#registry-1.docker.io/}"
        elif [[ "${repository}" != */* ]]; then
            repository="docker.io/library/${repository}"
        elif [[ "${repository%%/*}" != *.* && "${repository%%/*}" != *:* &&
                "${repository%%/*}" != "localhost" ]]; then
            repository="docker.io/${repository}"
        fi
        if [[ "${repository}" == "${expected_repository}" &&
              "${digest}" == "${expected_digest}" ]]; then
            found=true
            break
        fi
    done < <(
        "${docker_bin}" image inspect \
            --format '{{range .RepoDigests}}{{println .}}{{end}}' \
            "${tagged_reference}"
    )
    [[ "${found}" == true ]] || \
        fail "local RepoDigests does not cross-reference ${canonical_reference}"
}

check_remote_destination_absence() {
    local application="$1"
    local tagged_reference="$2"
    local probe_output
    local probe_status
    local lowercase_output

    set +e
    probe_output="$(
        "${docker_bin}" buildx imagetools inspect "${tagged_reference}" \
            --format '{{.Manifest.Digest}}' 2>&1
    )"
    probe_status="$?"
    set -e
    printf '%s\n' "${probe_output}" \
        >"${output_dir}/${application}.remote-preflight.log"

    if (( probe_status == 0 )); then
        fail "destination tag already exists in the registry: ${tagged_reference}"
    fi

    lowercase_output="${probe_output,,}"
    case "${lowercase_output}" in
        *"manifest unknown"*|*"name unknown"*|*"not found"*|*"no such manifest"*)
            return 0
            ;;
    esac

    if [[ "${allow_unconfirmed_remote_absence}" != true ]]; then
        printf 'error: registry response did not prove that %s is absent:\n%s\n' \
            "${tagged_reference}" "${probe_output:-<no error text>}" >&2
        fail "create/check the repository or rerun with --allow-unconfirmed-remote-absence and a globally unique image-set ID"
    fi
    printf 'warning: proceeding without confirmed remote-tag absence for %s\n' \
        "${tagged_reference}" >&2
}

printf '[%s] verifying observer digest in the registry\n' "$(timestamp)"
observer_metadata="$(resolve_manifest "${observer_image}")"
IFS='|' read -r observer_media_type observer_resolved_digest \
    <<<"${observer_metadata}"
[[ "${observer_resolved_digest}" == "${observer_image##*@}" ]] || \
    fail "observer digest did not resolve to itself"
"${docker_bin}" image pull --platform linux/amd64 "${observer_image}" \
    2>&1 | tee "${output_dir}/observer.pull.log"
observer_platform="$(
    "${docker_bin}" image inspect --format '{{.Os}}/{{.Architecture}}' \
        "${observer_image}"
)"
[[ "${observer_platform}" == "linux/amd64" ]] || \
    fail "observer image must resolve to linux/amd64"
observer_local_id="$(
    "${docker_bin}" image inspect --format '{{.Id}}' "${observer_image}"
)"
[[ "${observer_local_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    fail "observer has an invalid local image config ID"

printf '[%s] building the current static measurement tools once\n' "$(timestamp)"
"${eval_root}/scripts/build.sh" 2>&1 | tee "${output_dir}/native-build.log"
launcher_hash="$(sha256sum "${eval_root}/build/gap-probe" | awk '{print $1}')"

# Refuse known local or remote destination collisions before creating any of
# the four final local tags. The generated image-set ID should always be fresh.
for application in "${applications[@]}"; do
    tagged_reference="${tagged_images[${application}]}"
    if "${docker_bin}" image inspect "${tagged_reference}" >/dev/null 2>&1; then
        fail "destination tag already exists locally: ${tagged_reference}"
    fi
    check_remote_destination_absence "${application}" "${tagged_reference}"
done

# Complete every local build/verification before the first registry push.
if [[ "${rebuild}" == true ]]; then
    for application in "${applications[@]}"; do
        tagged_reference="${tagged_images[${application}]}"
        printf '[%s] rebuilding and verifying %s as %s\n' \
            "$(timestamp)" "${application}" "${tagged_reference}"
        "${eval_root}/scripts/build_application_image.sh" \
            --application "${application}" \
            --image "${tagged_reference}" \
            --base-image "${base_images[${application}]}" \
            --no-rebuild-probe \
            2>&1 | tee "${output_dir}/${application}.build.log"
        verify_local_application_image "${application}" "${tagged_reference}"
    done
else
    for application in "${applications[@]}"; do
        source_reference="${source_images[${application}]}"
        printf '[%s] verifying existing %s image %s\n' \
            "$(timestamp)" "${application}" "${source_reference}"
        verify_local_application_image "${application}" "${source_reference}"
    done
    for application in "${applications[@]}"; do
        source_reference="${source_images[${application}]}"
        tagged_reference="${tagged_images[${application}]}"
        "${docker_bin}" image tag "${source_reference}" "${tagged_reference}"
        tagged_id="$(
            "${docker_bin}" image inspect --format '{{.Id}}' "${tagged_reference}"
        )"
        [[ "${tagged_id}" == "${local_image_ids[${application}]}" ]] || \
            fail "${application} image ID changed while retagging"
    done
fi

printf 'timestamp\tapplication\tevent\ttagged_reference\tcanonical_reference\tlocal_image_id\tmedia_type\n' \
    >"${output_dir}/push-receipts.tsv"

for application in "${applications[@]}"; do
    tagged_reference="${tagged_images[${application}]}"
    pre_push_id="$(
        "${docker_bin}" image inspect --format '{{.Id}}' "${tagged_reference}"
    )"
    [[ "${pre_push_id}" == "${local_image_ids[${application}]}" ]] || \
        fail "${application} destination tag changed after local verification"

    printf '[%s] pushing %s\n' "$(timestamp)" "${tagged_reference}"
    push_log="${output_dir}/${application}.push.log"
    set +e
    "${docker_bin}" image push --platform linux/amd64 "${tagged_reference}" \
        2>&1 | tee "${push_log}"
    push_status="${PIPESTATUS[0]}"
    set -e
    if (( push_status != 0 )); then
        fail "${application} push failed with status ${push_status}"
    fi
    printf '%s\t%s\tpush_command_succeeded\t%s\t\t%s\t\n' \
        "$(timestamp)" "${application}" "${tagged_reference}" \
        "${local_image_ids[${application}]}" \
        >>"${output_dir}/push-receipts.tsv"

    push_reported_digest="$("${python_bin}" - "${push_log}" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
digests = sorted(set(re.findall(r"\bdigest:\s*(sha256:[0-9a-f]{64})\b", text)))
if len(digests) != 1:
    raise SystemExit(
        f"error: expected one push-reported manifest digest, found {digests!r}"
    )
print(digests[0])
PY
)"
    push_reported_reference="${tagged_reference%:*}@${push_reported_digest}"
    printf '%s\t%s\tpush_reported_digest\t%s\t%s\t%s\t\n' \
        "$(timestamp)" "${application}" "${tagged_reference}" \
        "${push_reported_reference}" "${local_image_ids[${application}]}" \
        >>"${output_dir}/push-receipts.tsv"

    manifest_metadata="$(resolve_manifest "${tagged_reference}")"
    IFS='|' read -r media_type manifest_digest <<<"${manifest_metadata}"
    [[ "${manifest_digest}" == "${push_reported_digest}" ]] || \
        fail "${application} registry tag digest differs from the push-reported digest"
    canonical_reference="${tagged_reference%:*}@${manifest_digest}"

    canonical_metadata="$(resolve_manifest "${canonical_reference}")"
    IFS='|' read -r canonical_media_type canonical_digest \
        <<<"${canonical_metadata}"
    [[ "${canonical_digest}" == "${manifest_digest}" &&
       "${canonical_media_type}" == "${media_type}" ]] || \
        fail "${application} digest reference did not resolve to the pushed manifest"

    "${docker_bin}" image pull --platform linux/amd64 "${canonical_reference}" \
        2>&1 | tee "${output_dir}/${application}.roundtrip-pull.log"
    roundtrip_id="$(
        "${docker_bin}" image inspect --format '{{.Id}}' "${canonical_reference}"
    )"
    roundtrip_platform="$(
        "${docker_bin}" image inspect --format '{{.Os}}/{{.Architecture}}' \
            "${canonical_reference}"
    )"
    [[ "${roundtrip_platform}" == "linux/amd64" ]] || \
        fail "${application} registry round trip changed the platform"
    [[ "${roundtrip_id}" == "${local_image_ids[${application}]}" ]] || \
        fail "${application} registry round trip changed the image config ID"

    verify_repo_digest_cross_reference "${tagged_reference}" \
        "${canonical_reference}"

    manifest_media_types[${application}]="${media_type}"
    canonical_images[${application}]="${canonical_reference}"
    printf '%s\t%s\troundtrip_verified\t%s\t%s\t%s\t%s\n' \
        "$(timestamp)" "${application}" "${tagged_reference}" \
        "${canonical_reference}" "${local_image_ids[${application}]}" \
        "${media_type}" \
        >>"${output_dir}/push-receipts.tsv"
done

environment_tmp="$(mktemp "${output_dir}/.campaign-images.env.XXXXXX")"
{
    printf '# Generated by publish_application_images.sh at %s\n' "$(timestamp)"
    printf '# Registry tags are provenance only; campaigns use immutable digests.\n'
    printf 'export OBSERVER_IMAGE=%q\n' "${observer_image}"
    for application in "${applications[@]}"; do
        upper="${application^^}"
        variable_name="${upper//-/_}_IMAGE"
        printf 'export %s=%q\n' "${variable_name}" \
            "${canonical_images[${application}]}"
    done
    printf 'export IMAGE_PULL_POLICY=Never\n'
} >"${environment_tmp}"

provenance_tmp="$(mktemp "${output_dir}/.publication.json.XXXXXX")"
provenance_arguments=()
for application in "${applications[@]}"; do
    provenance_arguments+=(
        "${application}"
        "${source_images[${application}]}"
        "${base_images[${application}]}"
        "${tagged_images[${application}]}"
        "${canonical_images[${application}]}"
        "${local_image_ids[${application}]}"
        "${manifest_media_types[${application}]}"
    )
done
"${python_bin}" - "${provenance_tmp}" "${repository_prefix}" \
    "${image_set_id}" "${rebuild}" "${allow_unconfirmed_remote_absence}" \
    "${observer_image}" \
    "${observer_media_type}" "${observer_local_id}" "${launcher_hash}" \
    "${provenance_arguments[@]}" <<'PY'
import datetime as dt
import json
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
repository_prefix = sys.argv[2]
image_set_id = sys.argv[3]
mode = "rebuild" if sys.argv[4] == "true" else "existing"
allowed_unconfirmed_remote_absence = sys.argv[5] == "true"
observer_image = sys.argv[6]
observer_media_type = sys.argv[7]
observer_local_id = sys.argv[8]
launcher_hash = sys.argv[9]
records = sys.argv[10:]
if len(records) % 7:
    raise SystemExit("invalid publication record arguments")

images = {}
for offset in range(0, len(records), 7):
    (
        application,
        source_image,
        base_image,
        tagged_image,
        canonical_image,
        local_image_id,
        media_type,
    ) = records[offset : offset + 7]
    images[application] = {
        "source_image": source_image,
        "base_image": base_image,
        "pushed_tag": tagged_image,
        "canonical_digest_reference": canonical_image,
        "local_config_digest": local_image_id,
        "manifest_media_type": media_type,
    }

document = {
    "schema_version": 1,
    "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "mode": mode,
    "platform": "linux/amd64",
    "repository_prefix": repository_prefix,
    "image_set_id": image_set_id,
    "allowed_unconfirmed_remote_absence": allowed_unconfirmed_remote_absence,
    "launcher_sha256": f"sha256:{launcher_hash}",
    "observer": {
        "canonical_digest_reference": observer_image,
        "local_config_digest": observer_local_id,
        "manifest_media_type": observer_media_type,
    },
    "applications": images,
}
output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 0644 "${provenance_tmp}"
mv -- "${provenance_tmp}" "${output_dir}/publication.json"
provenance_tmp=""

# campaign-images.env is the commit artifact and is exposed last. A failure
# while creating provenance therefore cannot leave a sourceable final env in
# an output directory whose STATUS will become FAILED.
chmod 0644 "${environment_tmp}"
mv -- "${environment_tmp}" "${output_dir}/campaign-images.env"
environment_tmp=""

completed=true
{
    printf '[%s] published and verified all application images\n' "$(timestamp)"
    printf 'Environment file: %s\n' "${output_dir}/campaign-images.env"
    printf 'Provenance:       %s\n' "${output_dir}/publication.json"
    printf 'Next: source %q, preload all five refs into the target-node CRI, then run the campaign wrapper.\n' \
        "${output_dir}/campaign-images.env"
} || true
