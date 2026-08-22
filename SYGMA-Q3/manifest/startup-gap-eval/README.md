# SYGMA startup policy-application-gap evaluation

This experiment evaluates startup **publish-before-release atomicity**. It asks
how many syscalls from the real nginx, Redis, httpd, or MySQL process lineage
execute before the container becomes eligible for its preloaded policy. The
launcher, image entrypoint scripts, and synthetic `uname` calls are excluded.

Application-lineage result records use protocol `schema_version: 4`. The
analyzer retains a separate compatibility path for historical v3 controlled
marker datasets, so the two measurement definitions cannot be pooled.

1. **SYGMA OCI-hook arm**: the image policy is preloaded in Redis. During
   container creation, the OCI hook installs the mandatory phase graphs and
   namespace/process gates, plus typed policy configuration when the deployed
   BPF layout supports it, before returning control to the runtime.
2. **Tetragon Kubernetes arm**: the `TracingPolicyNamespaced` is preloaded and
   its sensor is already enabled. Runtime hooks are disabled. After the pod is
   created, Tetragon's Kubernetes informer learns the pod/container identity
   and asynchronously adds the container cgroup to the policy-filter map. A
   separate timestamp-only OCI prestart hook records the common origin and
   returns immediately; it performs no Tetragon or SYGMA policy operation.

The primary safety claim is not that SYGMA policy setup takes zero time. It is
that SYGMA finishes setup before release, so the number of application calls
executed while the policy is unavailable is zero. Tetragon enrollment may
finish before, during, or after the timestamp-only hook; all three outcomes are
retained.

The second arm should not be described simply as an "operator applies the
policy." The per-container delay under test is the Kubernetes
informer/policy-filter arm path in the Tetragon agent. The Tetragon operator
manages CRDs and related control-plane objects, but it is not a pod-by-pod
enforcement worker in this data path.

## Fixed policy and workload

- Architecture: x86-64 only.
- Counted target: every syscall issued after the real server executable is
  `exec`'d, including calls from subsequently forked tasks and threads.
- Workload profiles: `nginx`, `redis`, `httpd`, `mysql` (original single-process
  targets, retained for reference/comparison), plus the eight DeathStarBench
  Hotel Reservation core microservices (`hotel-frontend`, `hotel-geo`,
  `hotel-profile`, `hotel-rate`, `hotel-recommendation`, `hotel-reservation`,
  `hotel-search`, `hotel-user`) and the ten Google Online Boutique services
  (`boutique-ad`, `boutique-cart`, `boutique-checkout`, `boutique-currency`,
  `boutique-email`, `boutique-frontend`, `boutique-payment`,
  `boutique-productcatalog`, `boutique-recommendation`, `boutique-shipping`).
  See "Hotel Reservation and Online Boutique profiles" below.
- Real-application aliases: `sygma-gap-{application}:v1` for every name in
  `APPLICATIONS` (`scripts/run_experiment.py`).
- Real-application SYGMA target: the common 10-byte process name `gap-launch`
  at `/opt/gap/gap-launch`.
- Pod container name: `probe`.
- Common label: `app.kubernetes.io/name=sygma-gap-probe`.
- Arm label: `gap.sygma.io/backend=sygma` or `tetragon`.
- Tetragon measurement annotation: `gap.sygma.io/prestart-timeline=v1`.
- Default Tetragon policy-filter polling period: 200 microseconds.
- Default measured duration: 5 s, followed by the same 5 s non-measurement
  evidence hold in both arms.
- Runtime result in both arms: calls are observed only; blocking actions are
  disabled.

The SYGMA Pod still carries `sygma.io/mode=enforcement` because that is the
hook's legacy routing token for the policy-installation path, as opposed to its
training/collection path. It is not a claim that this build blocks calls: the
campaign core is hard-wired observation-only, its BPF object contains no
signal/override helper, and the ptrace tracer always resumes the syscall.

Each application image bakes the same static PID-1 launcher as `gap-launch`.
It emits lifecycle timestamps, starts the ordinary image entrypoint, stops the
application at the five-second measurement deadline, and then keeps only PID 1
alive for the evidence hold. It does not generate a target syscall workload.
Application stdout/stderr remains in `/tmp/startup-gap-app.log`.

The observation-only core attaches to `raw_tracepoint/sys_enter`. Tracking
begins only when the configured target binary name (`nginx`, `redis-server`,
`httpd`, `mysqld`/`mariadbd` for the original four profiles; the actual
service executable -- e.g. `frontend`, `geo`, `cartservice`, `checkoutservice`
-- for the Hotel Reservation/Online Boutique profiles) completes `exec`, then
follows `sched_process_fork`. The target name is not hardcoded in the BPF
core: the tracer resolves it per trial from the `--application` value baked
into the carrier image's `gap-launch` invocation (see `images/Dockerfile.*`),
the same way the NRI plugin resolves it from the container's own args
(`extractBinaryNameFromArgs` in `ocihook/nri/main.go`). This is what makes
adding a new real-application profile a matter of a new Dockerfile and image,
not a BPF/core rebuild. Counts are keyed by cgroup
ID and stored both as a syscall-number histogram and 100-microsecond time bins.
The bins yield a conservative number definitely before Tetragon's last-absent
bound and possibly before its first-present bound.

The runner classifies SYGMA atomicity evidence as `proven`, `violation`, or
`unevaluable`; a missing lifecycle marker is never counted as an ordering
violation. By default, up to two replacement attempts are allowed only when a
SYGMA container reports Kubernetes `StartError`, exit 128, an
`oci_prestart_abort` record, and no application/probe execution. Every rejected
attempt remains in `infrastructure-failures.jsonl` with the exact hook failure
text and raw artifact paths. Any failure after application execution, including
an atomicity-order violation, is not retryable. Set
`INFRASTRUCTURE_RETRIES=0` to disable replacement attempts.

The Tetragon `raw_syscalls/sys_enter` policy uses only non-blocking `Post`, with `rateLimit: 10s` and
`rateLimitScope: process`. This produces one positive selector-match event per
trial without a 1 kHz exporter stream. The runner correlates it by namespace,
Pod name, container name, full container ID, and tracepoint name. Its event and
delivery timestamps are auxiliary evidence only: readiness timing always
comes from the policy-filter map interval `(L,U]`.

The SYGMA Redis template mirrors
`sygma-operator/pkg/storage/manager.go` exactly:

- valid syscall universe: `0..334` plus `424..448` (360 syscalls);
- phase 0: START source `500` and every valid syscall source, all with a
  45-byte big-endian allow-all mask (361 rows);
- phase 1 sequence: every valid source and destination (360 rows);
- a Redis `main_policy` descriptor declaring the same policy as `sequence`
  for typed-map-capable deployments; and
- 24-hour TTLs, matching the storage manager.

The phase-1 graph is an allow-all observation policy over the defined 360-call
x86-64 universe. It is installed before release; no syscall is denied.

The hook code can address two SYGMA sequence-engine layouts:

- **Legacy sequence layout:** `syscall_graph_map` exists, but
  `policy_config_map` is not pinned. The hook reads the policy type (or assumes
  `sequence` when the Redis descriptor is absent), loads phase 0 and phase 1
  into `syscall_graph_map`, and can fall back to graph-only observation.
- **Typed-map layout:** the typed policy maps are pinned. The hook loads the
  same phase graphs, confirms the full typed-map set can be opened, and
  additionally writes the namespace sequence configuration to
  `policy_config_map`.

Fallback is deliberately limited to sequence policies. DFA and phase policies
must not be downgraded to a legacy graph, and a partial/broken typed-map set is
an instrumentation error rather than a valid fallback. This explains hook
compatibility, but it does **not** make both core binaries interchangeable:
the audited campaign core has a 28-byte `process_state_map` value and cannot
reuse a pinned 20-byte map. Publication runs therefore require the complete
typed layout. The 20-byte layout is historical/diagnostic only unless a
separate non-blocking legacy core artifact and trust anchor are built and
audited. The runner rejects it before the canary.

## Hotel Reservation and Online Boutique profiles

Added 2026-08-20 to move the RQ3 startup-policy-activation-gap workloads from
single-process daemons (Nginx/httpd/Redis/MySQL) to real multi-container
microservice benchmarks, matching the Hotel Reservation deployment already
used in `../performance-eval`. The four legacy profiles are unchanged and
still run exactly as before; the new profiles are pure additions.

**Hotel Reservation** (DeathStarBench, `~/git/DeathStarBench/hotelReservation`):
the eight core application microservices, i.e. every deployment whose
container uses the shared `deathstarbench/hotel-reservation` image (matching
`HOTEL_APPLICATION_BINARIES` in `../performance-eval/benchmark/benchmark_lib.py`).
Supporting containers (MongoDB, memcached, Consul, Jaeger) are out of scope,
same as in the performance evaluation.

| Application | Base image (pinned) | In-image binary |
| --- | --- | --- |
| `hotel-frontend`, `hotel-geo`, `hotel-profile`, `hotel-rate`, `hotel-recommendation`, `hotel-reservation`, `hotel-search`, `hotel-user` | `docker.io/deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436` | `/go/bin/<service>` |

The published image has no per-service default command -- every binary is
compiled to `/go/bin/<service>` and the upstream Helm chart picks one via a
Pod-level `command:` override. `images/Dockerfile.hotel-*` bakes that choice
into the image instead (`ENTRYPOINT [..., "/go/bin/<service>"]`, `CMD []`),
so each derived image is a self-sufficient single-service carrier, matching
how `../performance-eval` rewrites `./<service>` to `/go/bin/<service>` for
the same reason (image `WORKDIR` is `/workspace`, not where the compiled
binaries live). Because each trial runs one container without its MongoDB/
Consul dependencies, the service is expected to start, `exec`, and then loop
retrying its unreachable dependencies -- sufficient for measuring policy
activation timing relative to the first application syscall, not a health
check.

**Online Boutique** (Google `~/git/microservices-demo`): all ten backend
services in the official `release/kubernetes-manifests.yaml`, each with its
own already-standalone published image (`v0.10.3`), covering four languages.

| Application | Service | Base image digest | Entrypoint |
| --- | --- | --- | --- |
| `boutique-ad` | adservice (Java) | `...adservice@sha256:ff1a059b...` | `/app/build/install/hipstershop/bin/AdService` |
| `boutique-cart` | cartservice (.NET/Go) | `...cartservice@sha256:598efe87...` | `/app/cartservice` |
| `boutique-checkout` | checkoutservice (Go) | `...checkoutservice@sha256:6688da87...` | `/src/checkoutservice` |
| `boutique-currency` | currencyservice (Node) | `...currencyservice@sha256:f7d6e530...` | `node server.js` |
| `boutique-email` | emailservice (Python) | `...emailservice@sha256:59558f8e...` | `python email_server.py` |
| `boutique-frontend` | frontend (Go) | `...frontend@sha256:83f44050...` | `/src/server` |
| `boutique-payment` | paymentservice (Node) | `...paymentservice@sha256:d95567da...` | `node index.js` |
| `boutique-productcatalog` | productcatalogservice (Go) | `...productcatalogservice@sha256:c358001d...` | `/src/server` |
| `boutique-recommendation` | recommendationservice (Python) | `...recommendationservice@sha256:2f3eae32...` | `python recommendation_server.py` |
| `boutique-shipping` | shippingservice (Go) | `...shippingservice@sha256:b0125be4...` | `/src/shippingservice` |

(Full digests are in `scripts/build_application_image.sh`'s
`default_base_images`.) Every Boutique base image already has a complete,
self-sufficient `ENTRYPOINT` and a null `CMD`, so `images/Dockerfile.boutique-*`
reproduces the base `ENTRYPOINT` verbatim after `gap-launch ... --`, the same
pattern the original nginx/redis/httpd/mysql Dockerfiles use. `loadgenerator`
(a client, not a server under test) and `shoppingassistantservice` (not in
the released manifest) are excluded. `redis-cart` (cartservice's own Redis
dependency) is infrastructure, not an application container, and is out of
scope for the same reason MongoDB/Consul are out of scope for Hotel
Reservation.

Both binary-detection paths used by this experiment are dynamic, not
hardcoded to the original four names -- see the note in "Fixed policy and
workload" above -- so no BPF core, tracer, or hook rebuild was required to
add these 18 profiles. What *was* required, and has been done:

- `scripts/run_experiment.py`: `APPLICATIONS` extended (drives `--application`
  validation, image alias, and Redis-policy binary name -- unchanged at
  `gap-launch`, since that is always the intercepted PID 1, not the child).
- `scripts/run_application_campaigns.sh` and
  `scripts/launch_application_campaign_nohup.sh`: the application allowlist
  and `*_IMAGE` environment-variable lookup are now table/convention-driven
  (`<APPLICATION_UPPER_SNAKE>_IMAGE`, e.g. `HOTEL_FRONTEND_IMAGE`,
  `BOUTIQUE_PAYMENT_IMAGE`) instead of a 4-way hand-written case statement.
- `scripts/build_application_image.sh`: `default_base_images`,
  `expected_base_entrypoints`, and `expected_derived_entrypoints` extended
  for all 18 profiles; a new `expected_derived_cmds` override table handles
  the Hotel Reservation profiles' CMD, which resets to `null` instead of
  being preserved (their base CMD is the placeholder `["bash"]`, not a real
  default). All 18 images have been built and verified locally with this
  script (`--application <name> --image sygma-gap-<name>:TAG`) -- byte-
  identical launcher, matching ENTRYPOINT/CMD/platform, no push.
- `ocihook/nri/main.go`: `validateTimelineOnlyTarget`'s application allowlist
  (used only to gate the Tetragon arm's timestamp-only prestart marker)
  extended to the 18 new names. Rebuilt and `go vet`/`go test` locally; **not
  installed** on the node.

What remains before a real campaign can run includes the following local-build
and shared node/cluster operations:

1. Run `../../local-workloads.sh build`, copy its archive/checksum/lock to
   every target node, and run `load` there. The command covers all 34 images,
   imports digest references for `imagePullPolicy: Never`, and generates the
   local `campaign-images.env`; no registry publication is required.
2. **Reinstall the updated `ocihook/nri` plugin** (`/opt/nri/plugins/00-sygma`)
   on the target node -- a node-maintenance operation per "Preparation"
   above, since it replaces the live audited trust anchor other workloads on
   this cluster may depend on.
3. **`prepare_sygma_policy.py`** against the live Redis instance for each new
   profile (mutates shared policy state).
4. Run `scripts/run_application_campaigns.sh` with
   `APPLICATIONS="hotel-frontend hotel-geo ..."` (and similarly for
   `boutique-*`) for the actual 100-trial measured campaign.

## Files

```text
startup-gap-eval/
├── README.md
├── MATCHED_STACK_ROLLOUT.md
├── build/
│   ├── gap-probe
│   ├── policy-map-watch
│   └── sygma-nri-current
├── images/
│   ├── Dockerfile.httpd
│   ├── Dockerfile.mysql
│   ├── Dockerfile.nginx
│   └── Dockerfile.redis
├── manifests/
│   ├── namespace.yaml
│   └── tetragon-policy.yaml
├── mapwatch/
│   └── policy_map_watch.c
├── scripts/
│   ├── analyze.py
│   ├── build.sh
│   ├── build_application_image.sh
│   ├── build_observation_core_image.sh
│   ├── install_instrumented_hook.sh
│   ├── prepare_sygma_policy.py
│   ├── restore_hook.sh
│   ├── run_experiment.py
│   └── stage_observation_stack.sh
├── tests/
│   ├── test_analyze.py
│   ├── test_application_images.py
│   ├── test_gap_probe.py
│   └── test_runner.py
└── workload/
    └── gap_probe.c
```

The full runner stores trial inputs under
`raw/<trial_id>/{container.log,wrapper.log,probe.jsonl,mapwatch.jsonl,`
`hook-timeline.jsonl,pod.json}` and one normalized record per trial in
`trials.jsonl`. `container.log` is the lossless Kubernetes container log;
`wrapper.log` preserves the SYGMA wrapper diagnostics, while `probe.jsonl`
contains only the probe's JSON records. Raw data is immutable; rerun analysis
instead of editing it.

Each `results/<run_id>/` also contains `metadata.json`, `commands.jsonl`,
`trials.csv`, `summary.json`, and `summary.csv`. A failed campaign retains its
partial records and adds `RUN_FAILED.txt`; never merge those partial records
silently into a valid campaign.

## Current test environment

Observed on 2026-08-02; capture the same information again in every result
directory because any of it may change:

| Component | Observed value |
| --- | --- |
| Node | one node, `master` |
| Kubernetes / kubelet | v1.29.1 |
| Runtime | containerd 1.7.24 |
| Kernel / architecture | Linux 5.15.0-177-generic, amd64 |
| Tetragon agent image | `quay.io/cilium/tetragon:v1.4.0` |
| Tetragon agent | DaemonSet 1/1 Ready |
| Policy filter | enabled |
| Runtime-hook DaemonSet | absent (required for the primary Tetragon arm) |
| Relevant CRDs | `TracingPolicy` and `TracingPolicyNamespaced` installed |
| Last observed SYGMA core | legacy 20-byte ABI, observation-only; no core Pod is currently running |
| SYGMA campaign prerequisite | audited typed 28-byte observation core and matching hook/tracer/wrapper/NRI |

The current node is not campaign-ready: quiesce managed container creation,
remove the stale legacy pinned-map generation in a maintenance window, deploy
the audited typed observation core, stage matching hook/tracer/wrapper/NRI
binaries, and install the instrumented hook and NRI plugin.
The runner requires the running `/usr/daemon/core` and installed host binaries
to match `build/sygma-{core,tracer,wrapper,nri}-current` and
`build/sygma-hook` before its canary and measured trials.

At the time of inspection, kube-system also retained many Evicted pod objects
and Hubble Relay was restarting. Do not use a noisy or resource-pressured run
for publication results. Record CPU pressure, disk pressure, pod restarts, and
all active observability agents before each campaign.

### Historical enforcement diagnostic

The single-trial diagnostic run in
[`results/smoke-sched204-diagnostic-20260802-r1`](results/smoke-sched204-diagnostic-20260802-r1)
validates the map-watcher mechanics, but it used the old blocking protocol and
is **not** an observation-only A/B result.
For that one Tetragon trial, the policy-filter insertion lay in the conservative
interval 836.031839--836.268953 ms after probe start (0.237114 ms interval
width); the first `EPERM` occurred at 837.000090 ms, after 837 successful
attempts. All 837 were definitely before the lower insertion bound.

Those EPERM-based validity labels and old blocking artifacts are obsolete
under the new protocol. The current typed-only requirement instead comes from
the audited core's 28-byte pinned-map ABI. Do not mix historical artifacts with
new trials. Collect a fresh campaign in which both arms keep every timed call
successful.

Useful environment capture commands are:

```sh
uname -a
kubectl get nodes -o wide
kubectl -n kube-system get ds tetragon
kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon -o wide
kubectl -n kube-system get configmap tetragon-config \
  -o jsonpath='{.data.enable-policy-filter}{"\n"}'
kubectl -n kube-system get ds -l app.kubernetes.io/name=tetragon-rthooks
kubectl get crd tracingpolicies.cilium.io \
  tracingpoliciesnamespaced.cilium.io
```

## Preparation

Build the native tools and run the deterministic policy checks:

```sh
cd SYGMA-Q3/manifest/startup-gap-eval
./scripts/build.sh
./scripts/prepare_sygma_policy.py --self-test
./scripts/prepare_sygma_policy.py --dry-run
```

Rebuild and stage the exact observation-only core, tracer, wrapper, and NRI
trust anchors. This command also regenerates the BPF object, rejects
policy-blocking helpers, and runs the Go tests/vet checks:

```sh
./scripts/stage_observation_stack.sh
```

Build the Q3 stack from the profile root. The canonical builder copies the
audited host binaries into the image, uses a neutral local tag, and saves an
archive without publishing it:

```sh
cd ../..
./local-images.sh build
./local-images.sh load
```

The builder records binary and image identifiers under `artifacts/local/`.
It also stages the exact core/hook/tracer/wrapper/NRI binaries placed in the
images under this harness's `build/` trust-anchor names. The separate
`local-workloads.sh build` command writes a local `campaign-images.env`; the
launcher consumes that environment without a registry publication step.
The runner identifies container `name=core`, then verifies its immutable
digest, unmodified entrypoint, and live binary hash. The ordinary legacy
`sygma_eBPF/Dockerfile` is not a campaign build path.

Changing from the historical 20-byte core to this 28-byte core is a pinned-map
ABI transition. In a node maintenance window, stop the old core, ensure no
SYGMA-managed workload is running, record map metadata for provenance, and let
the old core perform its graceful pin cleanup (or use the project's scoped
SYGMA map cleanup procedure). Never delete or replace live namespace/process
state beneath a running core. Deploy the new core image by registry digest and
wait for it to create the complete typed map set before installing the hook or
starting the canary.

Build and install the hook containing the BOOTTIME timeline markers before a
smoke trial. This uses a short-lived privileged Pod pinned to the target node,
preserves the previously installed hook at
`/usr/local/bin/sygma-hook.pre-startup-gap-eval` once, atomically replaces only
that host binary, and verifies its hash:

```sh
./scripts/install_instrumented_hook.sh \
  --redis-addr REDIS_HOST:6379 --node master
```

`--build-only` avoids the host installation. Separately rebuild/redeploy the
observation core and install the matching tracer/wrapper/NRI generation. The
NRI binary at `/opt/nri/plugins/00-sygma` supplies the Tetragon timestamp-only
hook adjustment, so merely replacing `/usr/local/bin/sygma-hook` is
insufficient. Replacing or restarting the NRI plugin/containerd is a node
maintenance operation: quiesce managed container creation, install
`build/sygma-nri-current`, restart it using the deployment's normal procedure,
and verify its host hash before the canary. The runner compares all five
audited artifacts with the running/installed hashes. The legacy
`--allow-hook-hash-mismatch` applies only to the hook;
`--diagnostic-allow-sygma-artifact-mismatch` is the explicit all-component
override. Either makes the run diagnostic and not publication-eligible. After
the campaign, restore the audited hook backup with:

```sh
./scripts/restore_hook.sh --node master
```

For the synthetic profile, pre-pull one carrier image with a writable
`/bin/sh` on every target node and use the same immutable image digest in both
arms. The runner mounts the static probe from a ConfigMap and sets the logical
SYGMA alias to `sygma-gap-probe:v1`.

For a real-application profile, build an immutable derived image. The audited
defaults below are the exact locally inspected linux/amd64 bases; changing a
base digest requires re-auditing its ENTRYPOINT and CMD.

| Profile | Default base |
| --- | --- |
| nginx | `docker.io/library/nginx@sha256:c7a6ad68be85142c7fe1089e48faa1e7c7166a194caa9180ddea66345876b9d2` |
| redis | `docker.io/library/redis@sha256:a7cee7c8178ff9b5297cb109e6240f5072cdaaafd775ce6b586c3c704b06458e` |
| httpd | `docker.io/library/httpd@sha256:374766f5bc5977c9b72fdb8ae3ed05b7fc89060e7edc88fcbf142d6988e58eeb` |
| mysql | `docker.io/library/mysql@sha256:c6812f0dcd978b589d9d3b90c20bd5e4a799deab4fd492985e0a076c5be1ee40` |

Build all 34 derived application images as one local-only bundle from the
profile root:

```sh
cd ../..
./local-workloads.sh build
./local-workloads.sh load
```

The helper invokes the audited per-application builder, uses
`localhost/sygma-q3/workload-*:artifact-v1` references, records image/config
digests in a lock file, and saves one tar archive. It never logs in or
publishes. Copy and import that same archive on every selected node before
using `imagePullPolicy: Never`.

Both arms of one application campaign must use the same locked workload
digest. MySQL uses a fresh writable layer and
`MYSQL_ALLOW_EMPTY_PASSWORD=yes` in every trial; do not attach a reused data
volume because that would make arm order affect startup behavior.

Create the isolated namespace:

```sh
kubectl apply -f manifests/namespace.yaml
```

Preload and verify the SYGMA policy. Supply the Redis DB 0 address reachable
from the machine running this command:

```sh
./scripts/prepare_sygma_policy.py --redis-addr REDIS_HOST:6379
./scripts/prepare_sygma_policy.py \
  --redis-addr REDIS_HOST:6379 --verify-only
```

The script speaks RESP2 directly and has no non-standard Python dependency.
It reuses the unique alias's image ID, refuses to clean an ID owned by another
image, removes only keys belonging to that ID, writes all rows in one Redis
transaction, and then verifies every mask, metadata value, Redis
`main_policy` descriptor, key set, and TTL. Do not run two copies concurrently.
Run it immediately before a campaign so the 24-hour TTL cannot expire mid-run.

Preload the Tetragon policy once, before creating any measured pod:

```sh
kubectl apply -f manifests/tetragon-policy.yaml
tetra tracingpolicy list
```

Wait until `observe-uname` is enabled on the target Tetragon agent,
then resolve and record its numeric policy-filter ID. Do not delete/reapply the
policy between trials: that would mix sensor-load latency into the per-pod arm
latency this experiment is intended to measure.

For the primary Tetragon arm, confirm that Tetragon runtime hooks are not
installed. For the SYGMA arm, confirm that the SYGMA OCI hook is installed and
that its readiness gate and pinned maps are healthy. In particular,
perform and save a SYGMA engine-layout preflight:

```sh
sudo bpftool map show pinned /sys/fs/bpf/sygma/syscall_graph_map
for map in policy_config_map policy_state_rule_map \
  policy_state_transition_map policy_location_transition_map \
  policy_decision_map; do
  if sudo test -e "/sys/fs/bpf/sygma/${map}"; then
    echo "${map}: present"
  else
    echo "${map}: absent"
  fi
done
```

A state where `policy_config_map` exists but any other typed map is absent is
invalid. A fully absent typed set identifies the historical legacy 20-byte
layout and is rejected by this campaign. A fully present set must expose the
typed 28-byte layout. Verify the Redis phase-1 graph has 359 rows and source
63 is absent. The mandatory readiness canary
must place `sygma_direct_policy_ready` before probe start and every timed call
must succeed. Save map IDs and ABI sizes, component hashes, hook hash, and the
selected layout in campaign metadata.

Keep both systems running across the campaign; the backend label ensures the
Tetragon policy does not select SYGMA trial pods.

Run the orchestrated campaign with explicit, recorded parameters. The default
runner uses 100 measured blocks and 10 warm-up blocks per arm; this example
uses the more conservative 20 warm-ups described below:

```sh
python3 scripts/run_experiment.py \
  --application synthetic \
  --trials 100 \
  --warmups 20 \
  --node master \
  --carrier-image CARRIER_IMAGE_AT_FIXED_DIGEST \
  --observer-image OBSERVER_IMAGE_AT_FIXED_DIGEST \
  --image-pull-policy Never \
  --redis-addr REDIS_HOST:6379
```

Run each service as its own campaign so image startup cost and invalid-trial
rates remain attributable. Use the same node, timing parameters, trial count,
seed, and observer digest across all four:

```sh
python3 scripts/run_experiment.py --application nginx \
  --run-id nginx-CAMPAIGN_ID --trials 100 --warmups 20 --node master \
  --carrier-image REGISTRY/sygma-gap-nginx@sha256:DERIVED_DIGEST \
  --observer-image OBSERVER_IMAGE_AT_FIXED_DIGEST \
  --image-pull-policy Never --redis-addr REDIS_HOST:6379

python3 scripts/run_experiment.py --application redis \
  --run-id redis-CAMPAIGN_ID --trials 100 --warmups 20 --node master \
  --carrier-image REGISTRY/sygma-gap-redis@sha256:DERIVED_DIGEST \
  --observer-image OBSERVER_IMAGE_AT_FIXED_DIGEST \
  --image-pull-policy Never --redis-addr REDIS_HOST:6379

python3 scripts/run_experiment.py --application httpd \
  --run-id httpd-CAMPAIGN_ID --trials 100 --warmups 20 --node master \
  --carrier-image REGISTRY/sygma-gap-httpd@sha256:DERIVED_DIGEST \
  --observer-image OBSERVER_IMAGE_AT_FIXED_DIGEST \
  --image-pull-policy Never --redis-addr REDIS_HOST:6379

python3 scripts/run_experiment.py --application mysql \
  --run-id mysql-CAMPAIGN_ID --trials 100 --warmups 20 --node master \
  --carrier-image REGISTRY/sygma-gap-mysql@sha256:DERIVED_DIGEST \
  --observer-image OBSERVER_IMAGE_AT_FIXED_DIGEST \
  --image-pull-policy Never --redis-addr REDIS_HOST:6379
```

To run all four application campaigns under `nohup`, use the sequential
wrapper below. Do not start four background runners: they share the namespace,
observer name, Tetragon policy, ConfigMaps, and SYGMA policy rows. Each
application image must be the derived `gap-launch` image, not the base image,
and all five digest references must already be present in the target node's
CRI store when using `Never`.

```sh
cd SYGMA-Q3/manifest/startup-gap-eval

export CAMPAIGN_ID="atomicity-$(date -u +%Y%m%dT%H%M%SZ)-$$"
export NODE_NAME=master
export NAMESPACE=sygma-gap-eval
export REDIS_ADDR=172.16.0.120:6379

export OBSERVER_IMAGE='REGISTRY/observer@sha256:REPLACE_WITH_64_HEX'
export NGINX_IMAGE='REGISTRY/sygma-gap-nginx@sha256:REPLACE_WITH_64_HEX'
export REDIS_IMAGE='REGISTRY/sygma-gap-redis@sha256:REPLACE_WITH_64_HEX'
export HTTPD_IMAGE='REGISTRY/sygma-gap-httpd@sha256:REPLACE_WITH_64_HEX'
export MYSQL_IMAGE='REGISTRY/sygma-gap-mysql@sha256:REPLACE_WITH_64_HEX'

export TRIALS=100
export WARMUPS=20
export DURATION_MS=5000
export EVIDENCE_HOLD_MS=5000
export INTERVAL_US=1000
export MAP_POLL_US=200
export SEED=20260802
export IMAGE_PULL_POLICY=Never

log_root="${PWD}/nohup-logs"
log_dir="${log_root}/${CAMPAIGN_ID}"
mkdir -p -- "${log_root}"
if [[ -e "${log_dir}" ]]; then
  printf 'Refusing to overwrite existing log directory: %s\n' "${log_dir}" >&2
  exit 1
fi
mkdir -- "${log_dir}"
nohup ./scripts/run_application_campaigns.sh \
  >"${log_dir}/campaign.log" 2>&1 </dev/null &
campaign_pid=$!
printf '%s\n' "${campaign_pid}" >"${log_dir}/pid"
printf 'PID=%s\nLOG=%s\n' "${campaign_pid}" "${log_dir}/campaign.log"
```

Monitor or request a graceful stop with:

```sh
tail -F "${log_dir}/campaign.log"
ps -fp "$(cat "${log_dir}/pid")"
kill "$(cat "${log_dir}/pid")"
```

The wrapper builds the two native measurement tools once, then runs nginx,
Redis, httpd, and MySQL in that order with identical timing and randomization
parameters. A host lock prevents overlapping copies. A non-zero runner exit,
`RUN_FAILED.txt`, `CLEANUP_FAILED.txt`, any invalid/censored measured trial,
an excluded pair, or a failed SYGMA atomicity invariant stops the sequence
before the next application. A successful application therefore has 100 valid
pairs and 100 evaluated SYGMA atomicity proofs in its `summary.json` under the
parameters above.

To continue after a completed application's gate without overwriting its raw
results, start a new campaign ID and select only the remaining applications,
for example `APPLICATIONS='httpd mysql'`. Each selected application still runs
its complete predeclared warm-up and 100-pair measurement schedule; an existing
partial result directory is never edited in place.

The runner builds the native tools unless `--skip-build` is given, creates the
observer and binary ConfigMaps, preloads and waits for the Tetragon policy,
prepares/verifies the Redis policy, generates a seeded interleaved schedule,
executes an unmeasured SYGMA readiness canary, collects raw artifacts, and
invokes the analyzer. The canary requires the hook marker before probe start
and only successful attempts; it is recorded in `sygma-canary.json`. Calls from
the same OCI process after hook release but before `probe_start` are retained as
pre-probe coverage evidence and reported as
`non_probe_target_calls_observed`; they do not invalidate a canary whose
controlled attempts are all covered. The runner also refuses the primary
Tetragon arm when `enable-policy-filter` is not true or CRI/runtime identity
integration is enabled, unless an explicit diagnostic override is supplied.
Before installing its own policy, it snapshots every cluster and namespaced
Tetragon policy and fails if any pre-existing selector can match either arm's
selected application label set plus container `name=probe`. Non-matching
policies are retained and recorded; the runner never deletes user policies.
Use `python3 scripts/run_experiment.py --help` for the complete interface.
`--diagnostic-skip-sygma-readiness-canary` (and its compatibility alias
`--diagnostic-skip-sygma-canary`) exists only to exercise collectors; any run
carrying it is diagnostic and must never be pooled with primary results.

Primary mode also refuses a mutable carrier reference or a pull policy other
than `Never`. Every trial records the runtime-resolved `status.imageID` and
must match the requested `IMAGE@sha256:...` digest. The mutable `latest`
default exists only for diagnostics used while bringing up a local stack.
Metadata distinguishes runner-host command output from the authoritative
target-node `status.nodeInfo`, records the resolved images of every target-node
Pod across all namespaces, running `/usr/daemon/core` hash, host
hook/tracer/wrapper/NRI hashes, source snapshot hash, and pinned-map
IDs/types/key/value sizes. The required typed critical map ABI, including
`process_state_map` HASH/key-4/value-32 and `blocked_history`
HASH/key-20/value-4 plus process-attributed `observed_misses`
HASH/key-20/value-4, is validated before the canary.

To re-run analysis without changing raw data:

```sh
python3 scripts/analyze.py results/RUN_ID
python3 -m unittest discover -s tests -v
```

## Trial protocol

Use a randomized, interleaved block order rather than running all SYGMA trials
and then all Tetragon trials. Before measured trials, run a fixed warm-up set
(at least 20 per arm is recommended) and exclude it from results. Collect at
least **100 valid measured trials per arm**; increase that count if bootstrap
confidence intervals remain wide.

For each trial:

1. Confirm that the previous pod is deleted and the relevant SYGMA namespace
   maps are clean. Snapshot all Tetragon baseline IDs; Tetragon 1.4 may retain
   a deleted Pod's key, so do not mistake a baseline key for a new insertion.
2. Start `policy_map_watch` before submitting the Tetragon pod and wait for its
   `watch_ready` record. Its baseline must not already contain the trial
   cgroup.
3. Submit exactly one pod, pinned to the same node and using the preloaded
   image. Save the Pod UID, node, full container ID, restart count, Kubernetes
   conditions, and runtime `startedAt` in `pod.json`. For a real profile, also
   require one `app_spawn`, a matching positive child PID, and
   `app_alive_at_summary=true`; an application that exits during measurement
   invalidates the trial even if the marker loop itself completed.
4. Preserve the complete container output as `container.log`, split recognized
   `[sygma-wrapper]` lines into `wrapper.log`, and feed only JSON records to
   `probe.jsonl`. Reject every unrecognized non-empty line. The runtime log may
   be fetched after termination because it already contains the startup bytes;
   exporter receipt time is never used as a measurement timestamp.
5. For SYGMA, capture `oci_prestart_enter`,
   `sygma_direct_policy_ready`, `target_release_begin`,
   `target_release_signal_sent`, and `oci_prestart_complete` as
   `hook-timeline.jsonl`. The direct-policy-ready marker is emitted only after
   phase graphs, typed namespace-policy configuration, namespace gates, and
   process-state initialization all succeed. Before deletion, the runner also
   reads the exact `(mnt_ns,pid_ns)` entry from `pid_mount_ns_map`: a value
   greater than 1 is the BPF-side first-policy-evaluation BOOTTIME timestamp.
   Enforce the ordering
   `enter <= ready <= release_begin <= release_signal <= complete <= probe_start <= attempt.before`
   as a correctness gate, not as a statistic. During the probe's post-summary
   evidence hold, also require the exact legacy-internal `observed_misses` sum for
   `(mnt_ns,pid_ns,tgid=hook.host_pid,to_syscall=63,phase=1)` to equal
   `probe_summary.attempts` in two consecutive snapshots, while phase 0 and
   all other phases remain zero. TGID attribution excludes the child service's
   own syscalls. This counter means **policy-evaluated would-deny calls**, not
   calls missed by SYGMA. The snapshot is a validity oracle, not the readiness
   timestamp. After deletion, require exactly one
   `sygma_cleanup_complete` marker; its absence invalidates the trial.
6. For Tetragon, require exactly one `oci_prestart_enter` and
   `oci_prestart_complete` from the `timestamp-only` hook role. Validate its
   full container ID, Pod UID, trial, backend, and application, and reject any
   SYGMA ready/release/cleanup event in this arm. Then capture the policy-filter
   insertion bracket as `mapwatch.jsonl`, and correlate the inserted cgroup ID to this trial's
   container rather than accepting any newly observed cgroup. Poll the
   rate-limited `export-stdout` stream for up to five seconds and save any
   exactly correlated `process_kprobe` Post event as auxiliary positive
   evidence. Never use its timestamp for the readiness metric. Absence is
   expected when map insertion occurs at or after probe end and does not by
   itself invalidate the trial.
7. The launcher emits `probe_summary` immediately after its measured window,
   then remains alive for `--evidence-hold-ms` (default 5000) so live SYGMA
   maps can be snapshotted before poststop cleanup. The hold contains no target
   `uname` calls and is excluded from all gap/miss metrics. In a real profile,
   the service remains alive during this hold; the launcher then terminates and
   reaps its process group and emits one cleanup-phase `app_exit`. Collect the
   raw artifacts after the hold and delete the pod.
   Record whether Tetragon removed the target key; a retained baseline is
   tolerated because the next watcher ignores existing IDs and exact probe
   cgroup correlation prevents misattribution. The policy is deleted at the
   end of the campaign to release all retained inner-map state.

Unless `--keep-resources` is set, final cleanup independently removes all
experiment-labelled Pods, the namespaced Tetragon policy, and the two binary
ConfigMaps. It intentionally retains the namespace because it may have
pre-existed the run. A partial cleanup is recorded as `CLEANUP_FAILED.txt`.

A trial is invalid—not a zero-gap success—if the pod restarts, the image is
pulled, any JSON line is lost or malformed, the map watcher was not ready,
the cgroup cannot be correlated, either common prestart boundary is missing or
misidentified, a syscall before/after bracket is missing, the hook reports an error, the policy ID
changes, the selected real application dies before summary, or cleanup times
out.
Every timed call in both arms must succeed; any `EPERM` or other syscall error
invalidates the trial. A Tetragon trial without a map insertion is invalid,
not a censored denial result.
Report invalid counts and reasons separately.

## Clock and event model

`CLOCK_BOOTTIME` nanoseconds are the canonical latency clock. Both native
tools also emit `CLOCK_REALTIME` nanoseconds for joining external records and
debugging. Each attempt has `before_*` and `after_*` syscall boundaries; the
map insertion record provides `last_absent_*` and `first_present_*` fields.

Use only BOOTTIME values from the same node for subtraction. Do not subtract a
Kubernetes RFC3339 timestamp, Tetragon exporter receipt time, or controller log
time from a BOOTTIME value. `pod.json` wall-clock timestamps are provenance,
not sub-millisecond measurement data. The `api_submit_*` and `api_ack_*`
fields have `api_clock_domain=runner_host`; use them only with each other
unless the runner is independently proven to be the target node. On a
multi-node cluster, the runner selects the Tetragon agent and runs the map and
hook collectors on the scheduled node; NTP synchronization does not make
cross-node sub-millisecond subtraction valid.

Operational event definitions are:

| Symbol | Definition |
| --- | --- |
| `H0` | `oci_prestart_enter.boottime_ns`, captured as the hook process's first measured operation, before log opening or OCI state decoding, in both arms |
| `C` | `oci_prestart_complete.boottime_ns`, the last marker before the hook returns |
| `P` | probe `probe_start.boottime_ns`; controlled marker-workload start, not the first arbitrary container instruction |
| `A_i^-`, `A_i^+` | `attempt.before_boottime_ns` immediately before syscall 63 and `attempt.after_boottime_ns` immediately after return |
| `R_s` | `sygma_direct_policy_ready`, after phase graphs, namespace policy/gates, and process state are installed |
| `B_s`, `S_s` | `target_release_begin` and `target_release_signal_sent` |
| `L_tet` | conservative lower bound: Pod-submit-preceding `watch_ready` time for the first poll, otherwise the **beginning** of the most recent full enumeration in which the target key was absent |
| `U_tet` | end of the first enumeration that contains that cgroup; under the target-key monotonicity control, true Tetragon arm time lies in `(L_tet, U_tet]` |
| `t_sygma_eval` | optional BPF-stored first-policy-evaluation BOOTTIME value from the exact namespace map key |

The standalone map watcher defaults to 1 ms; the campaign runner explicitly
uses 200 µs unless `--map-poll-us` changes it. Always report the recorded
interval-censored arm time instead of presenting `U_tet` as an exact instant.
The midpoint is acceptable for a plot only if the half-poll-width uncertainty
is also shown.

The watcher timestamps each enumeration on both sides. It deliberately does
not use the timestamp *after* an absent enumeration as `L_tet`: an insertion
could occur between enumeration completion and that timestamp. After an
absent poll it carries that poll's begin time forward, then pairs it with the
end time of the first present poll. This is conservative by one enumeration
duration but preserves the claimed bound. It is valid only while the target
key is not deleted before Pod teardown; the runner enforces that trial order
and preserves the baseline/post-delete snapshots.

## Metrics

Compute per-trial values before aggregating:

- **SYGMA policy-setup latency**: exact `R_s - H0`.
- **Tetragon enrollment latency from prestart**: signed interval
  `[L_tet - H0, U_tet - H0]`. Report `ready` when `U_tet <= H0`,
  `unavailable` when `L_tet >= H0`, and `ambiguous` otherwise.
- **Userland exposure**: SYGMA is exactly zero only after the ordering gate
  `H0 <= R_s <= B_s <= S_s <= C <= P <= every A_i^-` passes. Tetragon's
  interval is `[max(0,L_tet-P), max(0,U_tet-P)]`.
- **Tetragon uncovered controlled calls**: definite calls satisfy
  `A_i^+ <= L_tet`; possible calls satisfy `A_i^- <= U_tet`. Using the
  post-syscall timestamp for the definite endpoint avoids claiming a complete
  call was missed when enrollment could have occurred between timestamping and
  syscall entry.
- **SYGMA controlled calls outside coverage**: zero for every valid atomicity
  trial. Separately report `sygma_policy_observed_attempts=N`,
  `sygma_controlled_attempts_unobserved=0`, and coverage `1.0` from the exact
  policy-path evidence counter.
- **Additional uncovered calls versus SYGMA**: within each measured `mNNN` randomized
  block, report interval subtraction: lower = Tetragon definite minus SYGMA
  possible, upper = Tetragon possible minus SYGMA definite. Exclude a pair if
  either member is invalid, missing, or duplicated, and report every exclusion
  reason and the remaining paired sample size. Pair identifiers include the
  application name, so identically numbered nginx/MySQL/etc. blocks can never
  be paired across profiles.
- **Hook cost**: report `C-H0` for both arms. The timestamp-only hook delays
  Tetragon user-code start while its asynchronous path can continue, so it
  biases observed Tetragon exposure and uncovered-call counts downward.

Report the full empirical distribution, median, p95, p99, mean, standard
deviation, and a bootstrap 95% confidence interval for gap and missed-count
metrics. Include an ECDF or violin/box plot with every raw trial available.
Do not hide zeroes, invalid trials, timeouts, or the polling/cadence resolution.
`trials.csv` contains exact per-trial timestamps and counts;
`summary.json` and `summary.csv` provide backend-by-application groups,
campaign-level SYGMA atomicity violations/unevaluable trials, and
per-application paired Tetragon-minus-SYGMA uncovered-call intervals.

## Optional third arm: Tetragon runtime hook via NRI

After completing the two primary arms, a useful diagnostic is the same
Tetragon policy with Tetragon Runtime Hooks enabled using the containerd NRI
interface (`rthooks.enabled=true`, `rthooks.interface=nri-hook`). Tetragon's
create-container runtime callback supplies pod labels, container ID, and cgroup
ID directly to `AddPodContainer` so the policy filter is populated before the
container starts. This arm tests whether moving identity propagation into the
runtime path closes the Kubernetes informer gap.

Treat it as a separate backend and campaign. Enabling NRI changes node/runtime
configuration and may restart containerd or Tetragon; never mix those trials
with the primary Tetragon arm. Record hook failure policy and timeouts. The
third arm is not evidence about the asynchronous Kubernetes path—it is a
runtime-hook mitigation using the same Tetragon enforcement engine.

## Threats to validity and required controls

- **Preloading:** Redis policy rows and the Tetragon sensor must exist before
  every measured pod. Measuring CR creation conflates a different latency.
- **Phase boundary:** verify that SYGMA reaches the selected target's main
  phase (`gap-probe` for synthetic, `gap-launch` for a real profile) before
  interpreting probe attempts. This phase transition is required in the
  typed-map sequence layout; phase 0 deliberately permits syscall 63.
- **Application liveness:** the common launcher must remain PID 1 and the
  ordinary service entrypoint must run as its child in the same cgroup. Do not
  replace the design with an initContainer or sidecar. Require application
  liveness through summary, use a fresh MySQL layer, and keep native service
  syscalls out of the controlled uncovered-call count.
- **SYGMA engine layout:** the audited campaign requires the complete typed
  28-byte sequence ABI. A legacy 20-byte or partial typed-map set, or any
  component hash mismatch, invalidates the campaign; observation-only behavior
  is required.
- **Policy-map proxy:** a policy-filter map insertion is the closest direct arm
  observation. Validate selector operation with a rate-limited, exactly
  correlated Tetragon Post event, but do not use event delivery as a clock.
- **Sampling:** the default 1 ms probe cadence and 200 µs runner map polling
  quantize gap and count. Preserve interval bounds and do not claim
  nanosecond accuracy from ns fields.
- **Observer effect:** `Post` is rate-limited to once per process per 10 seconds.
  Collectors must be running before pod start and should be pinned away from
  the probe CPU when possible. The Tetragon arm's timestamp-only prestart hook
  is measurement instrumentation, not Tetragon identity/enforcement. Report
  its duration and disclose that the extra barrier time favors Tetragon by
  giving asynchronous enrollment more time before controlled calls begin.
- **Image/runtime cache:** preload the identical image; reject image-pull and
  first-unpack trials. Keep runtime, snapshotter, cgroup mode, and pod QoS fixed.
- **Stale identity:** correlate Pod UID, full container ID, cgroup ID, node, and
  policy ID. A new map key from an unrelated pod is not an arm event.
- **Cleanup:** require the `sygma_cleanup_complete` gate for every SYGMA trial.
  Tetragon 1.4 can retain deleted-Pod keys; preserve the full baseline and
  post-delete snapshot, reject ID reuse/timeouts, and delete the policy after
  the campaign rather than treating a stale baseline ID as a new insertion.
- **Non-blocking invariant:** every timed syscall must succeed. Any signal,
  `EPERM`, or other syscall error indicates that a blocking path is still
  active and invalidates the campaign.
- **Architecture:** syscall number 63 and the direct assembly are x86-64
  specific; do not silently run this workload on arm64.
- **Load and ordering:** randomize arm order, pin the node, record resource
  pressure, and avoid upgrades, autoscaling, or unrelated deployments during
  collection.
- **Clock discontinuity:** reject trials spanning reboot; record suspend and
  resume. BOOTTIME includes suspend, which is useful for kernel alignment but
  makes a suspended trial invalid for startup latency.

The primary claim should be limited to this measured configuration: with both
policies preloaded, SYGMA's runtime-gated OCI-hook path publishes policy state
before release and therefore executes zero controlled target calls while
unavailable, while Tetragon's Kubernetes informer/policy-filter path may leave
a finite number of controlled calls uncovered after the same lifecycle origin.
This is release atomicity, not a claim that every multi-map update is a general
transaction. The experiment does not imply that
all Tetragon deployment modes have that gap; the optional NRI arm explicitly
tests its runtime-hook alternative.
