# Reproducible Kubernetes performance campaign

This directory runs the five workloads (`nginx`, `httpd`, `redis`, `mysql`,
and DeathStarBench Hotel Reservation) against four execution arms:

| Arm | Workload seccomp | Active data plane |
|---|---|---|
| `default` | Kubernetes `Unconfined` | Tetragon and SYGMA request-path components stopped (idle host caveat below) |
| `tetragon` | Kubernetes `Unconfined` | namespaced `raw_syscalls/sys_enter` tracepoint policy |
| `sygma` | wrapper filter | selective hybrid syscall routing |
| `sygma-all-trace` | wrapper filter | `SECCOMP_RET_TRACE` for every syscall |

The runner redeploys a fresh workload for every trial, warms it up, snapshots
SYGMA route counters, starts resource sampling, runs the load, snapshots the
counters again, and rejects samples with restarts, changed container IDs,
load errors, or too few resource samples. Repetitions use a rotated arm order
by default; `--randomize` uses the recorded deterministic seed instead.
Pod readiness alone is not treated as endpoint readiness: the runner waits up
to `--endpoint-timeout` (60 seconds by default) for the NodePort data path to
accept a connection before warm-up.

This is a steady-state service experiment. MySQL database preparation and all
warm-up traffic occur outside the measured route/resource window.

## What is measured

- HTTP and Hotel Reservation: fixed offered rate with local `wrk2`, corrected
  coordinated-omission latency (`-L`), throughput, average and percentile
  latency, and HTTP/socket errors.
- Redis: closed-loop `redis-benchmark` GET and SET throughput and latency. The
  default five million requests are chosen to provide a useful CPU sampling
  window; Redis is request-count bounded rather than `--duration` bounded.
- MySQL: `sysbench oltp_read_write` transaction throughput and latency. By
  default the run is `--duration` bounded; setting `--mysql-events N` makes
  every arm complete the same number of transactions with `--time=0`, while
  database preparation and warm-up remain time bounded.
- CPU and memory: Metrics API values from `kubectl top pods -A --containers`
  every five seconds, summed per timestamp into `workload`, active `framework`,
  and `node` scopes. Reports contain mean, p95, and maximum. These are
  metrics-server/cAdvisor working-set samples, not process RSS or cycle counts.
- SYGMA routes: monotonic, node-local per-CPU decision-route counter deltas for
  the exact measured interval.

The three SYGMA counters mean:

| Counter | Counted event |
|---|---|
| `conventional_sigkill` | a managed syscall reaches a dedicated conventional/SIGKILL-route entry probe and invokes `Policy_Decision` |
| `lsm_bpf` | a managed syscall reaches a dedicated LSM-BPF-route entry probe and invokes `Policy_Decision` |
| `ptrace_notify` | a managed `ptrace_notify` event reaches stage 2 and invokes `Policy_Decision` |

They count policy-decision route hits, not denials or delivered SIGKILLs. The
evaluation policy is `allowAll`, and the lightweight core is observation-only.
The counter map adds one per-CPU array increment at each decision call; it does
not restore logging, compression, audit emission, or userspace event handling.

The Tetragon arm is an eBPF tracing comparison, not a userspace-enforcement
implementation. Its `Post` action is rate-limited to one event per process per
minute so the campaign measures the syscall tracepoint/selector path without
turning stdout export volume into the independent variable. Describe this
configuration explicitly in a paper.

## Prerequisites

Run on dedicated amd64 Kubernetes nodes. The load generator runs on the host
that invokes `run.sh`, so it must be able to reach the chosen node's NodePort.
Install these before starting:

- a working Kubernetes context with every selected node `Ready`;
- metrics-server (`kubectl top pods -A --containers` must succeed);
- Tetragon and its `TracingPolicyNamespaced` CRD;
- the SYGMA CRDs and performance stack from this repository;
- `kubectl`, `helm`, Python 3 with PyYAML, `wrk`, the checked-out
  DeathStarBench `wrk2`, `redis-benchmark`, and `sysbench` on the load host;
- the DeathStarBench checkout at `/workspace/git/DeathStarBench`, or matching
  `--hotel-chart` and `--wrk2` overrides.

The current local cluster must pass these checks before a real run:

```sh
kubectl get nodes -o wide
kubectl top pods -A --containers
kubectl get crd tracingpoliciesnamespaced.cilium.io
kubectl get crd sygmaconfigs.security.security.io
```

A `NotReady` node, kubelet certificate/hostname mismatch, missing metrics API,
or unresolved NodePort route is a hard preflight failure. Do not collect a
partial campaign and label it valid.

Build the anonymous Q4 source images, import them on every eligible node, and
deploy SYGMA:

```sh
cd ../../..
./local-images.sh build
./local-images.sh load
./local-images.sh deploy
```

For a remote worker, copy the generated `artifacts/local/` tar and checksum
and run `load` there as well. This is a `q4-source` successor build. The
identity-bearing paper-time tar is post-acceptance only; see
[`../ARTIFACTS.md`](../ARTIFACTS.md).

Pin all workload image references by digest for paper runs. The runner records
the resolved image ID of every application and dependency container and the
analyzer rejects a campaign if one declared image reference resolves to more
than one ID. Override primary workload images with repeated `--image` flags,
for example:

```sh
--image nginx=nginx@sha256:... \
--image hotel=deathstarbench/hotel-reservation@sha256:...
```

Pin Hotel backing-store images in the local Helm chart as well. `IfNotPresent`
prevents trial-to-trial pulls but is not a substitute for a digest.

## One-touch single-node run

Use `managed` switching only on a dedicated experimental cluster. It scales
the SYGMA operator/store and Tetragon operator, and disables/enables the
competing core/Tetragon DaemonSets through temporary impossible node
selectors. Original replicas and selectors are restored even after an error.

```sh
cd SYGMA-Q4/manifest/performance-eval/benchmark
./run.sh \
  --topology single \
  --workload-node NODE_NAME \
  --stack-management managed \
  --confirm-dedicated-cluster \
  --workloads all \
  --modes all \
  --repetitions 5 \
  --duration 60 \
  --warmup 20 \
  --cooldown 10 \
  --http-rate 5000 \
  --hotel-rate 500
```

If exactly one Ready schedulable node matches, `--workload-node` may be
omitted. Calibrate `--http-rate` and `--hotel-rate` in a separate default-only
pilot, then freeze them below saturation for every arm. Do not choose a new
offered rate per arm: that makes latency incomparable.

The managed default arm stops the SYGMA core, operator, and policy store, but
the installer `keeper` Pod and an already installed host NRI plugin remain
idle after Pod creation. The keeper is excluded from `framework` metrics; host
effects remain visible in the node scope. For a strict pristine-default claim,
run the default arm on an otherwise identical clean node image with the NRI
plugin absent, using `--stack-management external`. State this distinction in
reported results.

## Multi-node run

Label a homogeneous node pool, import the image bundle on every node, and use
the label as the selection boundary:

```sh
kubectl label node worker-a worker-b worker-c sygma.io/perf-node=true

./run.sh \
  --topology multi \
  --node-selector sygma.io/perf-node=true \
  --target-replicas 3 \
  --endpoint-host NODEPORT_REACHABLE_IP \
  --stack-management managed \
  --confirm-dedicated-cluster \
  --workloads all \
  --modes all \
  --repetitions 5
```

With `--target-replicas` greater than one, target application Pods receive a
best-effort hostname topology-spread constraint. For Hotel Reservation, only
the eight application microservice Deployments are scaled; backing stores keep
the chart's replica counts. Route snapshots are taken from every node hosting
a target Pod and summed. Resource samples include all workload/dependency Pods
in the campaign namespace.

Use the same CPU model, kernel, container runtime, frequency governor, node
labels, replica count, and client placement for all arms. A multi-node NodePort
test includes network and kube-proxy/CNI effects; report them as part of the
testbed rather than treating results as syscall-only microbenchmarks.

## External switching

`--stack-management external` never changes framework Deployments or
DaemonSets. It is intended for a wrapper/orchestrator that activates exactly
one data plane before each requested subset. Do not pass all four modes to one
external run while leaving both stacks active. A safe pattern is one campaign
per already-configured arm followed by an explicit cross-campaign analysis.

## Validation and dry-run

Render every workload/arm without contacting the server-side API:

```sh
./run.sh --render-only --workloads all --modes all \
  --node-selector kubernetes.io/hostname=example
python3 -m unittest -v test_benchmark.py
```

`--render-only` still requires the local Hotel chart, Helm, and kubectl client.
It uses `kubectl create --dry-run=client --validate=false` and does not deploy.

## Results

Each campaign is written below `results/CAMPAIGN_ID/`:

- `metadata.json`: arguments, selected nodes, kernels/runtimes, image inputs;
- `plan.json`: exact rotated/randomized trial order;
- `commands.jsonl`: commands, timing, exit status, and output sizes;
- `raw/*/`: rendered YAML, load/warm-up logs, resource samples, Pod/image
  evidence, and before/after route snapshots;
- `trials.jsonl`: one self-contained record per valid or rejected trial;
- `trial-metrics.csv`: flattened trial-level values;
- `summary.csv` and `summary.json`: per-workload/per-arm mean, median, sample
  standard deviation, and two-sided Student-t 95% confidence interval.

The analyzer excludes invalid trials but reports their reasons. `--continue-on-error`
allows the campaign to finish after a rejected sample; it does not silently
promote that sample. Re-run rejected repetitions under the same fixed plan and
retain the original raw directory for audit.

The runner's signal handler stops scheduling new trials and the `finally`
path restores managed stack state. If restoration fails, it writes
`RESTORE_FAILED.txt`; inspect and restore the named resources before any next
campaign.
