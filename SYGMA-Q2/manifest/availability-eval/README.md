# SYGMA initialization-policy availability evaluation

This runner measures only the initialization phase. It repeatedly creates a
fresh enforcement Pod and records phase-0 policy misses from
`blocked_history`. Main-phase misses are intentionally outside this
experiment.

The evaluation eBPF build must observe policy misses without killing the
process or returning `EPERM`. A Pod becoming Ready is therefore the actual
non-blocking deployment outcome, while `init_violation=1` is the
counterfactual result for fail-closed initialization enforcement.

## Required detector build

The running `core` process must pin all of these maps under
`/sys/fs/bpf/sygma`:

- `blocked_history`
- `transition_check_count`
- `syscall_graph_map`
- `pid_mount_ns_map`
- `execution_time_map`
- `process_state_map`
- `tid_to_namespace`
- `container_info_map`

`transition_check_count` is the detector-liveness heartbeat. Its ABI is:

```c
struct transition_check_key {
    __u32 mntns;
    __u32 pidns;
    __u32 phase;
};
// BPF_MAP_TYPE_HASH, value: __u64
```

Stage 2 increments it immediately before the policy graph lookup. For every
valid iteration, the exact container namespace's phase-0 counter must increase
relative to the snapshot taken immediately before Pod creation. A missing map,
wrong ABI, full counter map, replaced map ID, or non-increasing phase-0
heartbeat stops the experiment instead of being counted as zero violations.

Rebuild and restart the eBPF program and OCI hook before using this runner.
Old pinned maps from an incompatible build must not be reused.

## Host prerequisites

- A working SYGMA operator, hook, NRI integration, CRDs, and Redis.
- `kubectl`, `crictl`, `bpftool`, and Python 3 on the measurement node.
- Permission to inspect the local CRI runtime, `/proc/<host-pid>/ns/*`, and
  `/sys/fs/bpf/sygma`. Run the driver as root when needed.
- The workload must run on the same node as this script. These manifests and
  the runner target the original single-node experiment environment.
- Do not run another Pod with the same fixed workload name during the
  experiment.

The BPF pin root can be changed with `SYGMA_BPF_PIN`, although the hook and
`core` must use the same location.

## What makes an iteration valid

Before measured iteration 1, the runner creates one unmeasured enforcement
Pod as a fail-fast preflight and identity baseline. It verifies the same
detector conditions as a measured deployment and leaves that Pod running.
Iteration 1 must delete it and create a different Pod and container.

For every measured iteration, the runner:

1. verifies that the currently running Pod still has the expected UID and
   full container ID;
2. sends `kubectl delete --wait=false`, then polls the exact Pod UID until
   `NotFound`; a transient nonzero kubectl exit is accepted only when the
   final `NotFound` state is independently observed, while a different UID is
   never deleted;
3. polls the previous exact namespace until `poststop` has removed its
   syscall graph, namespace gates, blocked/heartbeat rows, container identity,
   root process state, and all `tid_to_namespace` links; a leftover or full
   map invalidates the run;
4. uses the clean `blocked_history` and `transition_check_count` snapshots as
   the next deployment's baseline;
5. uses `kubectl create`, which fails rather than accepting an
   `apply ... unchanged` result;
6. obtains the new Pod UID and the target container's full container ID and
   requires both to differ from the preceding deployment;
7. runs `crictl inspect` with that full ID, requires `status.id` to match
   exactly, and derives one PID and mount namespace pair from the container
   host PID's `/proc` namespace links;
8. requires an exact-namespace phase-0 graph with a START row
   (`from_syscall=500`), `pid_mount_ns_map`, an `execution_time_map` value of
   exactly 1 proving that the main-binary exec boundary was observed, a root
   `process_state_map` entry with a nonzero enforcement image ID, its exact
   `tid_to_namespace` link, and `container_info_map`;
9. requires the exact `{mntns,pidns,phase=0}` transition heartbeat to
   increase;
10. computes only exact-namespace, phase-0 `blocked_history` counter deltas;
11. re-reads the Pod and rejects an in-iteration restart or identity change.

Namespace lookup by container-name substring is not used. A missing or
ambiguous identity, policy/setup failure, detector-liveness failure, map
restart, deletion failure, or cleanup failure writes `valid=0` with an
`invalid_reason` and stops the experiment. Violation fields in that row remain
empty; an invalid iteration is never reported as zero misses.

## Run

First validate the four applications with two measured deployments each:

```sh
sudo -v
sudo -E env KUBECONFIG=/workspace/.kube/config \
  python3 -u run.py \
  --apps nginx redis mysql httpd \
  --iterations 2 \
  --output results/smoke-2
```

Run the full experiment in the background:

```sh
mkdir -p results/full-1000
sudo -v
sudo -E env KUBECONFIG=/workspace/.kube/config \
  nohup python3 -u run.py \
  --apps nginx redis mysql httpd \
  --iterations 1000 \
  --output results/full-1000 \
  > results/full-1000/experiment.log 2>&1 < /dev/null &
echo $! > results/full-1000/experiment.pid
```

Follow it with:

```sh
tail -f results/full-1000/experiment.log
```

Stop it gracefully with:

```sh
kill "$(cat results/full-1000/experiment.pid)"
```

Use `--skip-training` only when all four image policies still exist in Redis.
This does not bypass validation: the exact phase-0 graph and all detector maps
must still be installed for the preflight Pod.

### Resume a strict checkpoint

If a run stops after checkpointing valid iterations, rerun it with the same
total `--iterations`, the same `--output`, and `--resume`. Do not replace the
total with only the remaining count.

```sh
RUN_DIR=results/full-1000-20260730T050427Z
sudo -v
sudo -E env KUBECONFIG=/workspace/.kube/config \
  nohup python3 -u run.py \
  --apps nginx redis mysql httpd \
  --iterations 1000 \
  --resume \
  --output "$RUN_DIR" \
  >> "$RUN_DIR/experiment.log" 2>&1 < /dev/null &
echo $! > "$RUN_DIR/resume.pid"
```

Resume mode validates the CSV/JSONL schema, contiguous iteration numbers,
preflight-to-iteration identity chain, current counter-map IDs, retained
SYGMAConfig image ID, exact last Pod identity (if it still exists), and
poststop cleanup for an already-absent Pod. For runs created by the current
runner, persisted metadata additionally pins the SYGMAConfig UID/generation
and both manifest fingerprints. A progressed application is not retrained. An
application with no checkpoint still follows the normal training and
preflight path. A completed application is skipped only after its exact last
Pod is absent and namespace cleanup is verified.

Only one terminal row without deployment measurements can be retried. Before
removing that row from the active checkpoint, the runner copies the original
CSV, JSONL, summary, and preflight into
`operational-errors/<app>-<timestamp>/` and records the event in
`<app>-operational-errors.jsonl`. It then appends from that iteration; existing
valid rows are never rewritten as new measurements. Resume validation events
are recorded in `<app>-resume.jsonl`.

Without `--resume`, an output directory containing an application's
checkpoint is rejected instead of overwritten. An exclusive `.run.lock`
prevents two runners from changing the same output directory concurrently.
JSONL is fsynced before its derived CSV row; if a crash leaves JSONL exactly
one record ahead, resume reconstructs that CSV row and archives the torn pair.

Useful timeout options are `--ready-timeout`, `--instrumentation-timeout`,
`--delete-timeout`, and `--training-timeout`. There is no fixed post-Ready
sleep and no main-phase observation interval. The instrumentation timeout is
bounded polling for the exact BPF setup and phase-boundary marker, which
avoids racing Pods that have no readiness probe.

## Results

Each application produces:

- `<app>-preflight.json`: the unmeasured setup/liveness validation;
- `<app>-run-metadata.json`: namespace, total target, manifest hashes,
  SYGMAConfig identity, and initial BPF map IDs for strict future resume;
- `<app>-iterations.csv`: one checkpointed row per attempted iteration;
- `<app>-violations.jsonl`: exact phase-0 transitions and instrumentation
  evidence for each iteration;
- `<app>-summary.json`: counts and rates whose denominator is only valid
  iterations.

Important CSV fields include `valid`, `invalid_reason`, both old and new Pod
and container identities, the exact host PID and namespaces, phase-0 graph
rows, process image ID, heartbeat before/after/delta, and the two counter-map
IDs.

`experiment_complete` is true only if every requested iteration exists and is
valid. `counterfactual_init_policy_failure_rate_among_valid` never divides by
invalid or unattempted iterations.

Run the runner unit tests with:

```sh
python3 -m unittest -v test_run.py
```
