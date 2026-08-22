# SYGMA syscall-routing arms

For the complete five-workload, four-arm throughput/latency/resource campaign,
including single- and multi-node commands, use
[`benchmark/README.md`](benchmark/README.md).

Import the locally packaged core, operator, and installer images on every
eligible node before deployment; see [`ARTIFACTS.md`](ARTIFACTS.md). The
evaluation images are intentionally not aliases of the former remote
`latest`/pre-change digest artifacts.

`sygma.yaml` and `sygma-single.yaml` deliberately describe the same
Deployment. Their only content difference is the value of
`sygma.io/seccomp-routing`:

- `selective`: the normal SYGMA hybrid route. Dedicated eBPF-observed and
  asynchronous syscalls bypass ptrace; the remaining synchronous syscalls use
  `SECCOMP_RET_TRACE`.
- `all-trace`: the `sygma-single` mediation arm. The wrapper installs a
  one-instruction filter that returns `SECCOMP_RET_TRACE` for every kernel
  syscall. All calls still incur the ptrace stop. To keep policy-decision work
  identical to the selective arm, the eBPF stage skips state-machine lookup
  for `sched_yield`, `futex`, `epoll_wait`, and `ppoll`, which selective
  routing deliberately leaves outside policy processing.

Apply only one file at a time. Applying the other file updates the pod-template
annotation and rolls the same Deployment:

```sh
kubectl apply -f manifest/performance-eval/sygma.yaml
kubectl rollout status deployment/sygma-routing-example

kubectl apply -f manifest/performance-eval/sygma-single.yaml
kubectl rollout status deployment/sygma-routing-example
```

Before either arm is deployed, publish a policy for the exact same image
reference (preferably the same digest) with a `SYGMAConfig`. For an overhead-only
campaign, use `spec.policy.allowAll: true` and wait until the Config reports
`status.collectionComplete: true`. The operator publishes init and main policy
data behind `policy_ready:<imageID>`; the OCI hook intentionally aborts startup
when that marker is missing or changes while policy maps are being installed.
The operator sample
`sygma-operator/config/samples/security_v1_sygmaconfig_allowall.yaml` shows the
syntax, but its embedded workload image must be changed to match the workload
being measured.

The host-side `SYGMAPolicy` CR compatibility path is disabled by default in
this evaluation build (`SYGMA_POLICY_CR_ENABLED=false`). The hook installs the
policy synchronously before releasing the workload, avoiding an unauthorized
Kubernetes write through kubelet credentials. Enable that compatibility path
only with a dedicated, explicitly authorized host `KUBECONFIG`; it is not part
of either measurement arm.

For the first rollout from the pre-evaluation core, stop the old core and
quiesce SYGMA-managed workloads. The lightweight build changes the pinned
`process_state_map` value ABI from 32 to 28 bytes. At startup, the new core
holds a node-local exclusive loader lock, removes only explicitly named legacy
policy/audit/compression pins, and replaces `process_state_map` only when its
value size is incompatible. It also drops the coupled ephemeral
`tid_to_namespace` map in that case. The same rollout recreates the transient
`collection_graph_map` with `BPF_F_NO_PREALLOC`, eliminating its old empty-map
per-CPU capacity reservation. Restart managed workloads after the core
rollout so the OCI hook recreates their per-TID state; do not treat an in-place
rollout over running traced containers as a valid measurement.

Keep `securityContext.seccompProfile.type: Unconfined` in every evaluated
workload. This prevents a kubelet/runtime-default filter from being stacked
with the wrapper filter and changing which syscalls reach the tracer. The
setting does not disable the wrapper-installed filter.

The routing table and policy bitmap use Linux x86-64 syscall numbers. Run the
campaign only on amd64 nodes; the example manifests enforce this with
`nodeSelector: {kubernetes.io/arch: amd64}`. Do not use the selective arm for a
compat i386 process.

## Interpretation

In the tracer's MAIN phase, each `SECCOMP_RET_TRACE` match produces a
`PTRACE_EVENT_SECCOMP` stop and is resumed unchanged with `PTRACE_CONT`. The
tracer does not inspect arguments or make the policy decision. Consequently,
`sygma-single` is an optimistic lower bound for seccomp-plus-ptrace userspace
mediation, not an implementation of complete userspace enforcement.

`PTRACE_SYSCALL` normally creates separate syscall-entry and syscall-exit
stops. The MAIN `SECCOMP_RET_TRACE` path creates one mediation stop for a
matched syscall because it resumes with `PTRACE_CONT`. Do not label the two
paths as identical.

Measure steady-state service traffic only after readiness and warm-up. The
SYGMA tracer intentionally uses `PTRACE_SYSCALL` during INIT while it locates
the configured main binary, so measurements that include process startup mix
the INIT and MAIN mechanisms.

The policy Redis has no bundled PVC because the repository cannot assume a
StorageClass. Completed configs verify their four minimum publication keys
every 30 seconds and recover after Redis loss; keep Redis stable and confirm
the config has returned to `Completed` before starting any sample.

## Preflight checks

- Confirm the wrapper log reports either `selective` with 300 filter
  instructions or `all-trace` with 1 instruction.
- Confirm the hook log reports a stable published policy revision before the
  namespace is activated.
- On the first lightweight-core rollout, confirm its log either preserves an
  already compatible 28-byte process-state map or reports the one-time
  32-to-28-byte migration before declaring readiness.
- Confirm a host-side tracer remains attached for the whole sample. Without a
  tracer, a syscall matching `SECCOMP_RET_TRACE` is not executed and returns
  `-ENOSYS`.
- Verify readiness and error logs before collecting data, especially for
  blocking calls such as `futex`, `epoll_wait`, and `ppoll`, which are routed
  through ptrace only in `all-trace`.
- Use the same policy, image digest, CPU placement, warm-up, load generator,
  and collection window for both arms.

For Hotel Reservation, check two existing bootstrap constraints before a
campaign. Commands such as `./frontend` must resolve to a verifiable executable
path for wrapper replacement; abort if the hook reports that the replacement
path is unavailable. Also remember that `sygma.io/*` annotations are pod-wide:
an injected sidecar is another NRI target and can invalidate the comparison.
Use the sidecar-free evaluation deployment or otherwise verify every adjusted
container before measuring.

Kernel semantics are documented in the Linux
[seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
and the Linux [`ptrace(2)` manual](https://man7.org/linux/man-pages/man2/ptrace.2.html).
