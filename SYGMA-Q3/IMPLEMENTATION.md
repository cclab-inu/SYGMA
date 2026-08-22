# SYGMA: A Zero-Trust syscall Enforcement Framework for Containerized Microservices

## Environment

| Application | Version     | Application | Version            |
| ----------- | ----------- | ----------- | ------------------ |
| Ubuntu      | 22.04.5 LTS | Kernel      | 5.15.0-168-generic |
| Kubernetes  | 1.29.1      | containerd  | 2.2.1              |
| runc        | 1.3.4       | go          | 1.24.11            |



## Setup

```shell
# SETUP
$ sudo apt install -y gcc make libbpf-dev
# Optional only when rebuilding the checked-in BPF object:
$ sudo apt install -y clang-14 llvm-14 gcc-multilib

# All SYGMA source needed by the anonymous build is already included in this
# profile. No external source checkout is part of the canonical workflow.

$ cat /sys/kernel/security/lsm
# If it does not display as shown below, you need to edit it using the vi editor.
# GRUB_CMDLINE_LINUX="lsm=ndlock,lockdown,yama,integrity,apparmor,bpf"
$ sudo vi /etc/default/grub

$ sudo update-grub2
$ sudo init 6
```



## Deploy SYGMA

```shell
# Predeployment phase
# Deploy SYGMA & SYGMAConfig

$ cd SYGMA-Q3
$ ./local-images.sh build
# Copy artifacts/local/ with the same source tree and run this on every
# eligible Kubernetes node.
$ ./local-images.sh load
# Run once from the control-plane/build host after every node is loaded.
$ ./local-images.sh deploy

# Optional: use an explicit Redis endpoint instead of the ready Redis Pod's
# host IP discovered by deploy.sh.
$ REDIS_ADDR=192.0.2.10:6379 ./local-images.sh deploy

$ kubectl apply -f manifest/nginx-sygmaconfig.yaml
$ kubectl get pods -o wide
# Wait until the collection Pod is fully deleted and the config is Completed.
$ kubectl get sygmaconfig nginx-sygma-config -w
```

`deploy.sh` installs both SYGMA CRDs and waits for them to become established.
It then waits for the host-network Redis Pod, creates or updates `sygma-config`
with `data.redis-addr`, and only then starts the core, Config Operator, and
host installer. To update that ConfigMap separately, run `./config_set.sh
HOST:PORT` (or set `REDIS_ADDR`). The helper restarts any existing Config
Operator and host-installer DaemonSet so every node atomically rewrites
`/etc/nri/sygma-redis-addr` before containerd reloads the NRI plugin.

The evaluation DaemonSet keeps only a sleeping 1m CPU/8MiB container after
its privileged installer completes; it does not run the redundant
`SYGMAPolicy --mode=agent` watch controller on every node. The synchronous OCI
hook path is authoritative for policy installation in this build.

The policy-store Redis Pod and `redis-service` use the dedicated label
`app.kubernetes.io/name=sygma-policy-redis`. Benchmark Redis Pods may continue
to use `app=redis` without becoming endpoints of the policy-store Service.
The policy-store Deployment is named `sygma-policy-redis`, so an evaluated
Redis workload may use its normal `redis` name. An installation created from
the former policy-store `deployment/redis` must remove that old Deployment and
republish its policies during a planned migration. `deploy.sh` detects its
legacy host-port reservation and fails with an explicit migration message; it
never deletes policy data automatically.

The repository does not assume a cluster StorageClass, so this Redis
Deployment is not backed by a bundled PVC. Completed configs revalidate the
ready marker, main policy, image metadata, and init START row every 30 seconds;
after Redis loss, allow-all configs republish and explicit state machines
re-enter init collection. The store uses `noeviction` so a ready marker cannot
outlive a partially evicted payload. Wait for recovery to finish before a
measurement window.

Every `SYGMAConfig` must select exactly one main-policy mode under
`spec.policy`:

```yaml
# Production-style, explicitly configured state machine.
policy:
  stateMachine:
    initialState: 0
    states:
      "0":
        allowedSyscalls: [0, 1, 60, 231]
    transitions: {}
```

```yaml
# Evaluation-only wildcard. Policy lookup remains active, but every supported
# syscall is allowed.
policy:
  allowAll: true
```

The init-phase graph is collected dynamically from `spec.collection`; it is
not supplied as a legacy `thirdParty`, phase, sequence, or DFA field in a
`SYGMAConfig`. The nginx, Redis, HTTPD, and MySQL workload examples all use the
explicit evaluation-only wildcard so the performance campaign cannot confuse
a legacy syscall graph with a typed state machine. For a validated explicit
state-machine example, use
[`sygma-operator/config/samples/security_v1_sygmaconfig.yaml`](sygma-operator/config/samples/security_v1_sygmaconfig.yaml).



## Deploy policy adapted pod

```shell
# Pod deployment phase
$ kubectl apply -f nginx_sygma.yaml
```

## Hybrid observation routing

The x86-64 enforcement routes are synchronized with
`systematic_analysis/output-effective-n-full-patched` for the evaluated Linux
5.15 kernel build.

- Four fork-family syscalls (`clone`, `fork`, `vfork`, and `clone3`) and 141
  additional syscalls use dedicated syscall-entry kprobes for observation.
- `perf_event_open` uses the ptrace observation route because its syscall entry
  is not a safe kprobe target on the evaluated Linux 5.15 kernel.
- In the default `selective` route, the wrapper bypasses ptrace for those 145
  dedicated routes and four asynchronous syscalls. Every other synchronous
  syscall returns `SECCOMP_RET_TRACE` and is observed through `ptrace_notify`.
- This evaluation build evaluates bootstrap and state-machine allow/miss
  decisions but deliberately exports no per-call decision logs or counters and
  does not change syscall results. It contains no signal, override-return,
  `-EPERM`, or BPF LSM enforcement action.

The pod annotation `sygma.io/seccomp-routing` selects the wrapper filter:

```yaml
metadata:
  annotations:
    sygma.io/mode: "enforcement"
    sygma.io/seccomp-routing: "selective"  # or "all-trace"
spec:
  securityContext:
    seccompProfile:
      type: Unconfined
```

An omitted or empty annotation defaults to `selective`; any other non-empty
value fails container adjustment unless it is `selective` or `all-trace`.
`all-trace` is the `sygma-single` evaluation route and installs a
one-instruction filter that returns `SECCOMP_RET_TRACE` for every kernel
syscall. `Unconfined` prevents a kubelet/runtime-default seccomp filter from
being stacked with this experiment's wrapper filter. The selective route and
policy bitmap use x86-64 syscall numbers, so pin evaluated workloads to amd64
nodes and do not use compat i386 processes.

The tracer's MAIN loop resumes each seccomp event unchanged with
`PTRACE_CONT`. It performs no userspace policy decision, so `all-trace` is an
optimistic lower bound for seccomp-plus-ptrace userspace mediation rather than
a complete userspace enforcement implementation. Unlike `PTRACE_SYSCALL`,
which normally stops at both syscall entry and exit, this MAIN path creates one
seccomp mediation stop per matched syscall. Measure after service readiness and
warm-up: the tracer uses `PTRACE_SYSCALL` during INIT while locating the main
binary, so startup-inclusive measurements mix the two mechanisms.

Matched `sygma` and `sygma-single` manifests and preflight notes are in
[`manifest/performance-eval`](manifest/performance-eval/README.md). In
particular, verify that Hotel Reservation's relative commands (for example,
`./frontend`) resolve to a wrapper-replaceable executable and that pod-wide
SYGMA annotations do not unintentionally select injected sidecars.

After changing `monitoring.c`, regenerate the embedded BPF object before
building the daemon:

```shell
cd sygma_eBPF
make generate
go build -buildvcs=false -o core .
```

The first deployment of this performance build must replace the old core while
SYGMA-managed workloads are quiesced. Startup performs a bounded migration of
legacy pinned maps/programs/links before loading the new object and replaces
the old 32-byte `process_state_map` with the 28-byte state-machine-only ABI.
It also recreates the transient `collection_graph_map` once with
`BPF_F_NO_PREALLOC`, avoiding the former 150,000-entry per-CPU reservation
while keeping per-CPU collection semantics for inserted rows.
Restart managed workloads after the core rollout so their per-TID entries are
installed again. New cores also hold an exclusive node-local loader lock
(`/run/sygma-ebpf-loader.lock`, configurable with
`SYGMA_LOADER_LOCK_FILE`) for their lifetime.



## Log statics

```shell
# Watch log
$ kubectl logs ds/core
```
