# SYGMA bootstrap wrapper

SYGMA wraps the container's initial executable, not the detected application
binary. This avoids intercepting helper invocations of the application binary
(for example, the MySQL entrypoint's `mysqld --verbose --help` probe).

## Lifecycle

1. NRI reads the unmodified container arguments. It separately determines:
   - the initial executable: `container.Args[0]`;
   - the eventual main binary used for the phase transition.
2. NRI bind-mounts `/opt/sygma` and passes both values to the OCI prestart
   hook. It does not modify the command line, which keeps this implementation
   compatible with the NRI v0.6.1 API in containerd 1.7.
3. The prestart hook replaces only the initial executable:
   - `INITIAL` is renamed to `INITIAL.real`;
   - the static wrapper is copied to `INITIAL`.
4. The wrapper stops once for tracer attachment, installs the seccomp filter,
   and execs `INITIAL.real` with the original arguments and environment.
5. Seccomp is inherited by all forked and execed processes. The tracer follows
   those processes during INIT and transitions to MAIN only when the configured
   main binary is execed by the target PID.

The application binary itself is never renamed or replaced. Consequently,
entrypoint probes and helper children invoke the original application binary
normally.

## Expected MySQL sequence

```text
wrapper (PID 1, replacing docker-entrypoint.sh)
  -> docker-entrypoint.sh.real
     -> child mysqld probes (unmodified /usr/sbin/mysqld)
     -> exec /usr/sbin/mysqld as PID 1
```

The tracer INIT options include `PTRACE_O_TRACESECCOMP`, because the bootstrap
filter is active before the original entrypoint is executed.

The tracer is monitoring-only in both collection and enforcement deployments.
The obsolete `blocked_syscalls_map` and syscall-register rewriting path were
removed; policy misses are recorded by the eBPF `blocked_history` map. During
availability evaluation, `observed_transition_map` records every phase-0 edge
and its event count. Its predecessor is maintained independently in
`observation_state_map`, so one policy miss cannot create a cascade of
artificial follow-on misses.

## Instrumentation readiness and cleanup

The prestart hook is a fail-closed readiness barrier for instrumentation (not
for syscalls). In enforcement mode it loads the phase-0 policy directly,
requires a `from=500` START row, initializes the namespace gates, and creates
both the root `process_state_map` entry and its `tid_to_namespace` link before
resuming the wrapper. Failure aborts container creation; it never enables
syscall blocking.

The Redis `container:ns:<container-id>` record stores the PID namespace, mount
namespace, and host root PID. OCI poststop commonly reports `pid: 0`, so this
record is the authoritative cleanup identity. Poststop removes namespace graph,
collection, violation, heartbeat, and observed-transition rows, followed by
every linked root/child policy and observation state. It preserves the
TTL-backed Redis identity if any eBPF cleanup step fails, allowing retry and
forensic inspection.
