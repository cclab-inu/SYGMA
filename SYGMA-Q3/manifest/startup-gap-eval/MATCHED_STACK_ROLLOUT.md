# SYGMA observation-only stack prerequisite

## Current node status

The last observed SYGMA deployment had the intended non-blocking generation,
but there is currently no ready SYGMA core DaemonSet/Pod on the node. The
following values are historical provenance, not current readiness:

- core image digest
  `localhost/sygma-q3/core@sha256:c49f004fb4adee5f622b07b84b2bba9d4ffed7fbc4c730df0958f7e9f41c3060`;
- core log: `Observation mode enabled (blocking hooks disabled; policy misses are recorded)`;
- complete legacy 20-byte `process_state_map` sequence ABI; and
- no typed `policy_decision_map`.

That historical deployment is useful provenance but is **not** valid for the
current campaign. The audited observation-only core has a 28-byte
`process_state_map` and requires the complete typed map set; a BPF loader cannot
reuse the pinned 20-byte value layout.

The evaluation target is `uname(63)`. Unlike the former
`sched_getaffinity(204)` target, it traverses the audited policy path.
The runner proves that path per trial by comparing the exact namespace and PID
1 TGID's phase-1 `observed_misses` count for `to_syscall=63` with
`probe_summary.attempts`. TGID attribution prevents nginx, Redis, httpd, or
MySQL child syscalls from contaminating the controlled marker count. Phase 0
and all other phases must remain zero. `observed_misses` is a legacy internal
map name: externally this is the number of policy-evaluated would-deny calls,
not calls missed by SYGMA.

## Required observation contract

Do not deploy a blocking tracer/core for this campaign. Both arms must leave
every timed `uname` call successful:

- SYGMA must not call `bpf_send_signal` or turn a policy miss into `-EPERM`;
- Tetragon must use only rate-limited `Post`, never `Override`, `Signal`,
  `Sigkill`, or `NoPost`;
- the SYGMA OCI hook still installs the policy synchronously and emits
  `sygma_direct_policy_ready` before releasing the target; and
- the Tetragon arm receives only the common timestamp-only prestart marker,
  with no wrapper, tracer, Redis/BPF write, signal, or poststop hook; and
- poststop cleanup must emit exactly one `sygma_cleanup_complete` event.

The campaign requires the complete typed 28-byte layout. A legacy 20-byte or
partial typed-map set is invalid. The runner validates map type/key/value
sizes, including `blocked_history` and `observed_misses` as HASH/key 20/value
4, and records the running core plus host hook/tracer/wrapper/NRI hashes and
source snapshot hash.

## Matched observation-stack rollout

The local audited artifacts are newer than the currently installed host
binaries, and no core is running. Install them only in a node maintenance
window:

1. Quiesce creation of SYGMA-managed containers.
2. Save the current hook and NRI hashes/backups, core digest/log, pinned-map
   ABI, and tracer/wrapper hashes.
3. Run `scripts/stage_observation_stack.sh` to regenerate the BPF object and
   stage the exact typed core, tracer, wrapper, and NRI trust anchors.
4. Stop the old core and, only after confirming no managed workload is live,
   perform the scoped legacy-pin cleanup. Deploy an image built with
   `scripts/build_observation_core_image.sh` from an immutable base that
   provides `sha256sum`, and deploy it by immutable registry digest.
5. Build the hook from the same source snapshot and actual Redis address, then
   install the hook plus the staged tracer/wrapper/NRI so every installed hash
   equals the runner's trust anchor. Replacing the NRI binary is not enough for
   an already running process; restart it using the node's maintenance
   procedure before the canary.
6. Run the unmeasured readiness canary. It must show hook ready before probe
   start, all calls successful, exact phase-1 policy-observed count equal to
   probe attempts in two stable live snapshots, zero phase-0/other-phase
   target misses, and successful cleanup. For a real-application profile it
   must also show one matching app spawn, liveness through probe summary, and
   a cleanup-phase app exit.

Only then collect warm-ups and randomized measured blocks.

## Rollback

Quiesce new containers before rollback. Core, pinned-map ABI, hook, tracer,
wrapper, and NRI must be rolled back as one matched generation; restoring only the hook
across a 20/28-byte ABI boundary is unsafe. Verify every original hash and the
core log. Never restore live PID/namespace map contents from a dump; those
identities are stale.
