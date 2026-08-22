# SYGMA Evaluated Reference Source

This directory contains the common/reference surviving SYGMA source layout. It
is an architectural baseline; it
is not a claim that Q2, Q3, and Q4 used one byte-identical executable.

This particular surviving snapshot is the observation/performance reference
build: it evaluates policy decisions and hybrid routes but leaves syscall
results unchanged and contains no signal, override-return, `-EPERM`, or BPF-LSM
blocking action. It must not be labeled as the complete enforcement build.

## Layout

- `sygma_eBPF/`: kernel-side policy lookup, state tracking, and routing logic.
- `ocihook/`: OCI hook, ptrace tracer, seccomp wrapper, and containerd NRI
  integration.
- `sygma-operator/`: Kubernetes CRDs, policy construction, and Redis-backed
  policy publication.
- `manifest/`: common deployment and example workload manifests.
- `IMPLEMENTATION.md`: the detailed documentation retained from the source
  working tree.

The generated bpf2go binding and embedded object are retained so the surviving
source can be built immediately. The canonical anonymous build is:

```sh
./local-images.sh build
./local-images.sh load
./local-images.sh deploy
```

This builds the core, route snapshot helper, OCI/NRI components, and operator;
packages three neutral local images; writes checksums; and saves a transfer
archive plus config/manifest digest lock under `artifacts/local/`. It never
logs in or pushes. Deployment
requires a dedicated x86-64 Linux/Kubernetes environment with BPF, containerd
NRI, OCI hook, Redis, and privileged access to the host BPF filesystem.

The current reference source evolved after some paper measurements. Exact
paper results must therefore cite one of the Q-specific profiles, not this
directory alone.
