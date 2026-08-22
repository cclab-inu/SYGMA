# SYGMA Open Science Artifact

This directory contains the source and experiment layout for the SYGMA paper.
The three evaluation profiles are research-question-specific builds rather
than a single binary, since each answers a different paper claim.

## Components

| Directory | Role |
| --- | --- |
| [`SYGMA/`](SYGMA/) | Reference source: architectural baseline and shared runtime components |
| [`SYGMA-Q2/`](SYGMA-Q2/) | Q2: initialization policy precision and reliability |
| [`SYGMA-Q3/`](SYGMA-Q3/) | Q3: startup consistency |
| [`SYGMA-Q4/`](SYGMA-Q4/) | Q4: performance |
| [`Analyzer/`](Analyzer/) | Static syscall-enforceability analyzer |

`SYGMA-Q2`, `SYGMA-Q3`, and `SYGMA-Q4` share the SYGMA design and component
boundaries but are not interchangeable builds; identify the profile that
produced any given result.

## Build and deployment

Each profile builds and deploys locally, without a container registry:

```sh
cd SYGMA-Q2                 # or SYGMA, SYGMA-Q3, SYGMA-Q4
./local-images.sh build     # build binaries/images, save a local tar archive
./local-images.sh load      # import the archive into containerd on this node
./local-images.sh deploy    # apply the profile's Kubernetes manifests
```

For a multi-node cluster, copy the generated archive to every schedulable
node and run `load` on each before running `deploy` once
(`./local-images.sh all` is for a single-node cluster only). Only one profile
may be deployed at a time — they share cluster-scoped CRDs and pinned BPF
maps.

Q3's 34 derived application images use a separate workflow:
`SYGMA-Q3/local-workloads.sh build|load`.

Build host requirements: x86-64 Linux, Go, Docker, GCC, Python 3. Each
cluster node needs `ctr` access to containerd's `k8s.io` namespace; the
deployment host also needs `kubectl`.

## Analysis results

- `Analyzer/results/linux-v5.15-x86_64-syscall-enforceability-evidence.xlsx`
  — review-friendly workbook of the static syscall-enforceability analysis
- `Analyzer/output-effective-n-full-patched/` — full machine-readable output
  (all 360 per-syscall checkpoints and call trees) used to generate it