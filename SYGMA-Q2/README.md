# SYGMA-Q2: Precision and Reliability Profile

SYGMA-Q2 evaluates initialization-policy precision without intentionally
breaking the workload. It runs the policy lookup and transition logic, records
misses, but disables `SIGKILL`, LSM `-EPERM`, and the corresponding blocking
attachments. Reported false rejections are therefore counterfactual: they are
deployments that would have failed under fail-closed enforcement, not observed
Pod readiness failures.

## Layout

- `sygma_eBPF/`, `ocihook/`, and `sygma-operator/`: the Q2 observation-profile
  implementation.
- `manifest/availability-eval/`: Q2 runner, map snapshot helper, summarizer,
  tests, and workload manifests.
- `manifest/`: shared manifests referenced by the runner through relative
  paths.
- `IMPLEMENTATION.md`: documentation retained from the original working tree.
- `results/`: reserved for the curated Q2 result workbook/data.

The paper's Table 4 values correspond to campaign
`obsmap-full2-20260819T111134Z` (100 valid deployments per workload): nginx
6%, httpd 0%, MySQL 2%, and Redis 5%. That raw campaign is intentionally not
copied into this initial source package.

The generated bpf2go binding and embedded object are retained for an immediate
build. Build and transfer the Q2-specific images with:

```sh
./local-images.sh build
./local-images.sh load
./local-images.sh deploy
```

The Q2 manifests use only `localhost/sygma-q2/*:artifact-v1`, set
`imagePullPolicy: Never`, and contain no `regcred`. For multi-node Q2, set
an explicit node-reachable `REDIS_ADDR=HOST:6379` when building and deploying;
the historical Q2 NRI profile otherwise retains its single-node Redis
assumption.

`artifacts/local/` receives the transferable tar, its checksum, and a lock
that records both Docker config IDs and OCI manifest digests. The directory is
Git-ignored so the tar can be attached separately as a release asset.

`manifest/availability-eval/run.py` depends on the nginx and Redis manifests
in its parent `manifest/` directory, so preserve this directory topology.
Before a public release, image tags and the Q2 measured binary should be locked
by digest/hash. The surviving paper metadata did not record enough information
to prove that the current source rebuild is byte-identical to the measured
binary.

The copied Q2 test fixture has been updated to include the observation fields
required by the runner. The transition-stability percentage still lacks a
dedicated paper-result generator; add that generator and a golden-output check
before claiming full Table 4 reproduction.
