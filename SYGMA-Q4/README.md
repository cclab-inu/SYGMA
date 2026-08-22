# SYGMA-Q4: Performance Profile

SYGMA-Q4 contains the steady-state performance harness for the baseline,
Tetragon, selective SYGMA, and SYGMA all-trace arms. The profile uses an
allow-all policy, route counters, and a lightweight observation stack to
isolate routing overhead. It should be interpreted as an evaluation profile,
not as the complete blocking configuration.

## Layout

- `sygma_eBPF/`, `ocihook/`, and `sygma-operator/`: source retained with the
  performance harness.
- `manifest/performance-eval/`: benchmark runner, analyzers, manifests, tests,
  and workload helpers.
- `artifacts/`: post-acceptance paper-image checksum/provenance metadata.
- `IMPLEMENTATION.md`: detailed documentation retained from the source tree.
- `results/`: reserved for curated Q4 paper results.

The exact paper-time archive is excluded from anonymous review because its
compiled Go metadata contains identifying module and checkout paths. Its
checksum is retained for post-acceptance verification. The current source must
not be claimed to rebuild byte-identical Q4 binaries.

The anonymous source-build path is:

```sh
./local-images.sh build
./local-images.sh load
./local-images.sh deploy
```

It produces neutral `localhost/sygma-q4/*:artifact-v1` images and never logs
in or pushes. Its local lock records both config IDs and OCI manifest digests.
Label any data it produces as `q4-source`, not `q4-paper`.

The checked-in bpf2go binding/object pair belongs to the surviving later source;
it is included for source usability and is not the paper-time core object.

The benchmark defaults still refer to local DeathStarBench/wrk2 paths. A full
release must pin those repositories by commit and pass their paths explicitly.
It must also pin workload images by digest.

Release gate: the currently available local workbook/campaign set did not
match the paper's stated 100 repetitions or several Figure 11 values. Results
are intentionally omitted here. Locate and freeze the actual paper campaign,
rerun Q4, or update the paper before adding a Q4 workbook.
