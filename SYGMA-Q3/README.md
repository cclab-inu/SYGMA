# SYGMA-Q3: Startup Consistency Profile

SYGMA-Q3 measures publish-before-release ordering. The SYGMA arm installs the
preloaded policy synchronously in the OCI prestart path before the application
is released. The comparison arm measures asynchronous Tetragon policy-filter
enrollment. A neutral observer records lifecycle timestamps and application-
lineage syscalls; both arms are non-blocking.

## Layout

- `sygma_eBPF/`, `ocihook/`, and `sygma-operator/`: the surviving Q3-era
  runtime source layout.
- `manifest/startup-gap-eval/`: runner, analyzers, workload/image definitions,
  map watcher, tests, and deployment manifests.
- `IMPLEMENTATION.md`: common implementation documentation retained from the
  source working tree.
- `results/`: reserved for curated Q3 paper results.

The main paper campaign is the 30-container Hotel Reservation (19) and Online
Boutique (11) set whose directory suffix is
`atomicity-apps-20260820T140316Z-1893962-20420`. Each container has two
warm-ups and ten measured trials per arm. Raw campaigns are not included in
this initial package.

The measured profile used a 28-byte process-state ABI. Its recorded component
SHA-256 values are:

| Component | SHA-256 |
| --- | --- |
| core | `6129eb5f37f468b34cd7320ec81210945aebfca9754adec1886891feb35c38b1` |
| OCI hook | `76b974d35f5ead4c094cf5c0741036ebb2f9f41e6b9a32b66936c7f7192e8c9b` |
| tracer | `991d850c058246f2f027e7d6ed8f53766d25cd5d3e7640a80f504d02c493e5dd` |
| wrapper | `6694b7e48e4e34ca6aaf76124e56d4762cff8e3f271434e6f7f0a232a1cebebb` |
| NRI plugin | `443ddaa2ae10a8c42c33b4595836eff4c7e66a3fc84cd12cfc67ea10b6f88416` |

The exact measured core source snapshot was not recoverable from the damaged
working-tree history; the surviving tree later advanced to a different core.
Keep the full hashes from result metadata in the final result manifest and do
not claim source-to-binary identity until the measured image/binary is archived
or the experiment is rerun.

The checked-in bpf2go binding/object pair corresponds to that surviving later
source, not to the Q3 paper core identified above.

`figures/plot_policy_timing.py` is retained as legacy plotting material but
currently contains paper values directly. Replace it with a generator that
reads the selected campaign summaries before calling it a reproduction path.

The current Q3 harness assumes that Redis, the observation core, Tetragon, and
the host OCI/NRI components are already installed. It does not yet contain a
complete clean-cluster bootstrap manifest, and several staging scripts require
the same absolute package path to exist on the target node. These portability
gaps must be resolved or explicitly provisioned before advertising a one-command
full reproduction.

Several Q3 tests deliberately verify staged component binaries under
`manifest/startup-gap-eval/build/`. The small probe/map-watch harness tools
are retained, while the paper-time SYGMA component binaries are not. Rebuild
and stage the stack before running the complete test suite; source-only tests
do not establish paper-binary identity.

For an anonymous source rerun, build and import the Q3 system stack locally:

```sh
./local-images.sh build
./local-images.sh load
./local-images.sh deploy
```

This is explicitly a `q3-source` successor build; the paper-time Q3 binary
bundle was not recoverable. The system lock records OCI manifest digests, and
`deploy` finishes by pinning the core DaemonSet to its imported digest so the
startup-gap preflight does not see a mutable tag. The 34 derived application
images are a separate local bundle:

```sh
./local-workloads.sh build
./local-workloads.sh load
```

Neither workflow logs in or pushes to a registry. Import both archives on every
node that may run a campaign Pod. The workload build also generates
`artifacts/local/sygma-q3-local-publication/campaign-images.env` from the two
digest locks; the campaign launcher prefers this local environment over the
retained legacy registry-publication directories.

The old `publish_application_images.sh` and
`build_observation_core_image.sh` are retained only to interpret historical
publication receipts and are not part of the anonymous workflow.

This makes the source-successor system and workload images transportable
without a registry. The historical campaign launcher still has separate
trust-anchor/staging prerequisites described above; do not describe this as a
one-command reproduction of the paper-time Q3 campaign.
