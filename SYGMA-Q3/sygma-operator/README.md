# SYGMA operator

The operator builds the policy data consumed by SYGMA. A `SYGMAConfig`
contains a Pod manifest for init-phase collection and exactly one main-policy
mode:

- `policy.stateMachine`: collect the init syscall graph dynamically and store
  the configured state machine for the main phase.
- `policy.allowAll: true`: evaluation-only mode that materializes a complete
  allow graph for init and a one-state allow-all state machine for main.

The former third-party policy input and sequence/DFA/phase policy variants are
not part of the `SYGMAConfig` API. The main policy stored in Redis at
`main_policy:<imageID>` has this wire shape:

```json
{
  "type": "state-machine",
  "stateMachine": {
    "initialState": 0,
    "states": {
      "0": {"allowedSyscalls": [0, 1, 60, 231]}
    },
    "transitions": {}
  }
}
```

State IDs and transition syscall keys are canonical decimal strings. Supported
x86-64 syscall numbers are `0-334` and `424-448`. Every transition syscall
must appear in its source state's `allowedSyscalls`, and every transition must
target an existing state. If a syscall has no transition, the current state is
retained.

`SYGMAPolicy` is an init-only bootstrap API. Its optional `spec.phases` map may
contain only `initPhase`; supplying `mainPhase` is rejected. The agent also no
longer accepts path-blocking rules. Typed main enforcement is installed only by
the OCI hook.

## Redis publication and durability

Image metadata at `image_id_map:<imageID>` always uses one JSON shape:

```json
{
  "imageName": "docker.io/library/nginx:1.27",
  "binaryName": "nginx",
  "binaryPath": "/usr/sbin/nginx"
}
```

`binaryName` must be a basename other than `unknown`; `binaryPath` may be empty
but must be absolute when present. Exact image names and their normalized
Docker Hub aliases point to the same image ID.

`image_name_map`, `image_id_map`, init graph rows and metadata, `main_policy`,
and `policy_ready` are persistent Redis keys. A publication removes
`policy_ready:<imageID>` before the first metadata, alias, or policy mutation.
One publication path then writes metadata and both aliases, replaces the init
graph, removes any legacy main graph, and atomically writes the typed main policy
plus a unique ready revision last. A failed final transaction deletes the ready
marker again. Readers must observe the same non-empty revision before and after
loading.

`SYGMAConfig.status.observedGeneration` tracks the generation being processed.
A spec update resets the workflow and deletes only Pods owned by that
`SYGMAConfig`; collection lookup never selects another config's Pod.

## Evaluation allow-all mode

`allowAll` exists to measure the enforcement path without policy denials. It is
not a production policy. The operator expands it into 361 init source rows
(`START=500` plus every supported syscall), each allowing all 360 supported
syscalls. Main enforcement still performs a real state-machine lookup using a
single state whose allow-list contains the same 360 syscalls.

See
[`security_v1_sygmaconfig_allowall.yaml`](config/samples/security_v1_sygmaconfig_allowall.yaml)
and
[`security_v1_sygmaconfig.yaml`](config/samples/security_v1_sygmaconfig.yaml)
for complete examples.

## Development

Regenerate API artifacts and run the tests after changing the API:

```sh
make generate manifests
make test
```

Build the manager with:

```sh
make build
```

The generated CRDs are in `config/crd/bases/`; deployment copies are in
`deploy/crds/`.
