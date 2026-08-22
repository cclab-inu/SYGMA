# Effective LSM N-Classification Patch Validation

## Scope

- Kernel source: `/workspace/git/linux-v5.15-analysis-src`
- Compile database: `/workspace/git/linux-v5.15-analysis-build/compile_commands.json`
- Kernel config SHA-256: `6822405eac9f03aff7e4aed7f75cf2bb491186196a4f935ebc331e9f07ba734f`
- Compile database SHA-256: `b0beb34fa2cb7723bfb301f5dccbc7a9a7f515054eba6fa188f1ce8d38a18b98`
- Frontend cache fingerprint: `bfa78f4ab9aa009eab39699db64a686f04cae0aac463e701af11e5fe581637b4`
- Classification engine: `clang_cfg_path_value_success_exit_coverage`
- Enforcement semantics: `universal_success_path_enforcement_e_n_u_v5`
- Patched analyzer `main.go` SHA-256: `3b74608e142ee561fed3d8f0a5e0dae69831546eeed0f24f6ae7844f866fb21a`
- Full result: `/workspace/test/systematic_analysis/output-effective-n-full-patched`

The strict input validator completed successfully for all 360 x86-64 syscall
table entries. Seventeen unavailable slots are reported as `NA`, leaving 343
applicable syscalls.

## Root Cause and Fix

The previous analyzer could pass a child's required success value
(`nonnegative` or `valid_pointer`) upward as if it were the child's failure
encoding. This could turn a real `ERR_PTR`, `NULL`, `false`, or negative errno
failure into a synthetic successful bypass and incorrectly classify the syscall
as `N`.

The patch now:

1. propagates the actual tainted failure encoding across function boundaries;
2. preserves analyzer-aware LSM error effects before generic parsing;
3. discards an apparent CFG bypass only when an independent, complete kernel
   success-gate proof shows that the bypass cannot reach a successful syscall
   return;
4. uses narrowly scoped reviewed kernel contracts only after exact function,
   source path, CFG completeness, callsite count, and body-shape checks; and
5. records reviewed assumptions in `proof_method`.

If any prerequisite is missing, the analyzer does not override the CFG result
and conservatively returns `U`.

## Regression Result

| Domain | State | Before | After |
|---|---:|---:|---:|
| LSM | E | 85 | 146 |
| LSM | N | 198 | 138 |
| LSM | U | 60 | 59 |
| LSM | NA | 17 | 17 |
| SIGKILL | E | 4 | 4 |
| SIGKILL | N | 257 | 257 |
| SIGKILL | U | 82 | 82 |
| SIGKILL | NA | 17 | 17 |

All LSM transitions were monotonic refinements:

- 60 syscalls changed from `N` to `E`;
- `userfaultfd` changed from `U` to `E`;
- no syscall changed from `E` to `N` or `U`;
- no syscall changed from `N` to `U`; and
- no SIGKILL classification changed.

The dedicated 66-syscall regression set now contains 60 `E`, six `N`, and zero
`U`. The six remaining `N` classifications are intentional:

- `ptrace`: non-attach requests can bypass the effective hook;
- `move_pages`: the self-process path can bypass the capability hook;
- `signalfd` and `signalfd4`: updating an existing descriptor bypasses the
  allocation hook;
- `fanotify_mark`: feasible operations exist outside the effective hook's
  universal coverage; and
- `fsconfig`: common flag handling can return successfully before the effective
  hook path.

## Paper Reporting Policy

Only automatically certified `E` and `N` results should be included in the
corresponding paper totals. Unsupported semantics must remain `U`; they must not
be manually reassigned from source inspection alone.

Reviewed semantic contracts may contribute to certified totals only when they
are:

- tied to the exact kernel version, source file, function, and body shape;
- disabled automatically when the source no longer matches;
- exposed in the output through `proof_method`; and
- covered by positive and negative regression tests.

Runtime-registered function pointers, open ops-table target sets, unresolved
aliasing, inline assembly effects, and behavior outside the configured build
remain limitations. These cases should be reported as `U`, grouped by
`resolution_scope`, and discussed separately from implementation-improvable
proof gaps.

The defensible claim is:

> For the evaluated kernel build and the analyzer's explicitly supported
> semantics, the tool certifies E or N only when all required success-path and
> denial-propagation obligations are proven; all remaining cases are reported
> as uncertain.

This is a build-scoped, precision-first claim, not a universal claim over every
kernel configuration, dynamically loadable module set, or runtime state.
