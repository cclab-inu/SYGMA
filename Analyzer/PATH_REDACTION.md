# Anonymous path normalization

The canonical analyzer output contains source-location witnesses. The analyzer
was originally executed from an author-specific absolute checkout, so this
anonymous-review copy applies one deterministic presentation-only
normalization: the host-specific checkout prefix is replaced with
`/workspace` in every text and JSON output file.

No syscall names, classifications, counters, witness topology, source-relative
paths, line identifiers, or proof states were changed. The normalized
`summary.json` SHA-256 is:

```text
03a21229e1b15fa6abb3bc9ad822d5e901f967314593d31a41cdbcd23b077474
```

The classification totals remain LSM-BPF `146/138/59/17` and conventional
SIGKILL `4/257/82/17` for `E/N/U/NA`, respectively. A post-acceptance
archive may retain the private provenance mapping outside the anonymous
bundle. A clean rerun should use a neutral checkout rooted at `/workspace`
and therefore require no normalization.
