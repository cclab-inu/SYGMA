# SYGMA Analyzer

This directory contains the offline static analyzer used to classify Linux
syscall enforcement mechanisms. It consumes a target kernel tree and build
artifacts, combines Clang AST/CFG analysis with LLVM-IR checks, and classifies
each syscall as E, N, U, or NA for LSM-BPF and conventional SIGKILL.

## Layout

- `main.go`, `frontend_cache.go`, and `input_validation.go`: analyzer source.
- `tools/`: Clang extractor, LLVM verifier, and workbook exporter source.
- `scripts/`: kernel-input and comparison helpers.
- `docs/`: analysis/validation notes.
- `kernel-input/`: exact kernel base, compatibility patch, x86-64 configuration,
  and hashes required to reconstruct the analyzed input.
- `output-effective-n-full-patched/`: complete path-normalized canonical
  machine-readable paper output: aggregate metadata and summary, 360
  per-syscall checkpoints, 360 successful-path call trees, and 24 derived
  reports.
- `PATH_REDACTION.md`: deterministic normalization applied to absolute host
  paths for anonymous review.
- `IMPLEMENTATION.md`: the original detailed build and analysis manual.
- `results/`: published Analyzer evidence workbook and its SHA-256 file.

The canonical classification counts are:

| Mechanism | E | N | U | NA |
| --- | ---: | ---: | ---: | ---: |
| LSM-BPF | 146 | 138 | 59 | 17 |
| Conventional SIGKILL | 4 | 257 | 82 | 17 |

These values are recorded in
`output-effective-n-full-patched/reports/classification_counts.json` and match
the paper's analysis table.

Build and unit-test the Go analyzer with:

```sh
go test ./...
go build -trimpath -o systematic_analysis .
```

See `IMPLEMENTATION.md` for frontend builds and full-run commands. Full
reproduction requires the exact Linux 5.15 base tree, configuration, vmlinux,
System.map, compile database, and local compatibility patches. The original
analysis used base commit
`8bb7eca972ad531c9b149c0a51ab43a417385813`; the included `kernel-input/`
directory records its four-file compatibility patch and final configuration.

The published evidence workbook and its SHA-256 file are included in
`results/`. It is exported from the canonical JSON output included here, which
also supports machine-readable count and evidence verification without Excel.
See `output-effective-n-full-patched/README.txt` for the output schema and
`PATH_REDACTION.md` for the deterministic anonymous-path normalization.
