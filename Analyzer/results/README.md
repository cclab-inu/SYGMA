# Analyzer evidence workbook

`linux-v5.15-x86_64-syscall-enforceability-evidence.xlsx` contains the
build-specific LSM-BPF and conventional SIGKILL classification evidence for
all 360 x86-64 syscall-table entries. Its adjacent `.sha256` file authenticates
the distributed workbook.

The workbook preserves the paper-facing classes while exposing the Analyzer's
internal evidence state:

- `E`: Enforceable
- `N`: Non-Enforceable / Bypass-Certified
- `U`: Non-Enforceable / Unresolved
- `NA`: Not Available

From the `Analyzer/` directory, verify the distributed result with:

```bash
(cd results && sha256sum -c \
  linux-v5.15-x86_64-syscall-enforceability-evidence.xlsx.sha256)
```

Regenerate it from the included canonical output with:

```bash
python3 tools/export_open_science_workbook.py \
  --input-dir output-effective-n-full-patched \
  --output results/linux-v5.15-x86_64-syscall-enforceability-evidence.xlsx
```

The workbook records source-artifact hashes, Analyzer hashes, build
configuration, classification counts, path evidence, hook/check effects, and
active or proof-covered unresolved edges.

The complete machine-readable source of this workbook is distributed alongside
it in `../output-effective-n-full-patched/`; the workbook is a presentation
layer, not a replacement for those Analyzer outputs.
