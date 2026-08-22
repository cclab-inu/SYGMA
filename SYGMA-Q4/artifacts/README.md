# Q4 paper-time image provenance

The paper-time archive is intentionally absent from the anonymous-review
bundle. Although its image names are neutral, its compiled Go build metadata
contains author-specific module and checkout paths.

`PAPER_STACK_SOURCE_AND_BINARY_SHA256SUMS` retains the expected archive and
binary hashes so the exact archive can be verified and released after
deanonymization. The preserved private source copy has archive SHA-256:

```text
2c8cfbd4fed8eb9edc6b8cc2c006eab83081417395ee94e3cf1f7c3fb04e1c6c
```

For anonymous review, run `../local-images.sh build`. That command uses
neutral module paths, `-trimpath`, no VCS metadata, and local-only image
references. Its output is a successor `q4-source` build and must not be
described as byte-identical to the paper-time archive.
