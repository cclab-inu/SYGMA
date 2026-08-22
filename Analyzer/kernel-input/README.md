# Analyzer kernel input provenance

The Analyzer's canonical result was produced from Linux source commit:

```text
8bb7eca972ad531c9b149c0a51ab43a417385813
```

Apply `linux-v5.15-build-compat.patch` to that source and use
`config-x86_64` as the build configuration. The large build artifacts are not
included; their expected SHA-256 values are:

| Artifact | SHA-256 |
| --- | --- |
| `config-x86_64` | `6822405eac9f03aff7e4aed7f75cf2bb491186196a4f935ebc331e9f07ba734f` |
| `compile_commands.json` | `b0beb34fa2cb7723bfb301f5dccbc7a9a7f515054eba6fa188f1ce8d38a18b98` |
| `System.map` | `966e570c87a4775978036824a681543239d4bc1f05b5ecb893311402732fd37e` |
| `vmlinux` | `dad572cb2ebbf6e68285653f655d6c1200e82f5851dde37897aa7d573667d08b` |

The rebuild helper performs `mrproper`; use it only in a disposable kernel
worktree/build directory.

