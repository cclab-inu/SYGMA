# Q4 image modes

## Anonymous source build

From the `SYGMA-Q4/` profile root:

```sh
./local-images.sh build
./local-images.sh load
./local-images.sh deploy
```

This produces and imports the three `localhost/sygma-q4/*:artifact-v1`
images without login, push, or a registry. The manifests use
`imagePullPolicy: Never`.

## Paper-time replay

The exact 2026-08-17 archive is excluded from the anonymous-review bundle
because identity-bearing build metadata is embedded in its binaries. Its
expected checksums remain in `../../artifacts/` for post-acceptance
verification. Do not relabel an anonymous source rebuild as the paper-time
binary stack.
