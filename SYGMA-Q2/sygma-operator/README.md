# SYGMA-Q2 operator

This is the operator source used by the Q2 observation profile. The canonical
anonymous build is owned by the profile root, where the operator is compiled
with neutral module metadata and packaged together with the matching core and
installer:

```sh
cd SYGMA-Q2
./local-images.sh build
./local-images.sh load
./local-images.sh deploy
```

The workflow saves a local image archive and never logs in to or publishes to
a registry. The generated Kubebuilder `docker-push` and `docker-buildx`
publication targets are deliberately disabled in this anonymous artifact.

For source development, regenerate API artifacts and run tests with:

```sh
make generate manifests
make test
```

Generated CRDs are under `config/crd/bases/`. The profile deployment entry
point is `../manifest/deploy.sh`; do not substitute a registry-oriented
Kubebuilder deployment recipe for the profile workflow.
