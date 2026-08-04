# kubectl-sbom

A `kubectl` plugin that shows the SBOM attached to the container image(s) a
running Kubernetes resource (Pod or Deployment) is using — without having to
manually resolve the image digest and run `cosign` yourself.

```
$ kubectl sbom pod/my-app
CONTAINER   web
IMAGE       ghcr.io/example/my-app:1.4.0
DIGEST      ghcr.io/example/my-app@sha256:3b1f...
SBOM TYPE   https://cyclonedx.org/bom
COMPONENTS  128

NAME        VERSION  LICENSE
alpine-baselayout  3.4.3-r1  GPL-2.0-only
...
```

## Why

Standard supply-chain tooling (cosign, Sigstore, Trivy) all operate on an
*image reference*. In practice you usually start from a *running workload*:
"what is this Pod actually running, and what's in it?" kubectl-sbom bridges
that gap: it resolves the resource to its container image digest via the
Kubernetes API, then fetches the SBOM attestation for that exact digest.

## Prerequisites

- The image must have an SBOM attestation attached (e.g. via
  `cosign attest --predicate sbom.json --type cyclonedx` or
  `--type spdxjson`) at build time.
- [`cosign`](https://docs.sigstore.dev/cosign/installation/) must be
  installed and on `PATH` — kubectl-sbom shells out to it rather than
  reimplementing the Sigstore/OCI protocol.
- A working kubeconfig with read access to the target Pod/Deployment.

## Install

```
go install github.com/tkm112345/kubectl-sbom/cmd/kubectl-sbom@latest
```

Once installed as `kubectl-sbom` on `PATH`, kubectl will expose it as
`kubectl sbom`.

## Usage

```
kubectl sbom <pod|deployment>/<name> [-n namespace] [-c container] [-o table|json|spdx|cyclonedx]
```

- `pod/<name>` — resolves image digests directly from the pod's status.
- `deployment/<name>` — resolves via one of its running pods.
- `-o table` (default) — human-readable summary of packages.
- `-o json` — normalized JSON (container, image, digest, component list).
- `-o spdx` / `-o cyclonedx` — the raw attestation document for a single
  container (use `-c` to select one if the resource has more than one).

## Scope

This is a v1 focused on read/inspect only:

- No signature verification (use `cosign verify`).
- No vulnerability scanning (use `trivy` / `grype`).
- No policy enforcement (use `kyverno` / `policy-controller`).
- Supported resource kinds: `pod`, `deployment`.

## License

MIT
