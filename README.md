# kubectl-sbom

A `kubectl` plugin that shows the SBOM attached to the container image(s) a
running Kubernetes resource (Pod or Deployment) is using — without having to
manually resolve the image digest and run `cosign` yourself.

```
$ kubectl sbom pod/test-curl
CONTAINER        test-curl
IMAGE            cgr.dev/chainguard/curl:latest
DIGEST           cgr.dev/chainguard/curl@sha256:d9a0165f6b288b050441ab6a9789f98987211f72f527d53f16ffab575f615205
PLATFORM DIGEST  cgr.dev/chainguard/curl@sha256:17e611ecaaf2b1243d57b2ba4aa1ca618b7a2d89528ac0eff7378e6a66aedb53
SBOM TYPE        https://spdx.dev/Document
COMPONENTS       170

NAME               VERSION      LICENSE
...
wolfi-baselayout   20230201-r29 MIT
ca-certificates    20260413     MPL-2.0 AND MIT
libcrypto3         3.6.3-r3     Apache-2.0
libssl3            3.6.3-r3     Apache-2.0
curl               8.21.0-r1    MIT
...
```

See [`examples/`](examples/) for the full, real captured output (both
`table` and `json`).

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
kubectl sbom <pod|deployment>/<name> [-n namespace] [-c container] [-o table|json|spdx|cyclonedx] [--context ctx] [--kubeconfig path]
```

- `pod/<name>` — resolves image digests directly from the pod's status.
- `deployment/<name>` — resolves via one of its running pods.
- `-o table` (default) — human-readable summary of packages.
- `-o json` — normalized JSON (container, image, digest, component list).
- `-o spdx` / `-o cyclonedx` — the raw attestation document for a single
  container (use `-c` to select one if the resource has more than one).

For multi-arch images, the digest reported by the container runtime often
points to the image *index* rather than a single-platform manifest, and its
SBOM attestation (if any) only describes the index itself. kubectl-sbom
detects this and resolves down to the manifest for the node's actual
OS/architecture before fetching the SBOM; the resolved digest is shown as
`PLATFORM DIGEST`.

## Scope

This is a v1 focused on read/inspect only:

- No signature verification (use `cosign verify`).
- No vulnerability scanning (use `trivy` / `grype`).
- No policy enforcement (use `kyverno` / `policy-controller`).
- Supported resource kinds: `pod`, `deployment`.

## License

MIT
