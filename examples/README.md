# Examples

Real output captured by running `kubectl-sbom` against a Pod running
[`cgr.dev/chainguard/curl:latest`](https://images.chainguard.dev/directory/image/curl/overview)
(a public, multi-arch image with an SBOM attestation attached):

```sh
kubectl sbom pod/test-curl -o table
kubectl sbom pod/test-curl -o json
```

- [`table-output.txt`](table-output.txt) — the default human-readable format.
- [`json-output.json`](json-output.json) — `-o json`, the normalized,
  machine-readable format (container, image, digest, resolved platform
  digest, and the component list).

Since `cgr.dev/chainguard/curl:latest` is a multi-arch image, the digest
reported by the container runtime pointed to the image *index*; note
`platformDigest` / `PLATFORM DIGEST` in the output, which is the manifest
kubectl-sbom actually resolved the SBOM from (see the "Fixed" entry for
0.0.1+ in [CHANGELOG.md](../CHANGELOG.md)).

Raw document formats (`-o spdx`, `-o cyclonedx`) aren't included here since
they're just the attestation's `predicate` field, unmodified — see
[README.md](../README.md#usage) for how to fetch one directly.
