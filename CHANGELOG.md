# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Prebuilt binaries published to GitHub Releases on every `v*` tag, via
  GoReleaser (linux/darwin amd64+arm64, windows/amd64), with a
  `checksums.txt`.
- `examples/` with real captured `table` and `json` output.

### Fixed

- Multi-arch images: SBOM attestations attached to a manifest-list (image
  index) digest often only describe the index itself, not the actual
  package contents. `kubectl-sbom` now inspects the resolved digest and, if
  it is an index, resolves it down to the manifest for the node's actual
  OS/architecture (falling back to `linux/amd64` if the node can't be read)
  before fetching the SBOM. The resolved platform digest is shown as
  `PLATFORM DIGEST` / `platformDigest` when this happens.

## [0.0.1] - 2026-08-04

### Added

- Initial release of `kubectl-sbom`.
- Resolve a `pod/<name>` or `deployment/<name>` to its container image
  digest via the Kubernetes API.
- Fetch and display the SPDX or CycloneDX SBOM attestation attached to
  that image via `cosign`.
- Output formats: `table` (default), `json`, `spdx`, `cyclonedx`.
- `-n/--namespace`, `-c/--container`, `--context`, `--kubeconfig` flags.
- CI (build, vet, test, golangci-lint) and branch protection on `main`.

[Unreleased]: https://github.com/tkm112345/kubectl-sbom/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/tkm112345/kubectl-sbom/releases/tag/v0.0.1
