# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
