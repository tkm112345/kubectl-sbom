# Contributing

Thanks for considering a contribution to kubectl-sbom.

## Workflow

- The `main` branch is protected: all changes go through a pull request,
  except for repository admins.
- Every pull request must pass CI (`go build`, `go vet`, `go test -race`,
  `golangci-lint`) and get at least one approving review before it can be
  merged.
- Keep pull requests focused; unrelated changes should be a separate PR.

## Development

Requirements: Go (see `go.mod` for the version), and
[`cosign`](https://docs.sigstore.dev/cosign/installation/) on `PATH` for
manual testing.

```sh
go build ./...
go vet ./...
go test ./... -race
gofmt -l .   # should print nothing
```

## Project layout

- `cmd/kubectl-sbom` — plugin entry point.
- `internal/resolve` — maps a `<kind>/<name>` argument to container image
  digests via the Kubernetes API.
- `internal/sbomfetch` — fetches and decodes SBOM attestations via `cosign`.
- `internal/normalize` — converts SPDX/CycloneDX documents into a common
  component list.
- `internal/output` — renders results as a table, JSON, or the raw SBOM
  document.
- `internal/k8sclient` — builds the Kubernetes client from kubeconfig.

## Scope

This tool is intentionally read-only (see the "Scope" section in
[README.md](README.md)). Signature verification, vulnerability scanning, and
policy enforcement are out of scope — please point to the appropriate
existing tool (`cosign verify`, `trivy`/`grype`, `kyverno`) instead of adding
overlapping functionality here.

## License

By contributing, you agree that your contributions will be licensed under
the [MIT License](LICENSE).
