// Package sbomfetch retrieves SBOM attestations attached to a container
// image by shelling out to cosign, which already implements the Sigstore
// OCI/DSSE protocol correctly. Reimplementing that protocol is out of scope
// for this tool.
package sbomfetch

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// PredicateType identifies the in-toto predicate type of an SBOM attestation.
type PredicateType string

const (
	PredicateSPDX      PredicateType = "https://spdx.dev/Document"
	PredicateCycloneDX PredicateType = "https://cyclonedx.org/bom"
)

// Attestation holds the in-toto predicate extracted from a DSSE envelope.
type Attestation struct {
	PredicateType string
	Predicate     json.RawMessage
}

// Fetch downloads and decodes the SBOM attestation of the given predicate
// type for imageRef (which should be a digest reference for reproducible
// results). It requires the cosign binary to be available on PATH.
func Fetch(ctx context.Context, imageRef string, predicateType PredicateType) (*Attestation, error) {
	if _, err := exec.LookPath("cosign"); err != nil {
		return nil, fmt.Errorf("cosign not found in PATH: install it from https://docs.sigstore.dev/cosign/installation/")
	}

	cmd := exec.CommandContext(ctx, "cosign", "download", "attestation", "--predicate-type", string(predicateType), imageRef)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cosign download attestation failed: %s", strings.TrimSpace(stderr.String()))
	}

	line := firstNonEmptyLine(stdout.String())
	if line == "" {
		return nil, fmt.Errorf("no attestation found for predicate type %s", predicateType)
	}

	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(line), &envelope); err != nil {
		return nil, fmt.Errorf("parse DSSE envelope: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}

	var statement struct {
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(decoded, &statement); err != nil {
		return nil, fmt.Errorf("parse in-toto statement: %w", err)
	}

	return &Attestation{PredicateType: statement.PredicateType, Predicate: statement.Predicate}, nil
}

// FetchAny tries CycloneDX first, then SPDX, and returns whichever succeeds.
func FetchAny(ctx context.Context, imageRef string) (*Attestation, error) {
	att, cdxErr := Fetch(ctx, imageRef, PredicateCycloneDX)
	if cdxErr == nil {
		return att, nil
	}
	att, spdxErr := Fetch(ctx, imageRef, PredicateSPDX)
	if spdxErr == nil {
		return att, nil
	}
	return nil, fmt.Errorf("no SBOM attestation found (cyclonedx: %v; spdx: %v)", cdxErr, spdxErr)
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			return line
		}
	}
	return ""
}
