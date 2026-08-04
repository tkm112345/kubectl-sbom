// Package normalize extracts a common, minimal component list from either
// an SPDX or a CycloneDX SBOM document so the CLI can render one table
// regardless of which format the image was attested with.
package normalize

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Component is a minimal, format-agnostic view of an SBOM package entry.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	License string `json:"license,omitempty"`
}

// FromPredicate parses raw into a Component list based on predicateType.
func FromPredicate(predicateType string, raw json.RawMessage) ([]Component, error) {
	switch {
	case strings.Contains(predicateType, "cyclonedx"):
		return fromCycloneDX(raw)
	case strings.Contains(predicateType, "spdx"):
		return fromSPDX(raw)
	default:
		return nil, fmt.Errorf("unsupported predicate type %q", predicateType)
	}
}

func fromCycloneDX(raw json.RawMessage) ([]Component, error) {
	var doc struct {
		Components []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Licenses []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse CycloneDX document: %w", err)
	}

	comps := make([]Component, 0, len(doc.Components))
	for _, c := range doc.Components {
		license := ""
		if len(c.Licenses) > 0 {
			license = c.Licenses[0].License.ID
			if license == "" {
				license = c.Licenses[0].License.Name
			}
		}
		comps = append(comps, Component{Name: c.Name, Version: c.Version, License: license})
	}
	return comps, nil
}

func fromSPDX(raw json.RawMessage) ([]Component, error) {
	var doc struct {
		Packages []struct {
			Name             string `json:"name"`
			VersionInfo      string `json:"versionInfo"`
			LicenseConcluded string `json:"licenseConcluded"`
			LicenseDeclared  string `json:"licenseDeclared"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse SPDX document: %w", err)
	}

	comps := make([]Component, 0, len(doc.Packages))
	for _, p := range doc.Packages {
		license := p.LicenseConcluded
		if license == "" || license == "NOASSERTION" {
			license = p.LicenseDeclared
		}
		if license == "NOASSERTION" {
			license = ""
		}
		comps = append(comps, Component{Name: p.Name, Version: p.VersionInfo, License: license})
	}
	return comps, nil
}
