// Package output renders SBOM lookup results as a table, normalized JSON,
// or the raw SPDX/CycloneDX document.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/tkm112345/kubectl-sbom/internal/normalize"
)

// Result is the outcome of resolving and fetching the SBOM for one container.
type Result struct {
	Container string `json:"container"`
	Image     string `json:"image"`
	Digest    string `json:"digest,omitempty"`
	// PlatformDigest is set when Digest referred to a multi-arch image
	// index and was resolved down to this platform-specific manifest
	// digest before the SBOM was fetched.
	PlatformDigest string                `json:"platformDigest,omitempty"`
	PredicateType  string                `json:"predicateType,omitempty"`
	Components     []normalize.Component `json:"components,omitempty"`
	RawPredicate   json.RawMessage       `json:"-"`
	Error          string                `json:"error,omitempty"`
}

// PrintTable writes a human-readable summary of results to w.
func PrintTable(w io.Writer, results []Result) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(tw)
		}
		fmt.Fprintf(tw, "CONTAINER\t%s\n", r.Container)
		fmt.Fprintf(tw, "IMAGE\t%s\n", r.Image)
		if r.Digest != "" {
			fmt.Fprintf(tw, "DIGEST\t%s\n", r.Digest)
		}
		if r.PlatformDigest != "" {
			fmt.Fprintf(tw, "PLATFORM DIGEST\t%s\n", r.PlatformDigest)
		}
		if r.Error != "" {
			fmt.Fprintf(tw, "ERROR\t%s\n", r.Error)
			continue
		}
		fmt.Fprintf(tw, "SBOM TYPE\t%s\n", r.PredicateType)
		fmt.Fprintf(tw, "COMPONENTS\t%d\n", len(r.Components))
		if len(r.Components) > 0 {
			fmt.Fprintln(tw)
			fmt.Fprintf(tw, "NAME\tVERSION\tLICENSE\n")
			for _, c := range r.Components {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, c.Version, c.License)
			}
		}
	}
	tw.Flush()
}

// PrintJSON writes the normalized results as indented JSON to w.
func PrintJSON(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// PrintRaw writes the raw SBOM document of a single result to w.
func PrintRaw(w io.Writer, r Result) error {
	if r.Error != "" {
		return fmt.Errorf("%s", r.Error)
	}
	var buf []byte
	buf, err := json.MarshalIndent(r.RawPredicate, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal raw predicate: %w", err)
	}
	_, err = w.Write(append(buf, '\n'))
	return err
}
