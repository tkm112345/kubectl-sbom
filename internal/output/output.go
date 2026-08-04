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
func PrintTable(w io.Writer, results []Result) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	ew := &errWriter{w: tw}
	for i, r := range results {
		if i > 0 {
			ew.println()
		}
		ew.printf("CONTAINER\t%s\n", r.Container)
		ew.printf("IMAGE\t%s\n", r.Image)
		if r.Digest != "" {
			ew.printf("DIGEST\t%s\n", r.Digest)
		}
		if r.PlatformDigest != "" {
			ew.printf("PLATFORM DIGEST\t%s\n", r.PlatformDigest)
		}
		if r.Error != "" {
			ew.printf("ERROR\t%s\n", r.Error)
			continue
		}
		ew.printf("SBOM TYPE\t%s\n", r.PredicateType)
		ew.printf("COMPONENTS\t%d\n", len(r.Components))
		if len(r.Components) > 0 {
			ew.println()
			ew.printf("NAME\tVERSION\tLICENSE\n")
			for _, c := range r.Components {
				ew.printf("%s\t%s\t%s\n", c.Name, c.Version, c.License)
			}
		}
	}
	if ew.err != nil {
		return ew.err
	}
	return tw.Flush()
}

// errWriter lets a sequence of writes skip the usual per-call error check;
// the first error (if any) is recorded and later writes become no-ops.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, a ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, a...)
}

func (ew *errWriter) println() {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintln(ew.w)
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
