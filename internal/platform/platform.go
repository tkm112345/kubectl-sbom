// Package platform resolves a multi-architecture image index down to the
// manifest digest of a specific OS/architecture. This matters because SBOM
// attestations for the *index* digest (as commonly reported by container
// runtimes for multi-arch images) often only describe the index itself
// ("this is a multi-arch pointer") rather than the actual package contents,
// which are attested per platform manifest.
package platform

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Target is the OS/architecture a multi-arch index should be resolved to.
type Target struct {
	OS           string
	Architecture string
}

// DefaultTarget is used when the actual node platform cannot be determined.
var DefaultTarget = Target{OS: "linux", Architecture: "amd64"}

// ResolveDigest inspects ref (a "repo@sha256:..." or "repo:tag" reference).
// If it points to a multi-platform image index, it returns the digest of
// the manifest matching target, as "repo@sha256:...", and wasIndex=true. If
// ref already points to a single-platform manifest, it is returned
// unchanged with wasIndex=false.
func ResolveDigest(ctx context.Context, ref string, target Target) (resolved string, wasIndex bool, err error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", false, fmt.Errorf("parse image reference %q: %w", ref, err)
	}

	desc, err := remote.Get(r, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", false, fmt.Errorf("fetch manifest for %s: %w", ref, err)
	}

	if !desc.MediaType.IsIndex() {
		return ref, false, nil
	}

	idx, err := desc.ImageIndex()
	if err != nil {
		return "", true, fmt.Errorf("read image index for %s: %w", ref, err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", true, fmt.Errorf("read index manifest for %s: %w", ref, err)
	}

	for _, m := range manifest.Manifests {
		if m.Platform == nil {
			continue
		}
		if m.Platform.OS == target.OS && m.Platform.Architecture == target.Architecture {
			return fmt.Sprintf("%s@%s", r.Context().Name(), m.Digest.String()), true, nil
		}
	}
	return "", true, fmt.Errorf("no manifest for platform %s/%s found in index %s", target.OS, target.Architecture, ref)
}
