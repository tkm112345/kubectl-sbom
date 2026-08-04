// Package cli wires the kubectl-sbom command together.
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tkm112345/kubectl-sbom/internal/k8sclient"
	"github.com/tkm112345/kubectl-sbom/internal/normalize"
	"github.com/tkm112345/kubectl-sbom/internal/output"
	"github.com/tkm112345/kubectl-sbom/internal/resolve"
	"github.com/tkm112345/kubectl-sbom/internal/sbomfetch"
)

var (
	namespace      string
	container      string
	outputFormat   string
	kubeconfigPath string
)

// Execute runs the kubectl-sbom root command.
func Execute() {
	root := &cobra.Command{
		Use:   "kubectl-sbom <kind>/<name>",
		Short: "Show the SBOM attached to the container images a Kubernetes resource is running",
		Long: `kubectl-sbom resolves the container image(s) used by a Pod or Deployment,
then downloads and displays the SBOM attestation (SPDX or CycloneDX) attached
to that image via cosign/Sigstore.

Requires the cosign CLI to be installed and available on PATH.`,
		Example: `  kubectl sbom pod/my-app
  kubectl sbom deployment/my-app -c web -o json
  kubectl sbom pod/my-app -o cyclonedx > sbom.json`,
		Args: cobra.ExactArgs(1),
		RunE: run,
	}

	root.Flags().StringVarP(&namespace, "namespace", "n", "", "Kubernetes namespace (defaults to the current context's namespace)")
	root.Flags().StringVarP(&container, "container", "c", "", "Limit to a specific container name")
	root.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table|json|spdx|cyclonedx")
	root.Flags().StringVar(&kubeconfigPath, "kubeconfig", "", "Path to a kubeconfig file (defaults to $KUBECONFIG or ~/.kube/config)")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	kind, name, err := resolve.ParseResourceArg(args[0])
	if err != nil {
		return err
	}

	if outputFormat != "table" && outputFormat != "json" && outputFormat != "spdx" && outputFormat != "cyclonedx" {
		return fmt.Errorf("unknown output format %q (supported: table, json, spdx, cyclonedx)", outputFormat)
	}

	clientset, ns, err := k8sclient.New(kubeconfigPath, namespace)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	images, err := resolve.ContainerImages(ctx, clientset, ns, kind, name, container)
	if err != nil {
		return err
	}

	if (outputFormat == "spdx" || outputFormat == "cyclonedx") && len(images) > 1 {
		return fmt.Errorf("%d containers matched; use -c to select one when using -o %s", len(images), outputFormat)
	}

	results := make([]output.Result, 0, len(images))
	for _, img := range images {
		results = append(results, fetchOne(ctx, img, outputFormat))
	}

	switch outputFormat {
	case "table":
		output.PrintTable(os.Stdout, results)
		return nil
	case "json":
		return output.PrintJSON(os.Stdout, results)
	default: // spdx, cyclonedx
		return output.PrintRaw(os.Stdout, results[0])
	}
}

func fetchOne(ctx context.Context, img resolve.ContainerImage, outputFormat string) output.Result {
	r := output.Result{Container: img.Container, Image: img.Image, Digest: img.Digest}

	ref := img.Digest
	if ref == "" {
		ref = img.Image
	}
	if ref == "" {
		r.Error = "no resolvable image reference"
		return r
	}

	var (
		att *sbomfetch.Attestation
		err error
	)
	switch outputFormat {
	case "spdx":
		att, err = sbomfetch.Fetch(ctx, ref, sbomfetch.PredicateSPDX)
	case "cyclonedx":
		att, err = sbomfetch.Fetch(ctx, ref, sbomfetch.PredicateCycloneDX)
	default:
		att, err = sbomfetch.FetchAny(ctx, ref)
	}
	if err != nil {
		r.Error = err.Error()
		return r
	}

	r.PredicateType = att.PredicateType
	r.RawPredicate = att.Predicate

	if outputFormat == "table" || outputFormat == "json" {
		comps, err := normalize.FromPredicate(att.PredicateType, att.Predicate)
		if err != nil {
			r.Error = err.Error()
			return r
		}
		r.Components = comps
	}

	return r
}
