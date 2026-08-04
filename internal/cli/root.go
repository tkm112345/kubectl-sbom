// Package cli wires the kubectl-sbom command together.
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/tkm112345/kubectl-sbom/internal/k8sclient"
	"github.com/tkm112345/kubectl-sbom/internal/normalize"
	"github.com/tkm112345/kubectl-sbom/internal/output"
	"github.com/tkm112345/kubectl-sbom/internal/platform"
	"github.com/tkm112345/kubectl-sbom/internal/resolve"
	"github.com/tkm112345/kubectl-sbom/internal/sbomfetch"
)

var (
	namespace      string
	container      string
	outputFormat   string
	kubeconfigPath string
	kubeContext    string
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
	root.Flags().StringVar(&kubeContext, "context", "", "Kubeconfig context to use (defaults to the current-context)")

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

	clientset, ns, err := k8sclient.New(kubeconfigPath, kubeContext, namespace)
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
		results = append(results, fetchOne(ctx, clientset, img, outputFormat))
	}

	switch outputFormat {
	case "table":
		return output.PrintTable(os.Stdout, results)
	case "json":
		return output.PrintJSON(os.Stdout, results)
	default: // spdx, cyclonedx
		return output.PrintRaw(os.Stdout, results[0])
	}
}

func fetchOne(ctx context.Context, clientset kubernetes.Interface, img resolve.ContainerImage, outputFormat string) output.Result {
	r := output.Result{Container: img.Container, Image: img.Image, Digest: img.Digest}

	ref := img.Digest
	if ref == "" {
		ref = img.Image
	}
	if ref == "" {
		r.Error = "no resolvable image reference"
		return r
	}

	if resolvedRef, wasIndex, err := platform.ResolveDigest(ctx, ref, targetPlatform(ctx, clientset, img.NodeName)); err == nil && wasIndex {
		r.PlatformDigest = resolvedRef
		ref = resolvedRef
	}
	// If ResolveDigest fails (e.g. no network path to the registry from
	// where kubectl-sbom runs), fall through and try the SBOM fetch with
	// the original reference rather than failing the whole lookup here.

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

// targetPlatform determines the OS/architecture of the node a container is
// running on, so a multi-arch image index can be resolved to the manifest
// that was actually pulled. Falls back to platform.DefaultTarget if the
// node is unknown or unreadable (e.g. the caller lacks permission to get
// Node objects).
func targetPlatform(ctx context.Context, clientset kubernetes.Interface, nodeName string) platform.Target {
	if nodeName == "" {
		return platform.DefaultTarget
	}
	node, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil || node.Status.NodeInfo.Architecture == "" || node.Status.NodeInfo.OperatingSystem == "" {
		return platform.DefaultTarget
	}
	return platform.Target{OS: node.Status.NodeInfo.OperatingSystem, Architecture: node.Status.NodeInfo.Architecture}
}
