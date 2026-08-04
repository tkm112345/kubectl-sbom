// Command kubectl-sbom is a kubectl plugin entry point.
package main

import "github.com/tkm112345/kubectl-sbom/internal/cli"

func main() {
	cli.Execute()
}
