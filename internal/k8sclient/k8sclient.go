// Package k8sclient builds a Kubernetes clientset from the ambient
// kubeconfig, following the same conventions as kubectl itself.
package k8sclient

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// New builds a clientset and resolves the effective namespace. If
// kubeconfigPath is empty, the standard kubeconfig loading rules (KUBECONFIG
// env var, then ~/.kube/config) are used. If namespaceOverride is empty, the
// namespace is taken from the current context.
func New(kubeconfigPath, namespaceOverride string) (kubernetes.Interface, string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("load kubeconfig: %w", err)
	}

	namespace := namespaceOverride
	if namespace == "" {
		resolvedNs, _, err := clientConfig.Namespace()
		if err != nil {
			return nil, "", fmt.Errorf("resolve namespace: %w", err)
		}
		namespace = resolvedNs
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, "", fmt.Errorf("build kubernetes client: %w", err)
	}
	return clientset, namespace, nil
}
