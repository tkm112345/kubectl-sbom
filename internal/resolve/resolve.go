// Package resolve maps a Kubernetes resource reference (e.g. "pod/my-pod")
// to the container images it runs, including the immutable digest reported
// in the pod status when available.
package resolve

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ContainerImage describes a single container's image reference.
type ContainerImage struct {
	Container string
	Image     string // reference as declared in the pod spec (may be tag-based)
	Digest    string // repo@sha256:... reference, empty if it could not be resolved
}

// ParseResourceArg splits "<kind>/<name>" into a normalized kind and a name.
func ParseResourceArg(arg string) (kind, name string, err error) {
	parts := strings.SplitN(arg, "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", fmt.Errorf("resource must be in the form <kind>/<name>, e.g. pod/my-pod")
	}
	return normalizeKind(parts[0]), parts[1], nil
}

func normalizeKind(k string) string {
	switch strings.ToLower(k) {
	case "pod", "po", "pods":
		return "pod"
	case "deployment", "deploy", "deployments":
		return "deployment"
	default:
		return strings.ToLower(k)
	}
}

// ContainerImages resolves the container images for the given resource.
// Supported kinds: pod, deployment. For a deployment, it inspects a running
// pod owned by it so that image digests can be reported.
func ContainerImages(ctx context.Context, clientset kubernetes.Interface, namespace, kind, name, containerFilter string) ([]ContainerImage, error) {
	switch kind {
	case "pod":
		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get pod %s/%s: %w", namespace, name, err)
		}
		return imagesFromPod(pod, containerFilter)
	case "deployment":
		dep, err := clientset.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get deployment %s/%s: %w", namespace, name, err)
		}
		selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
		if err != nil {
			return nil, fmt.Errorf("parse deployment selector: %w", err)
		}
		pods, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
		if err != nil {
			return nil, fmt.Errorf("list pods for deployment %s/%s: %w", namespace, name, err)
		}
		if len(pods.Items) == 0 {
			return nil, fmt.Errorf("no pods found for deployment %s/%s", namespace, name)
		}
		pod := &pods.Items[0]
		for i := range pods.Items {
			if pods.Items[i].Status.Phase == corev1.PodRunning {
				pod = &pods.Items[i]
				break
			}
		}
		return imagesFromPod(pod, containerFilter)
	default:
		return nil, fmt.Errorf("unsupported resource kind %q (supported: pod, deployment)", kind)
	}
}

func imagesFromPod(pod *corev1.Pod, containerFilter string) ([]ContainerImage, error) {
	statusByName := make(map[string]corev1.ContainerStatus, len(pod.Status.ContainerStatuses))
	for _, cs := range pod.Status.ContainerStatuses {
		statusByName[cs.Name] = cs
	}

	var result []ContainerImage
	for _, c := range pod.Spec.Containers {
		if containerFilter != "" && c.Name != containerFilter {
			continue
		}
		ci := ContainerImage{Container: c.Name, Image: c.Image}
		if cs, ok := statusByName[c.Name]; ok {
			ci.Digest = digestRefFromImageID(cs.ImageID, c.Image)
		}
		result = append(result, ci)
	}

	if len(result) == 0 {
		if containerFilter != "" {
			return nil, fmt.Errorf("container %q not found in pod %s", containerFilter, pod.Name)
		}
		return nil, fmt.Errorf("no containers found in pod %s", pod.Name)
	}
	return result, nil
}

// digestRefFromImageID turns a container status imageID (which varies in
// format across container runtimes) into a "repo@sha256:..." reference.
func digestRefFromImageID(imageID, image string) string {
	imageID = strings.TrimPrefix(imageID, "docker-pullable://")
	if strings.Contains(imageID, "@sha256:") {
		return imageID
	}
	if !strings.HasPrefix(imageID, "sha256:") {
		return ""
	}
	repo := image
	if at := strings.Index(repo, "@"); at != -1 {
		repo = repo[:at]
	} else if colon := strings.LastIndex(repo, ":"); colon != -1 && !strings.Contains(repo[colon:], "/") {
		repo = repo[:colon]
	}
	return repo + "@" + imageID
}
