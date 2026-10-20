package kube

import (
	"fmt"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// LoadOptions configure client construction. Credential material is never logged
// or returned: only the resulting client is exposed.
type LoadOptions struct {
	// Context selects a kubeconfig context.
	Context string
	// Kubeconfig overrides the default kubeconfig location.
	Kubeconfig string
	// QPS is the client-side request rate; zero uses the documented default.
	QPS float64
	// Burst is the client-side burst; zero derives twice the QPS.
	Burst int
	// UserAgent is sent with every request.
	UserAgent string
}

// defaultQPS is the documented --kube-qps default.
const defaultQPS = 5

// Load builds a read-only Kubernetes client from --kubeconfig, --kube-context,
// the KUBECONFIG environment, or the in-cluster configuration, and returns a
// Scanner with scan options applied.
func Load(load LoadOptions, scan Options) (Source, error) {
	restConfig, err := restConfig(load)
	if err != nil {
		return nil, err
	}
	kubernetesClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	metadataClient, err := newMetadataClient(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create metadata client: %w", err)
	}
	return New(Clients{Kubernetes: kubernetesClient, Metadata: metadataClient, Dynamic: dynamicClient}, scan), nil
}

// newMetadataClient builds the metadata-only client from a copy of the REST
// configuration whose AcceptContentTypes allow only the PartialObjectMetadata
// media types. client-go's metadata constructors reset AcceptContentTypes and
// its List hardcodes an Accept header with a bare application/json fallback, so
// partialObjectMetadataTransport enforces the same restriction at the HTTP
// layer: a response that is not a PartialObjectMetadataList is never retained.
func newMetadataClient(restConfig *rest.Config) (metadata.Interface, error) {
	metadataConfig := metadata.ConfigFor(restConfig)
	metadataConfig.AcceptContentTypes = partialObjectMetadataContentTypes
	metadataConfig.WrapTransport = partialObjectMetadataTransport
	return metadata.NewForConfig(metadataConfig)
}

// restConfig resolves the REST configuration without ever surfacing credentials.
func restConfig(load LoadOptions) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if strings.TrimSpace(load.Kubeconfig) != "" {
		rules.ExplicitPath = load.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if strings.TrimSpace(load.Context) != "" {
		overrides.CurrentContext = load.Context
	}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	qps := load.QPS
	if qps <= 0 {
		qps = defaultQPS
	}
	burst := load.Burst
	if burst <= 0 {
		burst = int(qps * 2)
		if burst < 1 {
			burst = 1
		}
	}
	config.QPS = float32(qps)
	config.Burst = burst
	if load.UserAgent != "" {
		config.UserAgent = load.UserAgent
	}
	return config, nil
}
