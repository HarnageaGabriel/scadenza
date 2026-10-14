package kube

import (
	"context"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// cert-manager API coordinates. scadenza reads cert-manager through the dynamic
// client and never imports the cert-manager Go module: only cert-manager.io/v1
// is read, and the module offers no compatibility guarantee outside its apis/
// directory. See docs/adr/0005-kubernetes-client.md.
// VERIFY: the group, version, resource names, and the Certificate/Issuer spec
// keys used below against the cert-manager.io/v1 documentation.
const (
	// CertManagerGroup is the cert-manager API group.
	CertManagerGroup = "cert-manager.io"
	// CertManagerVersion is the API version scadenza reads.
	CertManagerVersion = "v1"
	// IssuerKind is the namespaced issuer kind.
	IssuerKind = "Issuer"
	// ClusterIssuerKind is the cluster-scoped issuer kind.
	ClusterIssuerKind = "ClusterIssuer"
)

// Resource names read by the dynamic client.
const (
	certificateResourceName = "certificates"
	issuerResourceName      = "issuers"
	clusterIssuerResource   = "clusterissuers"
)

// Issuer types. They are resolved only from which key exists under the issuer
// spec, or from a foreign issuerRef group. scadenza never guesses: anything else
// is unknown.
const (
	// IssuerTypeACME is an ACME issuer (spec.acme).
	IssuerTypeACME = "acme"
	// IssuerTypeCA is a CA issuer (spec.ca).
	IssuerTypeCA = "ca"
	// IssuerTypeSelfSigned is a self-signed issuer (spec.selfSigned).
	IssuerTypeSelfSigned = "selfSigned"
	// IssuerTypeVault is a Vault issuer (spec.vault).
	IssuerTypeVault = "vault"
	// IssuerTypeVenafi is a Venafi issuer (spec.venafi).
	IssuerTypeVenafi = "venafi"
	// IssuerTypeExternal is an issuerRef that points at a foreign API group.
	IssuerTypeExternal = "external"
	// IssuerTypeUnknown is recorded when the type cannot be established.
	IssuerTypeUnknown = "unknown"
)

// readyConditionType is the cert-manager condition that reports readiness.
const readyConditionType = "Ready"

// certManagerResource builds a group-version-resource for one cert-manager type.
func certManagerResource(name string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: CertManagerGroup, Version: CertManagerVersion, Resource: name}
}

// issuerIndex holds the readable issuer specs, so issuerRef resolution needs no
// extra API call per certificate.
type issuerIndex struct {
	namespaced map[string]map[string]any
	cluster    map[string]map[string]any
}

// resolve returns the issuer type and ACME server URL for one issuerRef. It
// returns unknown whenever the type cannot be established from the cluster.
func (index issuerIndex) resolve(namespace, group, kind, name string) (string, string) {
	switch {
	case group != "" && group != CertManagerGroup:
		return IssuerTypeExternal, ""
	case name == "":
		return IssuerTypeUnknown, ""
	}
	var spec map[string]any
	var ok bool
	if kind == "" {
		kind = IssuerKind
	}
	switch kind {
	case ClusterIssuerKind:
		spec, ok = index.cluster[name]
	case IssuerKind:
		spec, ok = index.namespaced[namespace+"/"+name]
	default:
		return IssuerTypeUnknown, ""
	}
	if !ok {
		return IssuerTypeUnknown, ""
	}
	issuerType := issuerTypeOf(spec)
	if issuerType != IssuerTypeACME {
		return issuerType, ""
	}
	return issuerType, acmeServer(spec)
}

// issuerTypeOf resolves an issuer type from which key exists under the spec.
func issuerTypeOf(spec map[string]any) string {
	matched := ""
	for _, candidate := range []struct {
		key  string
		kind string
	}{
		{"acme", IssuerTypeACME},
		{"ca", IssuerTypeCA},
		{"selfSigned", IssuerTypeSelfSigned},
		{"vault", IssuerTypeVault},
		{"venafi", IssuerTypeVenafi},
	} {
		if value, ok := spec[candidate.key]; ok {
			if _, mapValue := value.(map[string]any); !mapValue || matched != "" {
				return IssuerTypeUnknown
			}
			matched = candidate.kind
		}
	}
	if matched == "" {
		return IssuerTypeUnknown
	}
	return matched
}

// acmeServer returns spec.acme.server. It is public data; no ACME secret or
// privateKeySecretRef content is ever read.
func acmeServer(spec map[string]any) string {
	server, _, err := unstructured.NestedString(spec, "acme", "server")
	if err != nil {
		return ""
	}
	return server
}

// issuerIndex reads every Issuer and ClusterIssuer once. missing reports an
// absent cert-manager CRD, so the caller can skip cert-manager silently.
func (s *Scanner) issuerIndex(ctx context.Context) (issuerIndex, []Problem, bool, bool) {
	index := issuerIndex{namespaced: map[string]map[string]any{}, cluster: map[string]map[string]any{}}
	var problems []Problem
	authenticationFailed := false
	missing := false

	for _, namespace := range s.scope() {
		if missing {
			break
		}
		for object, err := range s.unstructuredItems(ctx, certManagerResource(issuerResourceName), namespace, nil) {
			if err != nil {
				problem, _ := classify(err, "issuers", namespace, true)
				problems = append(problems, problem)
				authenticationFailed = authenticationFailed || apierrors.IsUnauthorized(err)
				missing = missing || problem.Code == CodeCRDMissing
				break
			}
			if spec, ok := nestedMap(&object, "spec"); ok {
				index.namespaced[object.GetNamespace()+"/"+object.GetName()] = spec
			}
		}
	}
	if !missing {
		for object, err := range s.unstructuredItems(ctx, certManagerResource(clusterIssuerResource), "", nil) {
			if err != nil {
				problem, _ := classify(err, "clusterissuers", "", true)
				problems = append(problems, problem)
				authenticationFailed = authenticationFailed || apierrors.IsUnauthorized(err)
				missing = missing || problem.Code == CodeCRDMissing
				break
			}
			if spec, ok := nestedMap(&object, "spec"); ok {
				index.cluster[object.GetName()] = spec
			}
		}
	}
	return index, problems, authenticationFailed, missing
}

// certificateFact reads the raw facts from one cert-manager Certificate.
func certificateFact(object *unstructured.Unstructured, index issuerIndex) (managerFact, bool) {
	spec, ok := nestedMap(object, "spec")
	if !ok {
		return managerFact{}, false
	}
	namespace := object.GetNamespace()
	name := object.GetName()
	secretName, _, _ := unstructured.NestedString(spec, "secretName")
	ref, _ := nestedMap(object, "spec", "issuerRef")
	kind := stringKey(ref, "kind")
	if kind == "" {
		kind = IssuerKind
	}
	issuerName := stringKey(ref, "name")
	issuerType, server := index.resolve(namespace, stringKey(ref, "group"), kind, issuerName)
	status, _ := nestedMap(object, "status")
	ready, reason := readyCondition(status)
	notBeforeValue := stringKey(status, "notBefore")
	notAfterValue := stringKey(status, "notAfter")
	names := nestedStrings(spec, "dnsNames")
	return managerFact{
		namespace:  namespace,
		name:       name,
		secretName: secretName,
		certificate: Certificate{
			DedupKey:  "cert-manager/" + namespace + "/" + name,
			Names:     names,
			Issuer:    kind + "/" + issuerName,
			NotBefore: parseStatusTime(notBeforeValue),
			NotAfter:  parseStatusTime(notAfterValue),
		},
		observation: Observation{
			Source:   SourceCertManager,
			Location: namespace + "/" + name + " -> " + secretName,
			Detail:   "cert-manager Certificate; issuer " + kind + "/" + issuerName + " type=" + issuerType,
			Kubernetes: &Kubernetes{
				Resource:    CertManagerGroup + "/" + CertManagerVersion + " Certificate",
				Namespace:   namespace,
				Name:        name,
				SecretName:  secretName,
				IssuerKind:  kind,
				IssuerName:  issuerName,
				IssuerType:  issuerType,
				ACMEServer:  server,
				Duration:    stringKey(spec, "duration"),
				RenewBefore: stringKey(spec, "renewBefore"),
				NotBefore:   notBeforeValue,
				NotAfter:    notAfterValue,
				RenewalTime: stringKey(status, "renewalTime"),
				Ready:       ready,
				ReadyReason: reason,
			},
		},
	}, true
}

func parseStatusTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func nestedStrings(object map[string]any, key string) []string {
	raw, ok := object[key].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(raw))
	for _, entry := range raw {
		if value, ok := entry.(string); ok && strings.TrimSpace(value) != "" {
			result = append(result, value)
		}
	}
	return result
}

// readyCondition returns the Ready condition status and reason, if present.
func readyCondition(status map[string]any) (string, string) {
	conditions, ok := status["conditions"].([]any)
	if !ok {
		return "", ""
	}
	for _, entry := range conditions {
		condition, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if stringKey(condition, "type") != readyConditionType {
			continue
		}
		return stringKey(condition, "status"), stringKey(condition, "reason")
	}
	return "", ""
}

// nestedMap returns a nested object from an unstructured object.
func nestedMap(object *unstructured.Unstructured, fields ...string) (map[string]any, bool) {
	value, ok, err := unstructured.NestedMap(object.Object, fields...)
	if err != nil || !ok {
		return nil, false
	}
	return value, true
}

// stringKey returns a string field, or an empty string when it is absent or not
// a string.
func stringKey(object map[string]any, key string) string {
	value, ok := object[key].(string)
	if !ok {
		return ""
	}
	return value
}
