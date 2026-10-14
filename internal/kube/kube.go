// Package kube reads certificates from Kubernetes read-only. It lists TLS
// Secrets (type kubernetes.io/tls) and cert-manager Certificate resources with
// the list and get verbs only, parses certificate chains without ever decoding
// key material, and hands the results to the shared inventory.
//
// Reading strategy and the minimal RBAC are documented in
// docs/adr/0005-kubernetes-client.md and docs/cli/scan.md.
package kube

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"iter"
	"sort"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Observation sources recorded in the shared inventory.
const (
	// SourceSecret marks a certificate read from a kubernetes.io/tls Secret.
	SourceSecret = "kube-secret"
	// SourceCertManager marks facts read from a cert-manager Certificate.
	SourceCertManager = "cert-manager"
)

// Stable diagnostic codes reported by the Kubernetes source. Their pages are
// generated from internal/diag/registry.yaml.
const (
	// CodeUnreachable reports an API server that could not be reached.
	CodeUnreachable = "SCD-0014"
	// CodeForbidden reports RBAC that does not allow the required list/get.
	CodeForbidden = "SCD-0015"
	// CodeSecretWithoutCertificate reports a TLS secret with no tls.crt.
	//
	//nolint:gosec // G101: an SCD diagnostic code, not a credential.
	CodeSecretWithoutCertificate = "SCD-0016"
	// CodeCertificateParseFailed reports a PEM chain that could not be parsed.
	CodeCertificateParseFailed = "SCD-0017"
	// CodeCRDMissing reports an absent cert-manager CRD (informational).
	CodeCRDMissing = "SCD-0018"
	// CodeOwnershipFileInvalid reports an ownership file that could not be used.
	CodeOwnershipFileInvalid = "SCD-0019"
)

// defaultLimit is the list/continue page size.
const defaultLimit = 500

// tlsSecretFieldSelector asks the API server for TLS secrets only.
const tlsSecretFieldSelector = "type=kubernetes.io/tls" //nolint:gosec // G101: a Kubernetes field selector, not a credential.

// The only secret keys scadenza knows about. tls.crt is read; tls.key is dropped
// from the object as soon as it is decoded and is never read, copied, logged, or
// retained.
const (
	tlsCertificateKey = "tls.crt"
	tlsPrivateKey     = "tls.key"
)

// errUnreachable reports that no Kubernetes source could be read at all.
var errUnreachable = errors.New("Kubernetes API server unreachable")

// Kubernetes records the raw Kubernetes and cert-manager facts for one
// observation. Renewal classification is a later milestone: only facts are
// recorded here.
type Kubernetes struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	SecretName  string `json:"secret_name,omitempty"`
	IssuerKind  string `json:"issuer_kind,omitempty"`
	IssuerName  string `json:"issuer_name,omitempty"`
	IssuerType  string `json:"issuer_type,omitempty"`
	ACMEServer  string `json:"acme_server,omitempty"`
	Duration    string `json:"duration,omitempty"`
	RenewBefore string `json:"renew_before,omitempty"`
	NotAfter    string `json:"status_not_after,omitempty"`
	RenewalTime string `json:"status_renewal_time,omitempty"`
	Ready       string `json:"ready,omitempty"`
	ReadyReason string `json:"ready_reason,omitempty"`
}

// Observation is one place a certificate was read.
type Observation struct {
	Source     string
	Location   string
	Detail     string
	Kubernetes *Kubernetes
}

// Certificate is one certificate read from Kubernetes. Fingerprint is empty when
// no secret supplied the certificate; DedupKey then keeps the entry distinct.
type Certificate struct {
	Fingerprint  string
	DedupKey     string
	Serial       string
	Names        []string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	Public       *bool
	Owners       []owner.Owner
	Observations []Observation
}

// Problem is a non-fatal Kubernetes reading problem. Code is the stable
// diagnostic code that documents it.
type Problem struct {
	Code       string
	Resource   string
	Namespace  string
	HTTPStatus int32
	Reason     metav1.StatusReason
	Detail     string
}

// Result is everything one Kubernetes scan observed.
type Result struct {
	Certificates []Certificate
	Problems     []Problem
}

// Clients are the read-only Kubernetes clients a Scanner uses.
type Clients struct {
	Kubernetes kubernetes.Interface
	Dynamic    dynamic.Interface
}

// Options configure a scan. Client construction is configured separately by
// LoadOptions.
type Options struct {
	// Namespaces limits the scan; an empty list means every namespace.
	Namespaces []string
	// Limit is the list/continue page size; zero uses the default.
	Limit int64
	// Owners resolves ownership from labels, annotations, and namespaces.
	Owners owner.Config
	// Roots verifies certificate chains; nil uses the system roots.
	Roots *x509.CertPool
	// Clock supplies verification time; nil uses the system clock.
	Clock clock.Clock
}

// Source is the read interface the CLI depends on.
type Source interface {
	Scan(ctx context.Context) (Result, error)
}

// Scanner reads TLS Secrets and cert-manager Certificates. Every request is
// read-only: only list and get are ever issued.
type Scanner struct {
	Clients Clients
	Options Options
}

// New returns a Scanner over clients with options applied.
func New(clients Clients, options Options) *Scanner {
	if options.Limit <= 0 {
		options.Limit = defaultLimit
	}
	if options.Clock == nil {
		options.Clock = clock.System{}
	}
	return &Scanner{Clients: clients, Options: options}
}

// namespaceSignals are the ownership inputs taken from one namespace.
type namespaceSignals struct {
	Labels      map[string]string
	Annotations map[string]string
}

// secretCertificate pairs a parsed certificate with the secret it came from.
type secretCertificate struct {
	certificate Certificate
	namespace   string
	secretName  string
}

// managerFact is one cert-manager Certificate observation.
type managerFact struct {
	namespace   string
	name        string
	secretName  string
	observation Observation
	owners      []owner.Owner
}

// Scan lists TLS Secrets and cert-manager Certificates and returns the
// certificates it could parse. Problems are non-fatal; an error is returned only
// when no Kubernetes source could be read at all.
func (s *Scanner) Scan(ctx context.Context) (Result, error) {
	result := Result{}
	namespaces, problems := s.namespaces(ctx)
	result.Problems = append(result.Problems, problems...)

	listSucceeded := false
	authenticationFailed := false
	parsed := []secretCertificate{}
	for _, namespace := range s.scope() {
		listed := false
		for secret, err := range s.secrets(ctx, namespace, &listed) {
			if err != nil {
				problem, _ := classify(err, "secrets", namespace, false)
				result.Problems = append(result.Problems, problem)
				authenticationFailed = authenticationFailed || apierrors.IsUnauthorized(err)
				break
			}
			found, secretProblems := s.certificatesFromSecret(secret, namespaces)
			result.Problems = append(result.Problems, secretProblems...)
			parsed = append(parsed, found...)
		}
		listSucceeded = listSucceeded || listed
	}

	facts, certificatesListed, certificateProblems, certificateAuthFailed, _ := s.certificateFacts(ctx, namespaces)
	result.Problems = append(result.Problems, certificateProblems...)
	listSucceeded = listSucceeded || certificatesListed
	authenticationFailed = authenticationFailed || certificateAuthFailed

	result.Certificates = attachFacts(parsed, facts)
	sortCertificates(result.Certificates)
	result.Problems = uniqueProblems(result.Problems)

	if authenticationFailed || !listSucceeded {
		return Result{Problems: result.Problems}, fmt.Errorf("read Kubernetes: %w", errUnreachable)
	}
	return result, nil
}

// scope returns the namespaces to list, sorted and deduplicated. An empty result
// still contains metav1.NamespaceAll so every namespace is listed.
func (s *Scanner) scope() []string {
	if len(s.Options.Namespaces) == 0 {
		return []string{metav1.NamespaceAll}
	}
	set := map[string]bool{}
	result := make([]string, 0, len(s.Options.Namespaces))
	for _, namespace := range s.Options.Namespaces {
		namespace = strings.TrimSpace(namespace)
		if namespace == "" || set[namespace] {
			continue
		}
		set[namespace] = true
		result = append(result, namespace)
	}
	if len(result) == 0 {
		return []string{metav1.NamespaceAll}
	}
	sort.Strings(result)
	return result
}

// namespaces maps every readable namespace to its ownership signals.
func (s *Scanner) namespaces(ctx context.Context) (map[string]namespaceSignals, []Problem) {
	result := map[string]namespaceSignals{}
	var problems []Problem
	for object, err := range paginate(ctx, s.limit(), func(ctx context.Context, options metav1.ListOptions) ([]corev1.Namespace, string, error) {
		list, err := s.Clients.Kubernetes.CoreV1().Namespaces().List(ctx, options)
		if err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	}) {
		if err != nil {
			problem, _ := classify(err, "namespaces", "", false)
			return result, append(problems, problem)
		}
		result[object.Name] = namespaceSignals{Labels: object.Labels, Annotations: object.Annotations}
	}
	return result, problems
}

// secrets streams TLS secrets in one namespace, page by page. The private key is
// dropped from each object before it is yielded, so no caller can read it.
func (s *Scanner) secrets(ctx context.Context, namespace string, listed *bool) iter.Seq2[corev1.Secret, error] {
	return paginate(ctx, s.limit(), func(ctx context.Context, options metav1.ListOptions) ([]corev1.Secret, string, error) {
		options.FieldSelector = tlsSecretFieldSelector
		list, err := s.Clients.Kubernetes.CoreV1().Secrets(namespace).List(ctx, options)
		if list != nil {
			for index := range list.Items {
				delete(list.Items[index].Data, tlsPrivateKey)
				delete(list.Items[index].StringData, tlsPrivateKey)
			}
		}
		if err != nil {
			return nil, "", err
		}
		*listed = true
		return list.Items, list.Continue, nil
	})
}

// certificatesFromSecret parses the tls.crt chain of one TLS secret. The secret
// type is re-checked locally because a field selector is not a security
// boundary.
func (s *Scanner) certificatesFromSecret(secret corev1.Secret, namespaces map[string]namespaceSignals) ([]secretCertificate, []Problem) {
	if secret.Type != corev1.SecretTypeTLS {
		return nil, nil
	}
	location := secret.Namespace + "/" + secret.Name
	data, ok := secret.Data[tlsCertificateKey]
	if !ok || len(bytes.TrimSpace(data)) == 0 {
		return nil, []Problem{{Code: CodeSecretWithoutCertificate, Resource: "secrets", Detail: location}}
	}
	chain, err := ParseChain(data)
	if err != nil {
		return nil, []Problem{{Code: CodeCertificateParseFailed, Resource: "secrets", Detail: location + ": " + err.Error()}}
	}
	names := Names(chain.Leaf)
	certificate := Certificate{
		Fingerprint: Fingerprint(chain.Leaf.Raw),
		DedupKey:    "secret/" + location,
		Serial:      Serial(chain.Leaf),
		Names:       names,
		Issuer:      chain.Leaf.Issuer.String(),
		NotBefore:   chain.Leaf.NotBefore,
		NotAfter:    chain.Leaf.NotAfter,
		Public:      s.verify(chain),
		Owners:      s.Options.Owners.Resolve(s.signals(secret.Namespace, "secret/"+location, secret.Labels, secret.Annotations, names, namespaces)),
		Observations: []Observation{{
			Source:   SourceSecret,
			Location: location,
			Detail:   "kubernetes.io/tls secret",
			Kubernetes: &Kubernetes{
				Resource:  "kubernetes.io/tls",
				Namespace: secret.Namespace,
				Name:      secret.Name,
			},
		}},
	}
	return []secretCertificate{{certificate: certificate, namespace: secret.Namespace, secretName: secret.Name}}, nil
}

// verify reports whether the chain verifies against the trusted roots. It
// returns nil (unknown) when it does not: without an SNI host a Kubernetes
// certificate can never be proven private, so it is never reported as false.
func (s *Scanner) verify(chain Chain) *bool {
	roots := s.Options.Roots
	if roots == nil {
		system, err := x509.SystemCertPool()
		if err != nil {
			return nil
		}
		roots = system
	}
	options := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool(), CurrentTime: s.Options.Clock.Now()}
	for _, der := range chain.Der[1:] {
		if parsed, err := x509.ParseCertificate(der); err == nil {
			options.Intermediates.AddCert(parsed)
		}
	}
	if _, err := chain.Leaf.Verify(options); err != nil {
		return nil
	}
	verified := true
	return &verified
}

// signals assembles the pure ownership inputs for one object.
func (s *Scanner) signals(namespace, object string, labels, annotations map[string]string, names []string, namespaces map[string]namespaceSignals) owner.Signals {
	declared := namespaces[namespace]
	return owner.Signals{
		Object:               object,
		Labels:               labels,
		Annotations:          annotations,
		Namespace:            namespace,
		NamespaceLabels:      declared.Labels,
		NamespaceAnnotations: declared.Annotations,
		Names:                names,
	}
}

// attachFacts merges cert-manager observations into the certificates read from
// secrets, and emits one entry for each Certificate whose secret was not read.
func attachFacts(parsed []secretCertificate, facts []managerFact) []Certificate {
	result := make([]Certificate, 0, len(parsed)+len(facts))
	matched := make([]bool, len(facts))
	for _, entry := range parsed {
		certificate := entry.certificate
		for index, fact := range facts {
			if fact.namespace != entry.namespace || fact.secretName != entry.secretName {
				continue
			}
			matched[index] = true
			certificate.Observations = append(certificate.Observations, fact.observation)
			certificate.Owners = mergeOwners(certificate.Owners, fact.owners)
		}
		sortObservations(certificate.Observations)
		certificate.Owners = sortOwners(certificate.Owners)
		result = append(result, certificate)
	}
	for index, fact := range facts {
		if matched[index] {
			continue
		}
		result = append(result, Certificate{
			DedupKey:     "cert-manager/" + fact.namespace + "/" + fact.name,
			Owners:       sortOwners(fact.owners),
			Observations: []Observation{fact.observation},
		})
	}
	return result
}

func mergeOwners(existing, added []owner.Owner) []owner.Owner {
	set := map[string]owner.Owner{}
	for _, entry := range append(append([]owner.Owner(nil), existing...), added...) {
		set[entry.Value+"\x00"+string(entry.Source)+"\x00"+entry.Location] = entry
	}
	result := make([]owner.Owner, 0, len(set))
	for _, entry := range set {
		result = append(result, entry)
	}
	return result
}

func sortOwners(entries []owner.Owner) []owner.Owner {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Value != entries[j].Value {
			return entries[i].Value < entries[j].Value
		}
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].Location < entries[j].Location
	})
	return entries
}

func sortObservations(entries []Observation) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].Location < entries[j].Location
	})
}

func sortCertificates(entries []Certificate) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Fingerprint != entries[j].Fingerprint {
			return entries[i].Fingerprint < entries[j].Fingerprint
		}
		return entries[i].DedupKey < entries[j].DedupKey
	})
}

func uniqueProblems(problems []Problem) []Problem {
	set := map[string]bool{}
	result := make([]Problem, 0, len(problems))
	for _, problem := range problems {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s\x00%s", problem.Code, problem.Resource, problem.Namespace, problem.HTTPStatus, problem.Reason, problem.Detail)
		if set[key] {
			continue
		}
		set[key] = true
		result = append(result, problem)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Code != result[j].Code {
			return result[i].Code < result[j].Code
		}
		if result[i].Resource != result[j].Resource {
			return result[i].Resource < result[j].Resource
		}
		return result[i].Detail < result[j].Detail
	})
	return result
}

func (s *Scanner) limit() int64 {
	if s.Options.Limit <= 0 {
		return defaultLimit
	}
	return s.Options.Limit
}

// paginate lists every page of a resource and yields each item in order.
func paginate[T any](ctx context.Context, limit int64, page func(context.Context, metav1.ListOptions) ([]T, string, error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		options := metav1.ListOptions{Limit: limit}
		for {
			items, continueToken, err := page(ctx, options)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for index := range items {
				if err := ctx.Err(); err != nil {
					var zero T
					yield(zero, err)
					return
				}
				if !yield(items[index], nil) {
					return
				}
			}
			if continueToken == "" {
				return
			}
			if err := ctx.Err(); err != nil {
				var zero T
				yield(zero, err)
				return
			}
			options.Continue = continueToken
		}
	}
}

// unstructuredItems lists one page at a time from the dynamic client.
func (s *Scanner) unstructuredItems(ctx context.Context, resource schema.GroupVersionResource, namespace string, listed *bool) iter.Seq2[unstructured.Unstructured, error] {
	return paginate(ctx, s.limit(), func(ctx context.Context, options metav1.ListOptions) ([]unstructured.Unstructured, string, error) {
		list, err := s.Clients.Dynamic.Resource(resource).Namespace(namespace).List(ctx, options)
		if err != nil {
			return nil, "", err
		}
		if listed != nil {
			*listed = true
		}
		return list.Items, list.GetContinue(), nil
	})
}

// certificateFacts reads every cert-manager Certificate and resolves its issuer.
func (s *Scanner) certificateFacts(ctx context.Context, namespaces map[string]namespaceSignals) ([]managerFact, bool, []Problem, bool, bool) {
	var problems []Problem

	index, indexProblems, authenticationFailed, crdMissing := s.issuerIndex(ctx)
	problems = append(problems, indexProblems...)

	facts := []managerFact{}
	listed := false
	for _, namespace := range s.scope() {
		if crdMissing {
			break
		}
		for object, err := range s.unstructuredItems(ctx, certManagerResource(certificateResourceName), namespace, &listed) {
			if err != nil {
				problem, _ := classify(err, "certificates", namespace, true)
				problems = append(problems, problem)
				authenticationFailed = authenticationFailed || apierrors.IsUnauthorized(err)
				crdMissing = crdMissing || problem.Code == CodeCRDMissing
				break
			}
			fact, ok := certificateFact(&object, index)
			if !ok {
				continue
			}
			fact.owners = s.Options.Owners.Resolve(s.signals(fact.namespace, "certificate/"+fact.namespace+"/"+fact.name, object.GetLabels(), object.GetAnnotations(), nil, namespaces))
			facts = append(facts, fact)
		}
	}
	sort.SliceStable(facts, func(i, j int) bool {
		if facts[i].namespace != facts[j].namespace {
			return facts[i].namespace < facts[j].namespace
		}
		return facts[i].name < facts[j].name
	})
	return facts, listed, problems, authenticationFailed, crdMissing
}

// classify turns a client error into a documented problem. fatal reports that
// the API server could not be reached at all.
func classify(err error, resource, namespace string, certManager bool) (Problem, bool) {
	problem := Problem{Resource: resource, Namespace: namespace}
	if status, ok := err.(apierrors.APIStatus); ok {
		problem.HTTPStatus = status.Status().Code
		problem.Reason = status.Status().Reason
	}
	switch {
	case apierrors.IsUnauthorized(err):
		problem.Code = CodeUnreachable
		return problem, true
	case apierrors.IsForbidden(err):
		problem.Code = CodeForbidden
		return problem, false
	case certManager && isCRDMissing(err):
		problem.Code = CodeCRDMissing
		return problem, false
	default:
		problem.Code = CodeUnreachable
		return problem, true
	}
}

// isCRDMissing reports an absent custom resource definition.
func isCRDMissing(err error) bool {
	if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) || runtime.IsNotRegisteredError(err) {
		return true
	}
	// VERIFY: a missing CRD surfaces as a discovery failure on some API servers
	// and as a scheme lookup failure in the dynamic fake, so the message is
	// inspected as a last resort.
	message := err.Error()
	for _, fragment := range []string{
		"no matches for kind",
		"could not find the requested resource",
		"no list kind registered",
		"no kind registered",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}
