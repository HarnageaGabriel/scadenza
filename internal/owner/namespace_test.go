package owner

import "testing"

func TestResolveNamespaceAnnotationProvenance(t *testing.T) {
	config, err := ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	owners := config.Resolve(Signals{
		Object:               "secret/api-tls",
		Namespace:            "payments",
		NamespaceLabels:      map[string]string{"scadenza.io/owner": "label-team"},
		NamespaceAnnotations: map[string]string{"scadenza.io/owner": "annotation-team"},
	})
	sources := map[string]bool{}
	for _, entry := range owners {
		sources[string(entry.Source)] = true
		if entry.Location != "namespace/payments" {
			t.Errorf("location = %q", entry.Location)
		}
	}
	if !sources[string(SourceNamespaceLabel)] {
		t.Error("namespace label must report namespace-label")
	}
	if !sources[string(SourceNamespaceAnnotation)] {
		t.Error("namespace annotation must report namespace-annotation, not namespace-label")
	}
	if sources[string(SourceLabel)] || sources[string(SourceAnnotation)] {
		t.Errorf("unexpected object-level sources: %v", sources)
	}
	if len(owners) != 2 {
		t.Fatalf("owners = %v", owners)
	}
}
