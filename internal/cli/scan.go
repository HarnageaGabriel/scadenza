package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/diag"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/kube"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/HarnageaGabriel/scadenza/internal/render"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
	"github.com/HarnageaGabriel/scadenza/internal/version"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// hostProber probes one host for its presented certificate chain.
type hostProber interface {
	Probe(ctx context.Context, host string, port int, sni string) (tlsprobe.Result, error)
}

type probeTarget struct {
	host string
	port int
}

type diagnosticSet struct {
	seen  map[string]bool
	items []diag.Diagnostic
}

func (set *diagnosticSet) add(code, _ string) {
	if set.seen == nil {
		set.seen = map[string]bool{}
	}
	item, ok := diag.Lookup(code)
	if !ok || set.seen[code] {
		return
	}
	set.seen[code] = true
	set.items = append(set.items, item)
}

func newScanCommand(stdout, stderr io.Writer, dependencies ctDependencies) *cobra.Command {
	var domains []string
	var hosts []string
	var hostsFile string
	var sourceNames []string
	var fromCT bool
	var port, concurrency, maxHosts int
	var timeout time.Duration
	var format string
	var kubeEnabled bool
	var kubeContext, kubeconfig, ownershipFile string
	var namespaces []string
	var kubeQPS float64
	command := &cobra.Command{
		Use:   "scan",
		Short: "Correlate Certificate Transparency issuances with live TLS handshakes",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(command *cobra.Command, _ []string) error {
			if format != "table" && format != "json" && format != "csv" {
				emitDiagnostic(stderr, "SCD-0001", "--format must be table, json, or csv")
				return &commandError{code: ExitUsageError}
			}
			if port < 1 || port > 65535 || concurrency < 1 || maxHosts < 1 || timeout <= 0 {
				emitDiagnostic(stderr, "SCD-0001", "invalid --port, --concurrency, --max-hosts, or --timeout")
				return &commandError{code: ExitUsageError}
			}
			if kubeQPS <= 0 {
				emitDiagnostic(stderr, "SCD-0001", "--kube-qps must be positive")
				return &commandError{code: ExitUsageError}
			}
			if !kubeEnabled && (len(namespaces) > 0 || kubeContext != "" || kubeconfig != "" || ownershipFile != "" || command.Flags().Changed("kube-qps")) {
				emitDiagnostic(stderr, "SCD-0001", "--kube-context, --kubeconfig, --namespace, --ownership-file, and --kube-qps require --kube")
				return &commandError{code: ExitUsageError}
			}
			normalizedDomains, err := normalizeDomains(domains)
			if err != nil {
				emitDiagnostic(stderr, "SCD-0001", err.Error())
				return &commandError{code: ExitUsageError}
			}
			fileTokens, err := readHostsFile(hostsFile)
			if err != nil {
				emitDiagnostic(stderr, "SCD-0001", err.Error())
				return &commandError{code: ExitUsageError}
			}
			if len(normalizedDomains) == 0 && len(hosts) == 0 && len(fileTokens) == 0 && !kubeEnabled {
				emitDiagnostic(stderr, "SCD-0001", "supply at least one --domain, --host, --hosts-file, or --kube")
				return &commandError{code: ExitUsageError}
			}
			explicitTargets, err := parseTargets(append(append([]string{}, hosts...), fileTokens...), port)
			if err != nil {
				emitDiagnostic(stderr, "SCD-0001", err.Error())
				return &commandError{code: ExitUsageError}
			}
			for _, domain := range normalizedDomains {
				explicitTargets = append(explicitTargets, probeTarget{host: domain, port: port})
			}
			// Explicitly named targets are never displaced by --max-hosts, so
			// they are kept first and the cap only ever trims derived hosts.
			targets := dedupeTargets(explicitTargets)
			explicitNames := map[string]bool{}
			for _, target := range targets {
				explicitNames[target.host+":"+strconv.Itoa(target.port)] = true
			}
			chosen, err := resolveSources(sourceNames, dependencies.sources)
			if err != nil {
				emitDiagnostic(stderr, "SCD-0001", err.Error())
				return &commandError{code: ExitUsageError}
			}

			now := dependencies.clock.Now()
			diagnostics := &diagnosticSet{}
			unprobed := map[string]string{}

			owners, ownershipErr := loadOwnership(ownershipFile, stderr)
			if ownershipErr != nil {
				return &commandError{code: ExitUsageError}
			}
			kubeRequested := kubeEnabled
			kubeAvailable := false
			var kubeCertificates []kube.Certificate
			if kubeEnabled {
				source, loadErr := dependencies.loadKube(kube.LoadOptions{
					Context:    kubeContext,
					Kubeconfig: kubeconfig,
					QPS:        kubeQPS,
					UserAgent:  "scadenza/" + version.Version,
				}, kube.Options{Namespaces: namespaces, Owners: owners})
				if loadErr != nil {
					diagnostics.add(kube.CodeUnreachable, "")
					emitDiagnostic(stderr, kube.CodeUnreachable, loadErr.Error())
				} else {
					scanResult, scanErr := source.Scan(command.Context())
					for _, problem := range scanResult.Problems {
						diagnostics.add(problem.Code, problem.Resource)
						emitDiagnostic(stderr, problem.Code, problem.Resource+": "+problem.Detail)
					}
					kubeCertificates = scanResult.Certificates
					kubeAvailable = scanErr == nil
					if scanErr != nil {
						diagnostics.add(kube.CodeUnreachable, "")
						emitDiagnostic(stderr, kube.CodeUnreachable, scanErr.Error())
					}
				}
			}

			var records []ct.Certificate
			usedCT := map[string]bool{}
			ctAvailable := false
			if fromCT && len(normalizedDomains) > 0 {
				for _, domain := range normalizedDomains {
					var failed []string
					for _, source := range chosen {
						found, searchErr := source.Search(command.Context(), ct.Query{Domain: domain, IncludeSubdomains: true, Now: now})
						if searchErr == nil {
							// Record the fallback only now that the next source
							// actually answered; a failed fallback is not a fallback.
							if len(failed) > 0 {
								previous := failed[len(failed)-1]
								diagnostics.add("SCD-0007", previous)
								emitDiagnostic(stderr, "SCD-0007", previous+" -> "+source.Name())
							}
							records = append(records, found...)
							usedCT[source.Name()] = true
							ctAvailable = true
							break
						}
						code := sourceErrorCode(searchErr)
						diagnostics.add(code, source.Name())
						emitDiagnostic(stderr, code, source.Name())
						failed = append(failed, source.Name())
					}
				}
				derived, wildcards := deriveHosts(records, normalizedDomains, port)
				available := make([]probeTarget, 0, len(derived))
				for _, target := range dedupeTargets(derived) {
					if !explicitNames[target.host+":"+strconv.Itoa(target.port)] {
						available = append(available, target)
					}
				}
				if len(available) > maxHosts {
					for _, target := range available[maxHosts:] {
						unprobed[target.host] = "host-cap"
					}
					diagnostics.add("SCD-0009", fmt.Sprint(maxHosts))
					emitDiagnostic(stderr, "SCD-0009", strconv.Itoa(maxHosts))
					available = available[:maxHosts]
				}
				targets = append(targets, available...)
				for _, name := range wildcards {
					unprobed[name] = "wildcard"
					diagnostics.add("SCD-0008", name)
					emitDiagnostic(stderr, "SCD-0008", name)
				}
			}

			prober := dependencies.prober
			if prober == nil {
				prober = tlsprobe.New()
			}
			if concrete, ok := prober.(*tlsprobe.Prober); ok {
				clone := *concrete
				clone.Timeout = timeout
				prober = &clone
			}
			live, probeErrors, _ := runProbes(command.Context(), prober, targets, concurrency)
			for _, probeError := range probeErrors {
				diagnostics.add("SCD-0010", probeError.Host)
				emitDiagnostic(stderr, "SCD-0010", probeError.Host+":"+strconv.Itoa(probeError.Port)+" "+probeError.Class)
			}
			for _, result := range live {
				if !result.Trusted {
					diagnostics.add("SCD-0011", result.Host)
					emitDiagnostic(stderr, "SCD-0011", result.Host+":"+strconv.Itoa(result.Port))
				}
			}

			correlated, findings := inventory.Correlate(inventory.Input{
				Domains:  normalizedDomains,
				CT:       records,
				Kube:     kubeCertificates,
				Live:     live,
				Errors:   probeErrors,
				Unprobed: unprobed,
				Now:      now,
			})

			for _, finding := range findings {
				if finding.Kind == inventory.KindCTOnly {
					diagnostics.add("SCD-0012", finding.Fingerprint)
					emitDiagnostic(stderr, "SCD-0012", findingDetail(finding))
				}
				if finding.Kind == inventory.KindLiveOnly {
					diagnostics.add("SCD-0013", finding.Fingerprint)
					emitDiagnostic(stderr, "SCD-0013", findingDetail(finding))
				}
			}

			sourcesUsed := []string{}
			for name := range usedCT {
				sourcesUsed = append(sourcesUsed, name)
			}
			if len(targets) > 0 {
				sourcesUsed = append(sourcesUsed, "tls")
			}
			if kubeRequested && kubeAvailable {
				sourcesUsed = append(sourcesUsed, "kube")
			}
			sort.Strings(sourcesUsed)

			unresolved := make([]inventory.Unresolved, 0, len(unprobed))
			for name, reason := range unprobed {
				detail := "wildcard name is never probed"
				if reason == "host-cap" {
					detail = "beyond --max-hosts; increase the cap to probe it"
				}
				unresolved = append(unresolved, inventory.Unresolved{Name: name, Reason: reason, Detail: detail})
			}
			sort.SliceStable(unresolved, func(i, j int) bool { return unresolved[i].Name < unresolved[j].Name })

			document := render.ScanDocument{
				SchemaVersion: "scadenza.scan/v1",
				GeneratedAt:   now.UTC(),
				Domains:       normalizedDomains,
				SourcesUsed:   sourcesUsed,
				Certificates:  correlated,
				Findings:      findings,
				Unresolved:    unresolved,
				ProbeErrors:   probeErrors,
				Diagnostics:   diagnostics.items,
			}

			if err := render.Scan(stdout, format, document); err != nil {
				return fmt.Errorf("render output: %w", err)
			}
			// Exit 4 needs an external data source (Certificate Transparency or
			// Kubernetes) that was selected and failed entirely. A failed TLS
			// probe is a probe_errors entry, not an unavailable source.
			if sourcesUnavailable(
				sourceState{requested: fromCT && len(normalizedDomains) > 0, available: ctAvailable},
				sourceState{requested: kubeRequested, available: kubeAvailable},
			) {
				return &commandError{code: ExitSourceUnavailable}
			}
			for _, finding := range findings {
				switch finding.Kind {
				case inventory.KindCTOnly, inventory.KindLiveOnly, inventory.KindExceeds100D:
					return &commandError{code: ExitFindingsPresent}
				}
			}
			return nil
		},
	}
	command.Flags().StringArrayVar(&domains, "domain", nil, "domain to scan; repeatable")
	command.Flags().StringArrayVar(&hosts, "host", nil, "host or host:port to probe; repeatable")
	command.Flags().StringVar(&hostsFile, "hosts-file", "", "file with one host per line; '#' starts a comment")
	command.Flags().BoolVar(&fromCT, "from-ct", true, "derive probe hosts from non-wildcard Certificate Transparency names")
	command.Flags().IntVar(&port, "port", 443, "default probe port")
	command.Flags().IntVar(&concurrency, "concurrency", 8, "maximum concurrent probes")
	command.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-probe timeout")
	command.Flags().StringVar(&format, "format", "table", "output format: table, json, csv")
	command.Flags().IntVar(&maxHosts, "max-hosts", 200, "maximum hosts to probe")
	command.Flags().StringSliceVar(&sourceNames, "source", []string{"certspotter", "crtsh"}, "Certificate Transparency source order (certspotter, crtsh)")
	command.Flags().BoolVar(&kubeEnabled, "kube", false, "also read TLS Secrets and cert-manager Certificates from a Kubernetes cluster, read-only")
	command.Flags().StringVar(&kubeContext, "kube-context", "", "kubeconfig context to use")
	command.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig file to use; defaults to KUBECONFIG or the in-cluster configuration")
	command.Flags().StringArrayVar(&namespaces, "namespace", nil, "namespace to read; repeatable; default all namespaces")
	command.Flags().StringVar(&ownershipFile, "ownership-file", "", "YAML file mapping domains, namespaces, and label keys to owners")
	command.Flags().Float64Var(&kubeQPS, "kube-qps", 5, "Kubernetes client request rate per second")
	return command
}

// sourceState is the requested and available state of one input source.
type sourceState struct {
	requested bool
	available bool
}

// sourcesUnavailable reports whether at least one external data source was
// requested and every requested one failed. Partial failures are warnings,
// never exit code 4.
func sourcesUnavailable(states ...sourceState) bool {
	requested := false
	for _, state := range states {
		if !state.requested {
			continue
		}
		requested = true
		if state.available {
			return false
		}
	}
	return requested
}

// loadOwnership reads the optional ownership mapping file. An absent file keeps
// the documented defaults; an unreadable or invalid file is a usage error.
func loadOwnership(path string, stderr io.Writer) (owner.Config, error) {
	if strings.TrimSpace(path) == "" {
		return owner.ParseConfig(nil)
	}
	//nolint:gosec // G304: the path comes from --ownership-file, supplied by the user.
	data, err := os.ReadFile(path)
	if err != nil {
		emitDiagnostic(stderr, kube.CodeOwnershipFileInvalid, path)
		return owner.Config{}, fmt.Errorf("read ownership file: %w", err)
	}
	config, err := owner.ParseConfig(data)
	if err != nil {
		emitDiagnostic(stderr, kube.CodeOwnershipFileInvalid, path)
		return owner.Config{}, err
	}
	return config, nil
}

func findingDetail(finding inventory.Finding) string {
	if finding.Fingerprint != "" {
		return finding.Fingerprint
	}
	return strings.Join(finding.Names, ",")
}

func normalizeDomains(values []string) ([]string, error) {
	set := map[string]bool{}
	result := []string{}
	for _, value := range values {
		domain, err := ct.NormalizeDomain(value)
		if err != nil {
			return nil, err
		}
		if !set[domain] {
			set[domain] = true
			result = append(result, domain)
		}
	}
	sort.Strings(result)
	return result, nil
}

func resolveSources(names []string, available map[string]ct.Source) ([]ct.Source, error) {
	chosen := make([]ct.Source, 0, len(names))
	for _, name := range names {
		source, ok := available[name]
		if !ok {
			return nil, errors.New("unknown source " + name)
		}
		chosen = append(chosen, source)
	}
	return chosen, nil
}

func readHostsFile(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	//nolint:gosec // G304: path comes from the --hosts-file flag, which the user explicitly supplies.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open hosts file: %w", err)
	}
	defer func() { _ = file.Close() }()
	return parseHostsFile(file)
}

// parseHostsFile reads one host per line, ignoring blank lines and treating '#'
// as the start of a comment.
func parseHostsFile(reader io.Reader) ([]string, error) {
	result := []string{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimPrefix(scanner.Text(), "\ufeff")
		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = line[:index]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read hosts file: %w", err)
	}
	return result, nil
}

func parseTargets(values []string, defaultPort int) ([]probeTarget, error) {
	result := make([]probeTarget, 0, len(values))
	for _, value := range values {
		host, port, err := tlsprobe.ParseEndpoint(value, defaultPort)
		if err != nil {
			return nil, err
		}
		result = append(result, probeTarget{host: host, port: port})
	}
	return result, nil
}

func deriveHosts(records []ct.Certificate, domains []string, defaultPort int) ([]probeTarget, []string) {
	targets := map[string]probeTarget{}
	wildcards := map[string]bool{}
	for _, record := range records {
		for _, raw := range record.SubjectNames {
			name := strings.ToLower(strings.TrimSpace(raw))
			name = strings.TrimSuffix(name, ".")
			if name == "" {
				continue
			}
			if strings.Contains(name, "*") {
				if underAnyDomain(strings.TrimPrefix(name, "*."), domains) {
					wildcards[name] = true
				}
				continue
			}
			if !underAnyDomain(name, domains) {
				continue
			}
			host, targetPort, err := tlsprobe.ParseEndpoint(name, defaultPort)
			if err != nil {
				continue
			}
			targets[host+":"+strconv.Itoa(targetPort)] = probeTarget{host: host, port: targetPort}
		}
	}
	result := make([]probeTarget, 0, len(targets))
	for _, target := range targets {
		result = append(result, target)
	}
	sortTargets(result)
	names := make([]string, 0, len(wildcards))
	for name := range wildcards {
		names = append(names, name)
	}
	sort.Strings(names)
	return result, names
}

func underAnyDomain(name string, domains []string) bool {
	for _, domain := range domains {
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true
		}
	}
	return false
}

func dedupeTargets(targets []probeTarget) []probeTarget {
	set := map[string]probeTarget{}
	for _, target := range targets {
		set[target.host+":"+strconv.Itoa(target.port)] = target
	}
	result := make([]probeTarget, 0, len(set))
	for _, target := range set {
		result = append(result, target)
	}
	sortTargets(result)
	return result
}

func sortTargets(targets []probeTarget) {
	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].host != targets[j].host {
			return targets[i].host < targets[j].host
		}
		return targets[i].port < targets[j].port
	})
}

// runProbes probes every target with bounded concurrency, keeping results and
// errors in target order so output stays deterministic.
func runProbes(ctx context.Context, prober hostProber, targets []probeTarget, concurrency int) ([]tlsprobe.Result, []inventory.ProbeError, int) {
	results := make([]tlsprobe.Result, len(targets))
	failures := make([]inventory.ProbeError, len(targets))
	ok := make([]bool, len(targets))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(concurrency)
	for index := range targets {
		index := index
		group.Go(func() error {
			result, err := prober.Probe(groupCtx, targets[index].host, targets[index].port, "")
			if err != nil {
				class := tlsprobe.ClassHandshakeFailed
				var probeErr *tlsprobe.Error
				if errors.As(err, &probeErr) {
					class = probeErr.Class
				}
				failures[index] = inventory.ProbeError{Host: targets[index].host, Port: targets[index].port, Class: string(class), Detail: err.Error()}
				return nil
			}
			results[index] = result
			ok[index] = true
			return nil
		})
	}
	_ = group.Wait()

	live := make([]tlsprobe.Result, 0, len(targets))
	probeErrors := make([]inventory.ProbeError, 0, len(targets))
	successes := 0
	for index := range targets {
		if ok[index] {
			live = append(live, results[index])
			successes++
			continue
		}
		probeErrors = append(probeErrors, failures[index])
	}
	sort.SliceStable(probeErrors, func(i, j int) bool {
		if probeErrors[i].Class != probeErrors[j].Class {
			return probeErrors[i].Class < probeErrors[j].Class
		}
		if probeErrors[i].Host != probeErrors[j].Host {
			return probeErrors[i].Host < probeErrors[j].Host
		}
		return probeErrors[i].Port < probeErrors[j].Port
	})
	return live, probeErrors, successes
}
