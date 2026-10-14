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
	"github.com/HarnageaGabriel/scadenza/internal/render"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
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
			if len(normalizedDomains) == 0 && len(hosts) == 0 && len(fileTokens) == 0 {
				emitDiagnostic(stderr, "SCD-0001", "supply at least one --domain, --host, or --hosts-file")
				return &commandError{code: ExitUsageError}
			}
			targets, err := parseTargets(append(append([]string{}, hosts...), fileTokens...), port)
			if err != nil {
				emitDiagnostic(stderr, "SCD-0001", err.Error())
				return &commandError{code: ExitUsageError}
			}
			for _, domain := range normalizedDomains {
				targets = append(targets, probeTarget{host: domain, port: port})
			}
			chosen, err := resolveSources(sourceNames, dependencies.sources)
			if err != nil {
				emitDiagnostic(stderr, "SCD-0001", err.Error())
				return &commandError{code: ExitUsageError}
			}

			now := dependencies.clock.Now()
			diagnostics := &diagnosticSet{}
			unprobed := map[string]string{}

			var records []ct.Certificate
			usedCT := map[string]bool{}
			ctAvailable := false
			if fromCT && len(normalizedDomains) > 0 {
				for _, domain := range normalizedDomains {
					for index, source := range chosen {
						found, searchErr := source.Search(command.Context(), ct.Query{Domain: domain, IncludeSubdomains: true, Now: now})
						if searchErr == nil {
							records = append(records, found...)
							usedCT[source.Name()] = true
							ctAvailable = true
							break
						}
						code := sourceErrorCode(searchErr)
						diagnostics.add(code, source.Name())
						emitDiagnostic(stderr, code, source.Name())
						if index < len(chosen)-1 {
							diagnostics.add("SCD-0007", source.Name())
							emitDiagnostic(stderr, "SCD-0007", source.Name()+" -> "+chosen[index+1].Name())
						}
					}
				}
				derived, wildcards := deriveHosts(records, normalizedDomains)
				targets = append(targets, derived...)
				for _, name := range wildcards {
					unprobed[name] = "wildcard"
					diagnostics.add("SCD-0008", name)
					emitDiagnostic(stderr, "SCD-0008", name)
				}
			}

			targets = dedupeTargets(targets)
			if len(targets) > maxHosts {
				for _, target := range targets[maxHosts:] {
					unprobed[target.host] = "host-cap"
				}
				diagnostics.add("SCD-0009", fmt.Sprint(maxHosts))
				emitDiagnostic(stderr, "SCD-0009", strconv.Itoa(maxHosts))
				targets = targets[:maxHosts]
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
			live, probeErrors, successes := runProbes(command.Context(), prober, targets, concurrency)
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

			if !ctAvailable && successes == 0 && (len(normalizedDomains) > 0 || len(targets) > 0) {
				return &commandError{code: ExitSourceUnavailable}
			}
			if err := render.Scan(stdout, format, document); err != nil {
				return fmt.Errorf("render output: %w", err)
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
	return command
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
		line := scanner.Text()
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

func deriveHosts(records []ct.Certificate, domains []string) ([]probeTarget, []string) {
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
			host, port, err := tlsprobe.ParseEndpoint(name, 443)
			if err != nil {
				continue
			}
			targets[host+":"+strconv.Itoa(port)] = probeTarget{host: host, port: port}
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
