package dnstwist

import (
	"fmt"

	"github.com/ducksify/godnstwist/pkg/formatter"
	"github.com/ducksify/godnstwist/pkg/fuzzer"
	"github.com/ducksify/godnstwist/pkg/scanner"
)

// Options represents the configuration options for the domain permutation engine

// New creates a new domain permutation engine with the given options
func New(options Options) (*Engine, error) {
	if options.Domain == "" {
		return nil, fmt.Errorf("domain name is required")
	}

	if options.Registered && options.Unregistered {
		return nil, fmt.Errorf("options Registered and Unregistered are mutually exclusive")
	}

	if options.Threads < 1 {
		return nil, fmt.Errorf("number of threads must be greater than zero")
	}

	// Initialize fuzzer
	f := fuzzer.NewFuzzer(options.Domain)
	if f == nil {
		return nil, fmt.Errorf("invalid domain name: %s", options.Domain)
	}

	// Initialize scanner
	scannerConfig := &scanner.Config{
		All:         options.All,
		Banners:     options.Banners,
		GeoIP:       options.GeoIP,
		LSH:         options.LSH,
		MXCheck:     options.MXCheck,
		Nameservers: options.Nameservers,
		PHash:       options.PHash,
		Screenshots: options.Screenshots,
		UserAgent:   options.UserAgent,
		Threads:     options.Threads,
	}

	s := scanner.NewScanner(scannerConfig)

	return &Engine{
		options: options,
		fuzzer:  f,
		scanner: s,
	}, nil
}

// Generate generates domain permutations and returns the results
func (e *Engine) Generate() ([]Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Generate permutations
	if err := e.fuzzer.Generate(e.options.Fuzzers); err != nil {
		return nil, fmt.Errorf("failed to generate permutations: %v", err)
	}

	// Scan domains
	domains := e.scanner.Scan(e.fuzzer.Domains())

	// Convert to results
	results := make([]Result, len(domains))
	for i, domain := range domains {
		results[i] = Result{
			Fuzzer: domain.Fuzzer,
			Domain: domain.Domain,
			DNS:    domain.DNS,
			GeoIP:  domain.GeoIP,
			Banner: domain.Banner,
			Whois:  domain.Whois,
			LSH:    domain.LSH,
			PHash:  domain.PHash,
		}
	}

	return results, nil
}

// Format formats the results according to the specified format
func (e *Engine) Format(results []Result) (string, error) {
	// Convert results to domains
	domains := make([]*fuzzer.Domain, len(results))
	for i, r := range results {
		domains[i] = &fuzzer.Domain{
			Fuzzer: r.Fuzzer,
			Domain: r.Domain,
			DNS:    r.DNS,
			GeoIP:  r.GeoIP,
			Banner: r.Banner,
			Whois:  r.Whois,
			LSH:    r.LSH,
			PHash:  r.PHash,
		}
	}

	// Create formatter
	f := formatter.NewFormatter(domains)
	if f == nil {
		return "", fmt.Errorf("failed to create formatter")
	}

	// Format results
	return f.Format(e.options.Format), nil
}

// Run generates permutations and returns formatted results
func (e *Engine) Run() (string, error) {
	results, err := e.Generate()
	if err != nil {
		return "", err
	}

	return e.Format(results)
}
