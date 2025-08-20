package dnstwist

import (
	"fmt"
	"strings"

	"github.com/ducksify/godnstwist/internal/formatter"
	"github.com/ducksify/godnstwist/internal/fuzzer"
	"github.com/ducksify/godnstwist/internal/scanner"
)

// containsCyrillic returns true if the string contains Cyrillic characters
func containsCyrillic(s string) bool {
	for _, r := range s {
		if r >= 0x0400 && r <= 0x04FF { // Cyrillic Unicode block
			return true
		}
	}
	return false
}

// containsNonASCII returns true if the string contains non-ASCII characters
func containsNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

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

	// Set TLD files if specified
	if len(options.TLD) > 0 {
		// Join multiple TLD files with commas
		tldFiles := strings.Join(options.TLD, ",")
		f.SetTLDFile(tldFiles)
	}

	// Initialize scanner
	// Enable NS lookups when filtering and either NS is explicitly requested
	// or when using the default OR logic (no explicit selector).
	useNSSelector := strings.EqualFold(options.RegisteredBy, "NS")
	useASelector := strings.EqualFold(options.RegisteredBy, "A")
	defaultOR := !(useNSSelector || useASelector)
	nsNeeded := (options.Registered || options.Unregistered) && (useNSSelector || defaultOR)
	scannerConfig := &scanner.Config{
		All:         options.All,
		Banners:     options.Banners,
		GeoIP:       options.GeoIP,
		LSH:         options.LSH,
		MXCheck:     options.MXCheck,
		NSCheck:     options.NSCheck || nsNeeded,
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

// generate generates domain permutations and returns the results
func (e *Engine) generate() ([]Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Generate permutations
	if err := e.fuzzer.Generate(e.options.Fuzzers); err != nil {
		return nil, fmt.Errorf("failed to generate permutations: %v", err)
	}

	// Scan domains
	domains := e.scanner.Scan(e.fuzzer.Domains())

	// Convert to results
	results := make([]Result, 0, len(domains))
	for _, domain := range domains {
		// Determine registration condition
		recordType := strings.ToUpper(strings.TrimSpace(e.options.RegisteredBy))
		hasA := len(domain.DNS["A"]) > 0
		hasNS := len(domain.DNS["NS"]) > 0
		var isRegistered bool
		switch recordType {
		case "A":
			isRegistered = hasA
		case "NS":
			isRegistered = hasNS
		default:
			// Default: A OR NS
			isRegistered = hasA || hasNS
		}

		// Filter based on registered/unregistered flags
		if e.options.Registered && !isRegistered {
			continue
		}
		if e.options.Unregistered && isRegistered {
			continue
		}

		// Use the Cyrillic field that was already set by the fuzzer
		isCyrillic := domain.Cyrillic

		// Only set Punycode for non-ASCII domains
		var punycode string
		if containsNonASCII(domain.Domain) {
			punycode = domain.Punycode
		}

		results = append(results, Result{
			Fuzzer:   domain.Fuzzer,
			Domain:   domain.Domain,
			Punycode: punycode,
			Cyrillic: isCyrillic,
			DNS:      domain.DNS,
			GeoIP:    domain.GeoIP,
			Banner:   domain.Banner,
			Whois:    domain.Whois,
			LSH:      domain.LSH,
			PHash:    domain.PHash,
		})
	}

	return results, nil
}

// format formats the results according to the specified format
func (e *Engine) format(results []Result) (string, error) {
	// Convert results to domains
	domains := make([]*fuzzer.Domain, len(results))
	for i, r := range results {
		domains[i] = &fuzzer.Domain{
			Fuzzer:   r.Fuzzer,
			Domain:   r.Domain,
			Punycode: r.Punycode,
			Cyrillic: r.Cyrillic,
			DNS:      r.DNS,
			GeoIP:    r.GeoIP,
			Banner:   r.Banner,
			Whois:    r.Whois,
			LSH:      r.LSH,
			PHash:    r.PHash,
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

// GetResults generates permutations and returns the raw Result objects
func (e *Engine) GetResults() (Results, error) {
	return e.generate()
}
