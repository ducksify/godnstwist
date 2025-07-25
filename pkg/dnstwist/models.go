package dnstwist

import (
	"sync"

	"github.com/ducksify/godnstwist/pkg/formatter"
	"github.com/ducksify/godnstwist/pkg/fuzzer"
	"github.com/ducksify/godnstwist/pkg/scanner"
)

type Options struct {
	// Domain is the target domain to analyze
	Domain string

	// All prints all DNS records instead of the first ones
	All bool

	// Banners determines HTTP and SMTP service banners
	Banners bool

	// Dictionary generates more domains using dictionary file
	Dictionary string

	// Format specifies the output format (cli, csv, json, list)
	Format string

	// Fuzzers specifies which fuzzing algorithms to use (comma-separated)
	Fuzzers string

	// GeoIP performs GeoIP location lookup
	GeoIP bool

	// LSH evaluates web page similarity with LSH algorithm (ssdeep, tlsh)
	LSH string

	// LSHURL overrides URL to fetch the original web page from
	LSHURL string

	// MXCheck checks if MX host can be used to intercept emails
	MXCheck bool

	// Output saves output to file
	Output string

	// Registered shows only registered domain names
	Registered bool

	// Unregistered shows only unregistered domain names
	Unregistered bool

	// PHash renders web pages and evaluates visual similarity
	PHash bool

	// PHashURL overrides URL to render the original web page from
	PHashURL string

	// Screenshots saves web page screenshots into directory
	Screenshots string

	// Threads specifies the number of concurrent threads
	Threads int

	// Whois looks up WHOIS database for creation date and registrar
	Whois bool

	// TLD swaps TLD for the original domain from file
	TLD string

	// Nameservers specifies DNS or DoH servers to query (comma-separated)
	Nameservers string

	// UserAgent sets the User-Agent string
	UserAgent string
}

// Result represents a single domain permutation result
type Result struct {
	Fuzzer string              `json:"fuzzer"`
	Domain string              `json:"domain"`
	DNS    map[string][]string `json:"dns,omitempty"`
	GeoIP  string              `json:"geoip,omitempty"`
	Banner map[string]string   `json:"banner,omitempty"`
	Whois  map[string]string   `json:"whois,omitempty"`
	LSH    map[string]int      `json:"lsh,omitempty"`
	PHash  int                 `json:"phash,omitempty"`
}

// Results represents a slice of Result objects
type Results []Result

// ToDomain converts a Result to a fuzzer.Domain
func (r *Result) toDomain() *fuzzer.Domain {
	return &fuzzer.Domain{
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

// toDomains converts a slice of Result objects to a slice of fuzzer.Domain objects
func toDomains(results []Result) []*fuzzer.Domain {
	domains := make([]*fuzzer.Domain, len(results))
	for i, result := range results {
		domains[i] = result.toDomain()
	}
	return domains
}

// Format formats the Results slice according to the specified format
func (r Results) Format(format string) string {
	domains := toDomains(r)
	f := formatter.NewFormatter(domains)
	if f == nil {
		return ""
	}
	return f.Format(format)
}

// Engine represents the domain permutation engine
type Engine struct {
	options Options
	fuzzer  *fuzzer.Fuzzer
	scanner *scanner.Scanner
	mu      sync.Mutex
}
