package dnstwist

import (
	"strings"
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		options Options
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid basic options",
			options: Options{
				Domain:  "example.com",
				Threads: 10,
				Format:  "json",
			},
			wantErr: false,
		},
		{
			name: "empty domain",
			options: Options{
				Domain:  "",
				Threads: 10,
			},
			wantErr: true,
			errMsg:  "domain name is required",
		},
		{
			name: "invalid domain",
			options: Options{
				Domain:  "invalid",
				Threads: 10,
			},
			wantErr: true,
			errMsg:  "invalid domain name",
		},
		{
			name: "zero threads",
			options: Options{
				Domain:  "example.com",
				Threads: 0,
			},
			wantErr: true,
			errMsg:  "number of threads must be greater than zero",
		},
		{
			name: "negative threads",
			options: Options{
				Domain:  "example.com",
				Threads: -1,
			},
			wantErr: true,
			errMsg:  "number of threads must be greater than zero",
		},
		{
			name: "mutually exclusive flags - registered and unregistered",
			options: Options{
				Domain:       "example.com",
				Threads:      10,
				Registered:   true,
				Unregistered: true,
			},
			wantErr: true,
			errMsg:  "options Registered and Unregistered are mutually exclusive",
		},
		{
			name: "valid with all features enabled",
			options: Options{
				Domain:      "example.com",
				Threads:     10,
				All:         true,
				Banners:     true,
				GeoIP:       true,
				LSH:         "ssdeep",
				MXCheck:     true,
				PHash:       true,
				Screenshots: "/tmp/screenshots",
				UserAgent:   "Mozilla/5.0",
				Nameservers: "8.8.8.8:53,1.1.1.1:53",
				Format:      "cli",
			},
			wantErr: false,
		},
		{
			name: "valid with registered flag only",
			options: Options{
				Domain:     "example.com",
				Threads:    5,
				Registered: true,
			},
			wantErr: false,
		},
		{
			name: "valid with unregistered flag only",
			options: Options{
				Domain:       "example.com",
				Threads:      5,
				Unregistered: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := New(tt.options)

			if tt.wantErr {
				if err == nil {
					t.Errorf("New() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("New() error = %v, want to contain %v", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("New() unexpected error = %v", err)
				return
			}

			if engine == nil {
				t.Errorf("New() returned nil engine")
				return
			}

			// Verify engine configuration
			if engine.options.Domain != tt.options.Domain {
				t.Errorf("New() domain = %v, want %v", engine.options.Domain, tt.options.Domain)
			}

			if engine.options.Threads != tt.options.Threads {
				t.Errorf("New() threads = %v, want %v", engine.options.Threads, tt.options.Threads)
			}

			if engine.fuzzer == nil {
				t.Errorf("New() fuzzer is nil")
			}

			if engine.scanner == nil {
				t.Errorf("New() scanner is nil")
			}
		})
	}
}

func TestEngine_GetResults(t *testing.T) {
	options := Options{
		Domain:  "example.com",
		Threads: 2,
		Format:  "json",
		Fuzzers: "addition,omission",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("GetResults() error = %v", err)
	}

	if len(results) == 0 {
		t.Error("GetResults() returned no results")
	}

	// Verify results structure
	for _, result := range results {
		if result.Domain == "" {
			t.Error("GetResults() result has empty domain")
		}
		if result.Fuzzer == "" {
			t.Error("GetResults() result has empty fuzzer")
		}
		if result.DNS == nil {
			t.Error("GetResults() result has nil DNS map")
		}
	}
}

func TestEngine_Generate(t *testing.T) {
	options := Options{
		Domain:  "test.com",
		Threads: 1,
		Fuzzers: "addition,omission",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.generate()
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}

	if len(results) == 0 {
		t.Error("generate() returned no results")
	}

	// Check that original domain is included
	foundOriginal := false
	for _, result := range results {
		if result.Domain == "test.com" && result.Fuzzer == "original" {
			foundOriginal = true
			break
		}
	}
	if !foundOriginal {
		t.Error("generate() did not include original domain")
	}
}

func TestEngine_Generate_WithRegisteredFilter(t *testing.T) {
	options := Options{
		Domain:     "example.com",
		Threads:    1,
		Registered: true,
		Fuzzers:    "addition",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.generate()
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}

	// All returned results should have DNS A records (registered domains)
	for _, result := range results {
		if len(result.DNS["A"]) == 0 {
			t.Errorf("generate() with Registered=true returned unregistered domain: %s", result.Domain)
		}
	}
}

func TestEngine_Generate_WithUnregisteredFilter(t *testing.T) {
	options := Options{
		Domain:       "nonexistentdomain12345.com",
		Threads:      1,
		Unregistered: true,
		Fuzzers:      "addition",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.generate()
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}

	// All returned results should NOT have DNS A records (unregistered domains)
	for _, result := range results {
		if len(result.DNS["A"]) > 0 {
			t.Errorf("generate() with Unregistered=true returned registered domain: %s", result.Domain)
		}
	}
}

func TestEngine_Format(t *testing.T) {
	results := []Result{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS: map[string][]string{
				"A": {"93.184.216.34"},
			},
			GeoIP:  "United States",
			Banner: map[string]string{"http": "nginx"},
			Whois:  map[string]string{"registrar": "ICANN"},
			LSH:    map[string]int{"ssdeep": 100},
			PHash:  100,
		},
		{
			Fuzzer: "addition",
			Domain: "examplea.com",
			DNS:    map[string][]string{},
			Banner: map[string]string{},
			Whois:  map[string]string{},
			LSH:    map[string]int{},
		},
	}

	options := Options{
		Domain:  "example.com",
		Threads: 1,
		Format:  "json",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	formatted, err := engine.format(results)
	if err != nil {
		t.Fatalf("format() error = %v", err)
	}

	if formatted == "" {
		t.Error("format() returned empty string")
	}

	// Test different formats
	formats := []string{"json", "csv", "list", "cli"}
	for _, format := range formats {
		engine.options.Format = format
		formatted, err := engine.format(results)
		if err != nil {
			t.Errorf("format() with format %s error = %v", format, err)
		}
		if formatted == "" {
			t.Errorf("format() with format %s returned empty string", format)
		}
	}
}

func TestEngine_ConcurrentAccess(t *testing.T) {
	options := Options{
		Domain:  "example.com",
		Threads: 5,
		Fuzzers: "addition,omission",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test concurrent access to GetResults
	var wg sync.WaitGroup
	numGoroutines := 10
	results := make([]Results, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index], errors[index] = engine.GetResults()
		}(i)
	}

	wg.Wait()

	// Check that all goroutines completed successfully
	for i, err := range errors {
		if err != nil {
			t.Errorf("Goroutine %d failed with error: %v", i, err)
		}
	}

	// Check that all results are valid
	for i, result := range results {
		if len(result) == 0 {
			t.Errorf("Goroutine %d returned empty results", i)
		}
	}
}

func TestResult_ToDomain(t *testing.T) {
	result := &Result{
		Fuzzer: "original",
		Domain: "example.com",
		DNS: map[string][]string{
			"A": {"93.184.216.34"},
		},
		GeoIP:  "United States",
		Banner: map[string]string{"http": "nginx"},
		Whois:  map[string]string{"registrar": "ICANN"},
		LSH:    map[string]int{"ssdeep": 100},
		PHash:  100,
	}

	domain := result.toDomain()

	if domain.Fuzzer != result.Fuzzer {
		t.Errorf("toDomain() fuzzer = %v, want %v", domain.Fuzzer, result.Fuzzer)
	}
	if domain.Domain != result.Domain {
		t.Errorf("toDomain() domain = %v, want %v", domain.Domain, result.Domain)
	}
	if len(domain.DNS["A"]) != len(result.DNS["A"]) {
		t.Errorf("toDomain() DNS length = %v, want %v", len(domain.DNS["A"]), len(result.DNS["A"]))
	}
	if domain.GeoIP != result.GeoIP {
		t.Errorf("toDomain() GeoIP = %v, want %v", domain.GeoIP, result.GeoIP)
	}
	if domain.PHash != result.PHash {
		t.Errorf("toDomain() PHash = %v, want %v", domain.PHash, result.PHash)
	}
}

func TestToDomains(t *testing.T) {
	results := []Result{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS: map[string][]string{
				"A": {"93.184.216.34"},
			},
		},
		{
			Fuzzer: "addition",
			Domain: "examplea.com",
			DNS:    map[string][]string{},
		},
	}

	domains := toDomains(results)

	if len(domains) != len(results) {
		t.Errorf("toDomains() length = %v, want %v", len(domains), len(results))
	}

	for i, domain := range domains {
		if domain.Fuzzer != results[i].Fuzzer {
			t.Errorf("toDomains() fuzzer[%d] = %v, want %v", i, domain.Fuzzer, results[i].Fuzzer)
		}
		if domain.Domain != results[i].Domain {
			t.Errorf("toDomains() domain[%d] = %v, want %v", i, domain.Domain, results[i].Domain)
		}
	}
}

func TestResults_Format(t *testing.T) {
	results := Results{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS: map[string][]string{
				"A": {"93.184.216.34"},
			},
			GeoIP:  "United States",
			Banner: map[string]string{"http": "nginx"},
			Whois:  map[string]string{"registrar": "ICANN"},
			LSH:    map[string]int{"ssdeep": 100},
			PHash:  100,
		},
	}

	formats := []string{"json", "csv", "list", "cli"}
	for _, format := range formats {
		formatted := results.Format(format)
		if formatted == "" {
			t.Errorf("Results.Format() with format %s returned empty string", format)
		}
	}

	// Test invalid format
	formatted := results.Format("invalid")
	if formatted != "" {
		t.Error("Results.Format() with invalid format should return empty string")
	}
}

func TestResults_Format_EmptyResults(t *testing.T) {
	results := Results{}

	formatted := results.Format("json")
	if formatted == "" {
		t.Error("Results.Format() with empty results should not return empty string for JSON")
	}
}

func TestEngine_TLDSwap(t *testing.T) {
	options := Options{
		Domain:  "example.com",
		Fuzzers: "tld-swap",
		Threads: 1,
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("Failed to get results: %v", err)
	}

	// Check that we have results
	if len(results) == 0 {
		t.Error("No results generated")
	}

	// Check that we have tld-swap results
	tldSwapCount := 0
	for _, result := range results {
		if result.Fuzzer == "tld-swap" {
			tldSwapCount++
			// Check that the domain format is correct
			if !strings.HasPrefix(result.Domain, "example.") {
				t.Errorf("Generated domain doesn't start with 'example.': %s", result.Domain)
			}
			// Check that it's not the original domain
			if result.Domain == "example.com" {
				t.Errorf("Generated domain should not be the original: %s", result.Domain)
			}
		}
	}

	if tldSwapCount == 0 {
		t.Skip("No tld-swap results were generated - TLD dictionary files may not be available")
	}
}

func TestEngine_TLDSwapWithCustomFile(t *testing.T) {
	options := Options{
		Domain:  "test.com",
		Fuzzers: "tld-swap",
		TLD:     []string{"dictionaries/abused_tlds.dict"},
		Threads: 1,
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("Failed to get results: %v", err)
	}

	// Check that we have tld-swap results
	tldSwapCount := 0
	for _, result := range results {
		if result.Fuzzer == "tld-swap" {
			tldSwapCount++
			if !strings.HasPrefix(result.Domain, "test.") {
				t.Errorf("Generated domain doesn't start with 'test.': %s", result.Domain)
			}
		}
	}

	if tldSwapCount == 0 {
		t.Skip("No tld-swap results were generated with custom file - TLD dictionary files may not be available")
	}
}

// Benchmark tests
func BenchmarkEngine_GetResults(b *testing.B) {
	options := Options{
		Domain:  "example.com",
		Threads: 4,
		Fuzzers: "addition,omission",
	}

	engine, err := New(options)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.GetResults()
		if err != nil {
			b.Fatalf("GetResults() error = %v", err)
		}
	}
}

func BenchmarkResults_Format_JSON(b *testing.B) {
	results := Results{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS: map[string][]string{
				"A": {"93.184.216.34"},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = results.Format("json")
	}
}

// Test helper functions
func createTestEngine(t *testing.T) *Engine {
	options := Options{
		Domain:  "example.com",
		Threads: 1,
		Format:  "json",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create test engine: %v", err)
	}
	return engine
}

func createTestResults() []Result {
	return []Result{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS: map[string][]string{
				"A": {"93.184.216.34"},
			},
			GeoIP:  "United States",
			Banner: map[string]string{"http": "nginx"},
			Whois:  map[string]string{"registrar": "ICANN"},
			LSH:    map[string]int{"ssdeep": 100},
			PHash:  100,
		},
		{
			Fuzzer: "addition",
			Domain: "examplea.com",
			DNS:    map[string][]string{},
			Banner: map[string]string{},
			Whois:  map[string]string{},
			LSH:    map[string]int{},
		},
	}
}
