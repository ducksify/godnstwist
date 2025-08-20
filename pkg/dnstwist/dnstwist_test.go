package dnstwist

import (
	"strings"
	"testing"
)

func TestEngine_New(t *testing.T) {
	// Test valid domain
	options := Options{
		Domain:  "example.com",
		Threads: 4,
	}
	engine, err := New(options)
	if err != nil {
		t.Errorf("New() error = %v", err)
	}
	if engine == nil {
		t.Error("New() returned nil engine")
	}

	// Test empty domain
	_, err = New(Options{})
	if err == nil {
		t.Error("New() should return error for empty domain")
	}

	// Test invalid domain
	_, err = New(Options{Domain: "invalid domain"})
	if err == nil {
		t.Error("New() should return error for invalid domain")
	}

	// Test mutually exclusive options
	_, err = New(Options{
		Domain:       "example.com",
		Registered:   true,
		Unregistered: true,
	})
	if err == nil {
		t.Error("New() should return error for mutually exclusive options")
	}

	// Test invalid threads
	_, err = New(Options{
		Domain:  "example.com",
		Threads: 0,
	})
	if err == nil {
		t.Error("New() should return error for invalid threads")
	}
}

func TestEngine_Generate_WithRegisteredFilter(t *testing.T) {
	options := Options{
		Domain:     "example.com",
		Registered: true,
		Threads:    4,
		Fuzzers:    "addition",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("GetResults() error = %v", err)
	}

	// All results should have either A or NS records (registered)
	for _, result := range results {
		if !result.HasARecords() && !result.HasNSRecords() {
			t.Errorf("Result %s should be registered but has no A or NS records", result.Domain)
		}
	}
}

func TestEngine_Generate_WithUnregisteredFilter(t *testing.T) {
	options := Options{
		Domain:       "example.com",
		Unregistered: true,
		Threads:      4,
		Fuzzers:      "addition",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("GetResults() error = %v", err)
	}

	// All results should not have A or NS records (unregistered)
	for _, result := range results {
		if result.HasARecords() || result.HasNSRecords() {
			t.Errorf("Result %s should be unregistered but has A or NS records", result.Domain)
		}
	}
}

func TestEngine_Generate_WithRegisteredByA(t *testing.T) {
	options := Options{
		Domain:       "example.com",
		Registered:   true,
		RegisteredBy: "A",
		Threads:      4,
		Fuzzers:      "addition",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("GetResults() error = %v", err)
	}

	// All results should have A records
	for _, result := range results {
		if !result.HasARecords() {
			t.Errorf("Result %s should have A records", result.Domain)
		}
	}
}

func TestEngine_Generate_WithRegisteredByNS(t *testing.T) {
	options := Options{
		Domain:       "example.com",
		Registered:   true,
		RegisteredBy: "NS",
		Threads:      4,
		Fuzzers:      "addition",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("GetResults() error = %v", err)
	}

	// All results should have NS records
	for _, result := range results {
		if !result.HasNSRecords() {
			t.Errorf("Result %s should have NS records", result.Domain)
		}
	}
}

func TestResults_GetDomainsWithARecords(t *testing.T) {
	results := Results{
		{
			Fuzzer: "test1",
			Domain: "example1.com",
			DNS: map[string][]string{
				"A": {"192.168.1.1"},
			},
		},
		{
			Fuzzer: "test2",
			Domain: "example2.com",
			DNS: map[string][]string{
				"MX": {"mail.example.com"},
			},
		},
	}

	filtered := results.GetDomainsWithARecords()
	if len(filtered) != 1 {
		t.Errorf("Expected 1 result with A records, got %d", len(filtered))
	}
	if filtered[0].Domain != "example1.com" {
		t.Errorf("Expected example1.com, got %s", filtered[0].Domain)
	}
}

func TestResults_GetDomainsWithMXRecords(t *testing.T) {
	results := Results{
		{
			Fuzzer: "test1",
			Domain: "example1.com",
			DNS: map[string][]string{
				"A": {"192.168.1.1"},
			},
		},
		{
			Fuzzer: "test2",
			Domain: "example2.com",
			DNS: map[string][]string{
				"MX": {"mail.example.com"},
			},
		},
	}

	filtered := results.GetDomainsWithMXRecords()
	if len(filtered) != 1 {
		t.Errorf("Expected 1 result with MX records, got %d", len(filtered))
	}
	if filtered[0].Domain != "example2.com" {
		t.Errorf("Expected example2.com, got %s", filtered[0].Domain)
	}
}

func TestResults_GetDomainsWithNSRecords(t *testing.T) {
	results := Results{
		{
			Fuzzer: "test1",
			Domain: "example1.com",
			DNS: map[string][]string{
				"A": {"192.168.1.1"},
			},
		},
		{
			Fuzzer: "test2",
			Domain: "example2.com",
			DNS: map[string][]string{
				"NS": {"ns1.example.com"},
			},
		},
	}

	filtered := results.GetDomainsWithNSRecords()
	if len(filtered) != 1 {
		t.Errorf("Expected 1 result with NS records, got %d", len(filtered))
	}
	if filtered[0].Domain != "example2.com" {
		t.Errorf("Expected example2.com, got %s", filtered[0].Domain)
	}
}

func TestResults_GetDomainsWithoutARecords(t *testing.T) {
	results := Results{
		{
			Fuzzer: "test1",
			Domain: "example1.com",
			DNS: map[string][]string{
				"A": {"192.168.1.1"},
			},
		},
		{
			Fuzzer: "test2",
			Domain: "example2.com",
			DNS: map[string][]string{
				"MX": {"mail.example.com"},
			},
		},
	}

	filtered := results.GetDomainsWithoutARecords()
	if len(filtered) != 1 {
		t.Errorf("Expected 1 result without A records, got %d", len(filtered))
	}
	if filtered[0].Domain != "example2.com" {
		t.Errorf("Expected example2.com, got %s", filtered[0].Domain)
	}
}

func TestResults_Format(t *testing.T) {
	results := Results{
		{
			Fuzzer: "test",
			Domain: "example.com",
			DNS: map[string][]string{
				"A": {"192.168.1.1"},
			},
		},
	}

	// Test JSON format
	jsonOutput := results.Format("json")
	if !strings.Contains(jsonOutput, "example.com") {
		t.Error("JSON output should contain domain name")
	}

	// Test CSV format
	csvOutput := results.Format("csv")
	if !strings.Contains(csvOutput, "example.com") {
		t.Error("CSV output should contain domain name")
	}

	// Test list format
	listOutput := results.Format("list")
	if !strings.Contains(listOutput, "example.com") {
		t.Error("List output should contain domain name")
	}
}

func TestCyrillicDetectionAndPunycode(t *testing.T) {
	// Test containsCyrillic function
	tests := []struct {
		input    string
		expected bool
	}{
		{"google.com", false},
		{"gооgle.com", true},  // Cyrillic 'о' (о)
		{"gооgle.com", true},  // Cyrillic 'о' (о)
		{"gооgle.com", true},  // Cyrillic 'о' (о)
		{"gооgle.com", true},  // Cyrillic 'о' (о)
		{"gοοgle.com", false}, // Greek, not Cyrillic
	}

	for _, test := range tests {
		result := containsCyrillic(test.input)
		if result != test.expected {
			t.Errorf("containsCyrillic(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}

	// Test containsNonASCII function
	nonASCIITests := []struct {
		input    string
		expected bool
	}{
		{"google.com", false},
		{"gооgle.com", true}, // Cyrillic
		{"gοοgle.com", true}, // Greek
		{"gооgle.com", true}, // Cyrillic
	}

	for _, test := range nonASCIITests {
		result := containsNonASCII(test.input)
		if result != test.expected {
			t.Errorf("containsNonASCII(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestCyrillicFieldInResult(t *testing.T) {
	options := Options{
		Domain:  "google.com",
		Threads: 1,
		Fuzzers: "homoglyph",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("GetResults() error = %v", err)
	}

	// Find a Cyrillic domain
	var cyrillicResult *Result
	for i := range results {
		if containsCyrillic(results[i].Domain) {
			cyrillicResult = &results[i]
			break
		}
	}

	if cyrillicResult == nil {
		t.Fatal("No Cyrillic domain found in results")
	}

	if !cyrillicResult.Cyrillic {
		t.Errorf("Domain %s should have Cyrillic=true but got %v", cyrillicResult.Domain, cyrillicResult.Cyrillic)
	}

	// Check that ASCII domains have Cyrillic=false
	for _, result := range results {
		if !containsCyrillic(result.Domain) && result.Cyrillic {
			t.Errorf("Domain %s should have Cyrillic=false but got %v", result.Domain, result.Cyrillic)
		}
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
		},
	}
}
