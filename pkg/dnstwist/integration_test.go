package dnstwist

import (
	"testing"
)

// TestIntegration_BasicUsage demonstrates the basic usage of the dnstwist package
func TestIntegration_BasicUsage(t *testing.T) {
	// Create basic options
	options := Options{
		Domain:  "example.com",
		Threads: 2,
		Format:  "json",
		Fuzzers: "addition,omission,transposition",
	}

	// Create engine
	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Generate results
	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("Failed to get results: %v", err)
	}

	// Verify we got some results
	if len(results) == 0 {
		t.Error("Expected some results but got none")
	}

	// Verify original domain is included
	foundOriginal := false
	for _, result := range results {
		if result.Domain == "example.com" && result.Fuzzer == "original" {
			foundOriginal = true
			break
		}
	}
	if !foundOriginal {
		t.Error("Original domain not found in results")
	}

	// Test formatting
	formatted := results.Format("json")
	if formatted == "" {
		t.Error("Failed to format results as JSON")
	}

	formatted = results.Format("csv")
	if formatted == "" {
		t.Error("Failed to format results as CSV")
	}

	formatted = results.Format("list")
	if formatted == "" {
		t.Error("Failed to format results as list")
	}

	formatted = results.Format("cli")
	if formatted == "" {
		t.Error("Failed to format results as CLI")
	}
}

// TestIntegration_RegisteredDomainsOnly tests filtering for registered domains only
func TestIntegration_RegisteredDomainsOnly(t *testing.T) {
	options := Options{
		Domain:     "google.com", // Use a well-known domain that should be registered
		Threads:    1,
		Registered: true,
		Fuzzers:    "addition", // Limit to one fuzzer for faster test
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("Failed to get results: %v", err)
	}

	// All results should have DNS A records (registered domains)
	for _, result := range results {
		if len(result.DNS["A"]) == 0 {
			t.Errorf("Expected registered domain but %s has no A records", result.Domain)
		}
	}
}

// TestIntegration_MultipleFormats tests various output formats
func TestIntegration_MultipleFormats(t *testing.T) {
	options := Options{
		Domain:  "test.com",
		Threads: 1,
		Fuzzers: "omission",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	results, err := engine.GetResults()
	if err != nil {
		t.Fatalf("Failed to get results: %v", err)
	}

	formats := []string{"json", "csv", "list", "cli"}
	for _, format := range formats {
		formatted := results.Format(format)
		if formatted == "" {
			t.Errorf("Format %s produced empty output", format)
		}
		t.Logf("Format %s produced %d characters of output", format, len(formatted))
	}
}

// TestIntegration_ErrorHandling tests error scenarios
func TestIntegration_ErrorHandling(t *testing.T) {
	// Test with invalid domain
	_, err := New(Options{
		Domain:  "invalid-domain",
		Threads: 1,
	})
	if err == nil {
		t.Error("Expected error for invalid domain")
	}

	// Test with zero threads
	_, err = New(Options{
		Domain:  "test.com",
		Threads: 0,
	})
	if err == nil {
		t.Error("Expected error for zero threads")
	}

	// Test with conflicting flags
	_, err = New(Options{
		Domain:       "test.com",
		Threads:      1,
		Registered:   true,
		Unregistered: true,
	})
	if err == nil {
		t.Error("Expected error for conflicting flags")
	}
}

// TestIntegration_ConcurrentEngines tests multiple engines running concurrently
func TestIntegration_ConcurrentEngines(t *testing.T) {
	domains := []string{"test1.com", "test2.com", "test3.com"}
	results := make([]Results, len(domains))
	errors := make([]error, len(domains))

	// Create and run multiple engines concurrently
	done := make(chan int, len(domains))
	for i, domain := range domains {
		go func(index int, d string) {
			defer func() { done <- index }()

			options := Options{
				Domain:  d,
				Threads: 1,
				Fuzzers: "addition",
			}

			engine, err := New(options)
			if err != nil {
				errors[index] = err
				return
			}

			results[index], errors[index] = engine.GetResults()
		}(i, domain)
	}

	// Wait for all engines to complete
	for i := 0; i < len(domains); i++ {
		<-done
	}

	// Check results
	for i, err := range errors {
		if err != nil {
			t.Errorf("Engine %d failed: %v", i, err)
		}
		if len(results[i]) == 0 {
			t.Errorf("Engine %d produced no results", i)
		}
	}
}

// BenchmarkIntegration_FullWorkflow benchmarks the complete workflow
func BenchmarkIntegration_FullWorkflow(b *testing.B) {
	options := Options{
		Domain:  "benchmark.com",
		Threads: 2,
		Fuzzers: "addition,omission",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine, err := New(options)
		if err != nil {
			b.Fatalf("Failed to create engine: %v", err)
		}

		results, err := engine.GetResults()
		if err != nil {
			b.Fatalf("Failed to get results: %v", err)
		}

		_ = results.Format("json")
	}
}
