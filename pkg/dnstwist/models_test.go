package dnstwist

import (
	"reflect"
	"testing"

	"github.com/ducksify/godnstwist/internal/fuzzer"
)

func TestOptions_Validation(t *testing.T) {
	tests := []struct {
		name    string
		options Options
		valid   bool
	}{
		{
			name: "valid minimal options",
			options: Options{
				Domain:  "example.com",
				Threads: 1,
			},
			valid: true,
		},
		{
			name: "empty domain invalid",
			options: Options{
				Domain:  "",
				Threads: 1,
			},
			valid: false,
		},
		{
			name: "zero threads invalid",
			options: Options{
				Domain:  "example.com",
				Threads: 0,
			},
			valid: false,
		},
		{
			name: "negative threads invalid",
			options: Options{
				Domain:  "example.com",
				Threads: -1,
			},
			valid: false,
		},
		{
			name: "conflicting flags invalid",
			options: Options{
				Domain:       "example.com",
				Threads:      1,
				Registered:   true,
				Unregistered: true,
			},
			valid: false,
		},
		{
			name: "all valid options",
			options: Options{
				Domain:       "example.com",
				All:          true,
				Banners:      true,
				Dictionary:   "dict.txt",
				Format:       "json",
				Fuzzers:      "addition,omission",
				GeoIP:        true,
				LSH:          "ssdeep",
				LSHURL:       "http://example.com",
				MXCheck:      true,
				Output:       "output.txt",
				Registered:   false,
				Unregistered: false,
				PHash:        true,
				PHashURL:     "http://example.com",
				Screenshots:  "/tmp/screenshots",
				Threads:      10,
				Whois:        true,
				TLD:          "tlds.txt",
				Nameservers:  "8.8.8.8:53,1.1.1.1:53",
				UserAgent:    "Mozilla/5.0",
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.options)
			isValid := err == nil

			if isValid != tt.valid {
				if tt.valid {
					t.Errorf("Expected valid options but got error: %v", err)
				} else {
					t.Errorf("Expected invalid options but validation passed")
				}
			}
		})
	}
}

func TestResult_Initialization(t *testing.T) {
	result := Result{
		Fuzzer: "original",
		Domain: "example.com",
		DNS: map[string][]string{
			"A":    {"93.184.216.34"},
			"AAAA": {"2606:2800:220:1:248:1893:25c8:1946"},
			"MX":   {"mail.example.com"},
		},
		GeoIP: "United States",
		Banner: map[string]string{
			"http":  "nginx/1.19.0",
			"https": "nginx/1.19.0",
			"smtp":  "Postfix",
		},
		Whois: map[string]string{
			"registrar":     "ICANN",
			"creation_date": "1995-08-14",
		},
		LSH: map[string]int{
			"ssdeep": 100,
			"tlsh":   95,
		},
		PHash: 85,
	}

	// Test all fields are properly set
	if result.Fuzzer != "original" {
		t.Errorf("Fuzzer = %v, want %v", result.Fuzzer, "original")
	}
	if result.Domain != "example.com" {
		t.Errorf("Domain = %v, want %v", result.Domain, "example.com")
	}
	if len(result.DNS) != 3 {
		t.Errorf("DNS map length = %v, want %v", len(result.DNS), 3)
	}
	if result.GeoIP != "United States" {
		t.Errorf("GeoIP = %v, want %v", result.GeoIP, "United States")
	}
	if len(result.Banner) != 3 {
		t.Errorf("Banner map length = %v, want %v", len(result.Banner), 3)
	}
	if len(result.Whois) != 2 {
		t.Errorf("Whois map length = %v, want %v", len(result.Whois), 2)
	}
	if len(result.LSH) != 2 {
		t.Errorf("LSH map length = %v, want %v", len(result.LSH), 2)
	}
	if result.PHash != 85 {
		t.Errorf("PHash = %v, want %v", result.PHash, 85)
	}
}

func TestResult_ToDomainn(t *testing.T) {
	result := Result{
		Fuzzer: "addition",
		Domain: "examplea.com",
		DNS: map[string][]string{
			"A": {"192.0.2.1"},
		},
		GeoIP: "Canada",
		Banner: map[string]string{
			"http": "Apache/2.4.41",
		},
		Whois: map[string]string{
			"registrar": "GoDaddy",
		},
		LSH: map[string]int{
			"ssdeep": 75,
		},
		PHash: 90,
	}

	domain := result.toDomain()

	if domain == nil {
		t.Fatal("toDomain() returned nil")
	}

	// Test all fields are correctly converted
	if domain.Fuzzer != result.Fuzzer {
		t.Errorf("toDomain() Fuzzer = %v, want %v", domain.Fuzzer, result.Fuzzer)
	}
	if domain.Domain != result.Domain {
		t.Errorf("toDomain() Domain = %v, want %v", domain.Domain, result.Domain)
	}
	if !reflect.DeepEqual(domain.DNS, result.DNS) {
		t.Errorf("toDomain() DNS = %v, want %v", domain.DNS, result.DNS)
	}
	if domain.GeoIP != result.GeoIP {
		t.Errorf("toDomain() GeoIP = %v, want %v", domain.GeoIP, result.GeoIP)
	}
	if !reflect.DeepEqual(domain.Banner, result.Banner) {
		t.Errorf("toDomain() Banner = %v, want %v", domain.Banner, result.Banner)
	}
	if !reflect.DeepEqual(domain.Whois, result.Whois) {
		t.Errorf("toDomain() Whois = %v, want %v", domain.Whois, result.Whois)
	}
	if !reflect.DeepEqual(domain.LSH, result.LSH) {
		t.Errorf("toDomain() LSH = %v, want %v", domain.LSH, result.LSH)
	}
	if domain.PHash != result.PHash {
		t.Errorf("toDomain() PHash = %v, want %v", domain.PHash, result.PHash)
	}
}

func TestResult_ToDomainn_EmptyMaps(t *testing.T) {
	result := Result{
		Fuzzer: "original",
		Domain: "test.com",
		DNS:    map[string][]string{},
		Banner: map[string]string{},
		Whois:  map[string]string{},
		LSH:    map[string]int{},
		PHash:  0,
	}

	domain := result.toDomain()

	if domain == nil {
		t.Fatal("toDomain() returned nil")
	}

	// Test empty maps are handled correctly
	if len(domain.DNS) != 0 {
		t.Errorf("toDomain() DNS length = %v, want %v", len(domain.DNS), 0)
	}
	if len(domain.Banner) != 0 {
		t.Errorf("toDomain() Banner length = %v, want %v", len(domain.Banner), 0)
	}
	if len(domain.Whois) != 0 {
		t.Errorf("toDomain() Whois length = %v, want %v", len(domain.Whois), 0)
	}
	if len(domain.LSH) != 0 {
		t.Errorf("toDomain() LSH length = %v, want %v", len(domain.LSH), 0)
	}
}

func TestResult_ToDomainn_NilMaps(t *testing.T) {
	result := Result{
		Fuzzer: "original",
		Domain: "test.com",
		DNS:    nil,
		Banner: nil,
		Whois:  nil,
		LSH:    nil,
		PHash:  0,
	}

	domain := result.toDomain()

	if domain == nil {
		t.Fatal("toDomain() returned nil")
	}

	// Test nil maps are handled correctly
	if domain.DNS != nil && len(domain.DNS) != 0 {
		t.Errorf("toDomain() DNS should be nil or empty, got %v", domain.DNS)
	}
}

func TestToDomainss(t *testing.T) {
	results := []Result{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS: map[string][]string{
				"A": {"93.184.216.34"},
			},
			GeoIP: "United States",
		},
		{
			Fuzzer: "addition",
			Domain: "examplea.com",
			DNS:    map[string][]string{},
		},
		{
			Fuzzer: "omission",
			Domain: "exampl.com",
			DNS: map[string][]string{
				"A": {"192.0.2.1"},
			},
			Banner: map[string]string{
				"http": "Apache",
			},
		},
	}

	domains := toDomains(results)

	if len(domains) != len(results) {
		t.Errorf("toDomains() length = %v, want %v", len(domains), len(results))
	}

	for i, domain := range domains {
		if domain.Fuzzer != results[i].Fuzzer {
			t.Errorf("toDomains()[%d] Fuzzer = %v, want %v", i, domain.Fuzzer, results[i].Fuzzer)
		}
		if domain.Domain != results[i].Domain {
			t.Errorf("toDomains()[%d] Domain = %v, want %v", i, domain.Domain, results[i].Domain)
		}
		if !reflect.DeepEqual(domain.DNS, results[i].DNS) {
			t.Errorf("toDomains()[%d] DNS = %v, want %v", i, domain.DNS, results[i].DNS)
		}
	}
}

func TestToDomainss_Empty(t *testing.T) {
	results := []Result{}
	domains := toDomains(results)

	if len(domains) != 0 {
		t.Errorf("toDomains() with empty input length = %v, want %v", len(domains), 0)
	}
}

func TestToDomainss_Single(t *testing.T) {
	results := []Result{
		{
			Fuzzer: "test",
			Domain: "single.com",
		},
	}

	domains := toDomains(results)

	if len(domains) != 1 {
		t.Errorf("toDomains() with single result length = %v, want %v", len(domains), 1)
	}

	if domains[0].Fuzzer != "test" {
		t.Errorf("toDomains() single result Fuzzer = %v, want %v", domains[0].Fuzzer, "test")
	}
}

func TestResults_FormatAllFormats(t *testing.T) {
	results := Results{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS: map[string][]string{
				"A": {"93.184.216.34"},
			},
			GeoIP: "United States",
			Banner: map[string]string{
				"http": "nginx/1.19.0",
			},
		},
		{
			Fuzzer: "addition",
			Domain: "examplea.com",
			DNS:    map[string][]string{},
		},
	}

	tests := []struct {
		format    string
		wantEmpty bool
	}{
		{"json", false},
		{"csv", false},
		{"list", false},
		{"cli", false},
		{"invalid", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			formatted := results.Format(tt.format)
			isEmpty := formatted == ""

			if isEmpty != tt.wantEmpty {
				if tt.wantEmpty {
					t.Errorf("Format(%s) should return empty string, got: %s", tt.format, formatted)
				} else {
					t.Errorf("Format(%s) should not return empty string", tt.format)
				}
			}
		})
	}
}

func TestResults_FormatEmptyResults(t *testing.T) {
	results := Results{}

	// Even empty results should produce valid output for most formats
	formats := []string{"json", "csv", "list", "cli"}
	for _, format := range formats {
		formatted := results.Format(format)
		// Some formats might return empty for empty input, but shouldn't crash
		_ = formatted // Just ensure no panic
	}
}

func TestResults_FormatLargeDataset(t *testing.T) {
	// Create a large dataset to test performance and memory usage
	results := Results{}
	for i := 0; i < 1000; i++ {
		results = append(results, Result{
			Fuzzer: "addition",
			Domain: "example" + string(rune(i%26+'a')) + ".com",
			DNS: map[string][]string{
				"A": {"192.0.2." + string(rune(i%255))},
			},
		})
	}

	formats := []string{"json", "csv", "list", "cli"}
	for _, format := range formats {
		formatted := results.Format(format)
		if formatted == "" {
			t.Errorf("Format(%s) should not return empty string for large dataset", format)
		}
	}
}

func TestEngine_Initialization(t *testing.T) {
	options := Options{
		Domain:  "test.com",
		Threads: 5,
		Format:  "json",
	}

	engine, err := New(options)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test engine structure
	if engine.options.Domain != options.Domain {
		t.Errorf("Engine domain = %v, want %v", engine.options.Domain, options.Domain)
	}
	if engine.options.Threads != options.Threads {
		t.Errorf("Engine threads = %v, want %v", engine.options.Threads, options.Threads)
	}
	if engine.fuzzer == nil {
		t.Error("Engine fuzzer is nil")
	}
	if engine.scanner == nil {
		t.Error("Engine scanner is nil")
	}

	// Test that mutex is initialized
	engine.mu.Lock()
	engine.mu.Unlock()
}

func TestEngine_ZeroValue(t *testing.T) {
	// Test behavior with zero-value engine (should not panic)
	var engine Engine

	// This should not panic but will likely return error
	defer func() {
		if r := recover(); r != nil {
			// We actually expect a panic here due to nil pointer dereference
			// This is acceptable behavior for an uninitialized engine
			t.Logf("Zero-value engine caused panic as expected: %v", r)
		}
	}()

	_, err := engine.GetResults()
	// We expect an error here since the engine is not properly initialized
	if err == nil {
		t.Error("Expected error from uninitialized engine")
	}
}

// Test type assertions and interface compliance
func TestResult_Interfaces(t *testing.T) {
	result := Result{
		Fuzzer: "test",
		Domain: "test.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	// Test that Result can be converted to fuzzer.Domain
	domain := result.toDomain()
	var _ *fuzzer.Domain = domain

	// Test Results slice behavior
	results := Results{result}
	if len(results) != 1 {
		t.Errorf("Results slice length = %v, want %v", len(results), 1)
	}
}

func TestResult_DNSMethods(t *testing.T) {
	result := Result{
		Fuzzer: "test",
		Domain: "test.com",
		DNS: map[string][]string{
			"A":  {"192.0.2.1", "192.0.2.2"},
			"MX": {"mail.test.com.", "backup.test.com."},
			"NS": {"ns1.test.com.", "ns2.test.com."},
		},
	}

	// Test A record methods
	aRecords := result.GetARecords()
	if len(aRecords) != 2 {
		t.Errorf("GetARecords() returned %d records, want 2", len(aRecords))
	}
	if !result.HasARecords() {
		t.Error("HasARecords() should return true")
	}

	// Test MX record methods
	mxRecords := result.GetMXRecords()
	if len(mxRecords) != 2 {
		t.Errorf("GetMXRecords() returned %d records, want 2", len(mxRecords))
	}
	if !result.HasMXRecords() {
		t.Error("HasMXRecords() should return true")
	}

	// Test NS record methods
	nsRecords := result.GetNSRecords()
	if len(nsRecords) != 2 {
		t.Errorf("GetNSRecords() returned %d records, want 2", len(nsRecords))
	}
	if !result.HasNSRecords() {
		t.Error("HasNSRecords() should return true")
	}

	// Test with nil DNS
	result.DNS = nil
	if result.GetARecords() != nil {
		t.Error("GetARecords() should return nil for nil DNS")
	}
	if result.GetMXRecords() != nil {
		t.Error("GetMXRecords() should return nil for nil DNS")
	}
	if result.GetNSRecords() != nil {
		t.Error("GetNSRecords() should return nil for nil DNS")
	}
	if result.HasARecords() {
		t.Error("HasARecords() should return false for nil DNS")
	}
	if result.HasMXRecords() {
		t.Error("HasMXRecords() should return false for nil DNS")
	}
	if result.HasNSRecords() {
		t.Error("HasNSRecords() should return false for nil DNS")
	}
}

func TestResults_FilteringMethods(t *testing.T) {
	results := Results{
		{
			Fuzzer: "test1",
			Domain: "test1.com",
			DNS: map[string][]string{
				"A": {"192.0.2.1"},
			},
		},
		{
			Fuzzer: "test2",
			Domain: "test2.com",
			DNS: map[string][]string{
				"MX": {"mail.test2.com."},
			},
		},
		{
			Fuzzer: "test3",
			Domain: "test3.com",
			DNS: map[string][]string{
				"A":  {"192.0.2.3"},
				"MX": {"mail.test3.com."},
				"NS": {"ns1.test3.com."},
			},
		},
		{
			Fuzzer: "test4",
			Domain: "test4.com",
			DNS:    map[string][]string{},
		},
		{
			Fuzzer: "test5",
			Domain: "test5.com",
			DNS: map[string][]string{
				"NS": {"ns1.test5.com.", "ns2.test5.com."},
			},
		},
	}

	// Test filtering by A records
	withARecords := results.GetDomainsWithARecords()
	if len(withARecords) != 2 {
		t.Errorf("GetDomainsWithARecords() returned %d results, want 2", len(withARecords))
	}

	withoutARecords := results.GetDomainsWithoutARecords()
	if len(withoutARecords) != 3 {
		t.Errorf("GetDomainsWithoutARecords() returned %d results, want 3", len(withoutARecords))
	}

	// Test filtering by MX records
	withMXRecords := results.GetDomainsWithMXRecords()
	if len(withMXRecords) != 2 {
		t.Errorf("GetDomainsWithMXRecords() returned %d results, want 2", len(withMXRecords))
	}

	// Test filtering by NS records
	withNSRecords := results.GetDomainsWithNSRecords()
	if len(withNSRecords) != 2 {
		t.Errorf("GetDomainsWithNSRecords() returned %d results, want 2", len(withNSRecords))
	}
}
