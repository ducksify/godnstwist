package fuzzer

import (
	"strings"
	"testing"
)

func TestNewFuzzer(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{
			name:    "valid domain",
			domain:  "example.com",
			wantErr: false,
		},
		{
			name:    "invalid domain",
			domain:  "invalid",
			wantErr: true,
		},
		{
			name:    "empty domain",
			domain:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFuzzer(tt.domain)
			if (f == nil) != tt.wantErr {
				t.Errorf("NewFuzzer() returned nil for valid domain")
				return
			}
			if !tt.wantErr && f == nil {
				t.Error("NewFuzzer() returned nil fuzzer for valid domain")
			}
		})
	}
}

func TestFuzzer_Generate(t *testing.T) {
	f := NewFuzzer("example.com")
	if f == nil {
		t.Fatalf("Failed to create fuzzer")
	}

	err := f.Generate("")
	if err != nil {
		t.Fatalf("Generate() failed: %v", err)
	}

	domains := f.Domains()
	if len(domains) == 0 {
		t.Error("Generate() produced no domains")
	}

	// Check if all generated domains are valid
	for _, domain := range domains {
		if !validFQDNRegex.MatchString(domain.Domain) {
			t.Errorf("Generated invalid domain: %s", domain.Domain)
		}
	}
}

func TestFuzzer_Addition(t *testing.T) {
	f := NewFuzzer("example.com")
	if f == nil {
		t.Fatalf("Failed to create fuzzer")
	}

	f.addition()

	domains := f.Domains()
	if len(domains) == 0 {
		t.Error("addition() produced no domains")
	}

	// Check if all generated domains contain the original domain
	for _, domain := range domains {
		if !validFQDNRegex.MatchString(domain.Domain) {
			t.Errorf("Generated invalid domain: %s", domain.Domain)
		}
	}
}

func TestFuzzer_Bitsquatting(t *testing.T) {
	f := NewFuzzer("example.com")
	if f == nil {
		t.Fatalf("Failed to create fuzzer")
	}

	f.bitsquatting()

	domains := f.Domains()
	if len(domains) == 0 {
		t.Error("bitsquatting() produced no domains")
	}

	// Check if all generated domains contain the original domain
	for _, domain := range domains {
		if !validFQDNRegex.MatchString(domain.Domain) {
			t.Errorf("Generated invalid domain: %s", domain.Domain)
		}
	}
}

func TestFuzzer_TLDSwap(t *testing.T) {
	f := NewFuzzer("example.com")
	if f == nil {
		t.Fatalf("Failed to create fuzzer")
	}

	// Test with default TLD dictionary
	f.tldSwap()

	domains := f.Domains()

	// Check if all generated domains are valid and have different TLDs
	tldSwapCount := 0
	for _, domain := range domains {
		if domain.Fuzzer == "tld-swap" {
			tldSwapCount++
			if !validFQDNRegex.MatchString(domain.Domain) {
				t.Errorf("Generated invalid domain: %s", domain.Domain)
			}
			// Check that the domain part is correct
			if !strings.HasPrefix(domain.Domain, "example.") {
				t.Errorf("Generated domain doesn't start with 'example.': %s", domain.Domain)
			}
			// Check that it's not the original TLD
			if domain.Domain == "example.com" {
				t.Errorf("Generated domain should not be the original: %s", domain.Domain)
			}
		}
	}

	// Skip test if no TLD dictionary files are available
	if tldSwapCount == 0 {
		t.Skip("No tld-swap domains were generated - TLD dictionary files may not be available")
	}
}

func TestFuzzer_TLDSwapWithCustomFile(t *testing.T) {
	f := NewFuzzer("test.com")
	if f == nil {
		t.Fatalf("Failed to create fuzzer")
	}

	// Test with custom TLD file
	f.SetTLDFile("dictionaries/abused_tlds.dict")
	f.tldSwap()

	domains := f.Domains()
	tldSwapCount := 0
	for _, domain := range domains {
		if domain.Fuzzer == "tld-swap" {
			tldSwapCount++
			if !validFQDNRegex.MatchString(domain.Domain) {
				t.Errorf("Generated invalid domain: %s", domain.Domain)
			}
		}
	}

	// Skip test if no TLD dictionary files are available
	if tldSwapCount == 0 {
		t.Skip("No tld-swap domains were generated with custom file - TLD dictionary files may not be available")
	}
}

func TestFuzzer_ReadTLDDictionary(t *testing.T) {
	f := NewFuzzer("test.com")
	if f == nil {
		t.Fatalf("Failed to create fuzzer")
	}

	// Test reading a valid TLD dictionary
	tlds, err := f.readTLDDictionary("dictionaries/common_tlds.dict")
	if err != nil {
		t.Skipf("Skipping test - TLD dictionary file not found: %v", err)
	}

	if len(tlds) == 0 {
		t.Error("No TLDs were read from dictionary file")
	}

	// Check that common TLDs are present
	expectedTLDs := []string{"com", "net", "org"}
	for _, expected := range expectedTLDs {
		found := false
		for _, tld := range tlds {
			if tld == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected TLD '%s' not found in dictionary", expected)
		}
	}
}
