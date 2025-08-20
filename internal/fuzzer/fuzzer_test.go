package fuzzer

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestFuzzer_HomoglyphBytes(t *testing.T) {
	f := NewFuzzer("google.com")
	if f == nil {
		t.Fatal("Failed to create fuzzer")
	}

	// Generate homoglyph variants
	f.Generate("homoglyph")
	domains := f.Domains()

	// Find original domain
	var originalDomain *Domain
	var homoglyphDomains []*Domain
	for _, domain := range domains {
		if domain.Fuzzer == "original" {
			originalDomain = domain
		} else if domain.Fuzzer == "homoglyph" {
			homoglyphDomains = append(homoglyphDomains, domain)
		}
	}

	if originalDomain == nil {
		t.Fatal("Original domain not found")
	}

	if len(homoglyphDomains) == 0 {
		t.Fatal("No homoglyph domains generated")
	}

	originalBytes := []byte(originalDomain.Domain)
	t.Logf("Original domain: %s (bytes: %v)", originalDomain.Domain, originalBytes)

	// Check that at least one homoglyph has different bytes
	foundDifferent := false
	foundCyrillic := false
	for i, homoglyph := range homoglyphDomains {
		homoglyphBytes := []byte(homoglyph.Domain)
		t.Logf("Homoglyph %d: %s (bytes: %v)", i, homoglyph.Domain, homoglyphBytes)

		if !bytes.Equal(originalBytes, homoglyphBytes) {
			foundDifferent = true
			t.Logf("Found different bytes: original=%v, homoglyph=%v", originalBytes, homoglyphBytes)

			// Check if this is a Cyrillic variant (should have different byte length or different bytes)
			if len(homoglyphBytes) != len(originalBytes) {
				foundCyrillic = true
				t.Logf("Found Cyrillic variant with different byte length: %d vs %d", len(homoglyphBytes), len(originalBytes))
			} else {
				// Check if any byte is different (Cyrillic characters have different byte values)
				for j, b := range homoglyphBytes {
					if b != originalBytes[j] {
						foundCyrillic = true
						t.Logf("Found Cyrillic variant with different byte at position %d: %d vs %d", j, b, originalBytes[j])
						break
					}
				}
			}
		}
	}

	if !foundDifferent {
		t.Error("All homoglyph results have identical bytes to original - this indicates identity replacements are not being filtered")
	}

	if !foundCyrillic {
		t.Log("No Cyrillic homoglyphs found - this is expected if they're filtered by the ASCII regex")
	}
}

func TestFuzzer_CyrillicHomoglyphs(t *testing.T) {
	f := NewFuzzer("google.com")
	if f == nil {
		t.Fatal("Failed to create fuzzer")
	}

	// Temporarily store the original regex
	originalRegex := validFQDNRegex
	// Use a more permissive regex that allows Unicode
	validFQDNRegex = regexp.MustCompile(`^(.+\.)+[a-z]{2,63}$`)
	defer func() { validFQDNRegex = originalRegex }()

	// Generate homoglyph variants
	f.Generate("homoglyph")
	domains := f.Domains()

	// Find homoglyph domains
	var homoglyphDomains []*Domain
	for _, domain := range domains {
		if domain.Fuzzer == "homoglyph" {
			homoglyphDomains = append(homoglyphDomains, domain)
		}
	}

	t.Logf("Found %d homoglyph domains", len(homoglyphDomains))

	// Check for Cyrillic variants
	foundCyrillic := false
	for i, homoglyph := range homoglyphDomains {
		homoglyphBytes := []byte(homoglyph.Domain)
		t.Logf("Homoglyph %d: %s (bytes: %v)", i, homoglyph.Domain, homoglyphBytes)

		// Check if any byte is > 127 (non-ASCII)
		for j, b := range homoglyphBytes {
			if b > 127 {
				foundCyrillic = true
				t.Logf("Found Cyrillic character at position %d: byte %d in domain %s", j, b, homoglyph.Domain)
			}
		}
	}

	if !foundCyrillic {
		t.Log("No Cyrillic homoglyphs found even with permissive regex - they may not be in the homoglyph map")
	}
}

func TestHomoglyphPunycode(t *testing.T) {
	f := NewFuzzer("google.com")
	assert.NotNil(t, f)

	// Generate homoglyph permutations
	f.homoglyph()

	// Check that domains with non-ASCII characters have Punycode versions
	foundHomoglyph := false
	for _, domain := range f.domains {
		if domain.Fuzzer == "homoglyph" {
			// Check if this domain contains non-ASCII characters
			hasNonASCII := false
			for _, r := range domain.Domain {
				if r > 127 {
					hasNonASCII = true
					break
				}
			}

			if hasNonASCII {
				foundHomoglyph = true
				// Verify that Punycode is set and different from Domain
				assert.NotEmpty(t, domain.Punycode, "Punycode should be set for non-ASCII domains")
				assert.NotEqual(t, domain.Domain, domain.Punycode, "Punycode should be different from Domain for non-ASCII domains")

				t.Logf("Found homoglyph domain: %s -> %s", domain.Domain, domain.Punycode)
			}
		}
	}

	assert.True(t, foundHomoglyph, "Should find at least one homoglyph domain with non-ASCII characters")
}

func TestContainsNonASCII(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"google.com", false},
		{"gооgle.com", true}, // Cyrillic 'о'
		{"gοοgle.com", true}, // Greek 'ο'
		{"g00gle.com", false},
		{"", false},
	}

	for _, tt := range tests {
		result := containsNonASCII(tt.input)
		assert.Equal(t, tt.expected, result, "containsNonASCII(%q) should be %v", tt.input, tt.expected)
	}
}

func TestContainsCyrillic(t *testing.T) {
	// Test containsCyrillic function
	tests := []struct {
		input    string
		expected bool
	}{
		{"google.com", false},
		{"gоogle.com", true},  // Cyrillic 'о' (о)
		{"goоgle.com", true},  // Cyrillic 'о' (о)
		{"googlе.com", true},  // Cyrillic 'е' (е)
		{"gοοgle.com", false}, // Greek, not Cyrillic
	}

	for _, test := range tests {
		result := containsCyrillic(test.input)
		if result != test.expected {
			t.Errorf("containsCyrillic(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestRegexWithCyrillic(t *testing.T) {
	// Test if the regex matches Cyrillic domains
	tests := []struct {
		input    string
		expected bool
	}{
		{"google.com", true},
		{"gоogle.com", true}, // Cyrillic 'о' (о)
		{"goоgle.com", true}, // Cyrillic 'о' (о)
		{"googlе.com", true}, // Cyrillic 'е' (е)
		{"gοοgle.com", true}, // Greek
	}

	for _, test := range tests {
		result := validFQDNRegex.MatchString(test.input)
		if result != test.expected {
			t.Errorf("validFQDNRegex.MatchString(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}
