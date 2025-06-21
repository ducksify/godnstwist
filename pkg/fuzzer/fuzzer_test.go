package fuzzer

import (
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
