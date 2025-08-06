package formatter

import (
	"testing"

	"github.com/ducksify/godnstwist/internal/fuzzer"
)

func TestNewFormatter(t *testing.T) {
	domains := []*fuzzer.Domain{
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
			Whois: map[string]string{
				"registrar": "ICANN",
			},
			LSH: map[string]int{
				"ssdeep": 100,
			},
			PHash: 100,
		},
	}

	f := NewFormatter(domains)
	if f == nil {
		t.Fatal("NewFormatter() returned nil")
	}

	if len(f.domains) != len(domains) {
		t.Error("NewFormatter() did not set domains correctly")
	}
}

func TestFormatter_Format(t *testing.T) {
	domains := []*fuzzer.Domain{
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
			Whois: map[string]string{
				"registrar": "ICANN",
			},
			LSH: map[string]int{
				"ssdeep": 100,
			},
			PHash: 100,
		},
	}

	f := NewFormatter(domains)
	if f == nil {
		t.Fatal("Failed to create formatter")
	}

	// Test JSON format
	jsonOutput := f.Format("json")
	if jsonOutput == "" {
		t.Error("Format() returned empty string for JSON format")
	}

	// Test CSV format
	csvOutput := f.Format("csv")
	if csvOutput == "" {
		t.Error("Format() returned empty string for CSV format")
	}

	// Test list format
	listOutput := f.Format("list")
	if listOutput == "" {
		t.Error("Format() returned empty string for list format")
	}

	// Test CLI format
	cliOutput := f.Format("cli")
	if cliOutput == "" {
		t.Error("Format() returned empty string for CLI format")
	}

	// Test invalid format
	invalidOutput := f.Format("invalid")
	if invalidOutput != "" {
		t.Error("Format() returned non-empty string for invalid format")
	}
}

func TestFormatter_JSON(t *testing.T) {
	domains := []*fuzzer.Domain{
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
			Whois: map[string]string{
				"registrar": "ICANN",
			},
			LSH: map[string]int{
				"ssdeep": 100,
			},
			PHash: 100,
		},
	}

	f := NewFormatter(domains)
	if f == nil {
		t.Fatal("Failed to create formatter")
	}

	output := f.json()
	if output == "" {
		t.Error("JSON() returned empty string")
	}
}

func TestFormatter_CSV(t *testing.T) {
	domains := []*fuzzer.Domain{
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
			Whois: map[string]string{
				"registrar": "ICANN",
			},
			LSH: map[string]int{
				"ssdeep": 100,
			},
			PHash: 100,
		},
	}

	f := NewFormatter(domains)
	if f == nil {
		t.Fatal("Failed to create formatter")
	}

	output := f.csv()
	if output == "" {
		t.Error("CSV() returned empty string")
	}
}

func TestFormatter_List(t *testing.T) {
	domains := []*fuzzer.Domain{
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
			Whois: map[string]string{
				"registrar": "ICANN",
			},
			LSH: map[string]int{
				"ssdeep": 100,
			},
			PHash: 100,
		},
	}

	f := NewFormatter(domains)
	if f == nil {
		t.Fatal("Failed to create formatter")
	}

	output := f.list()
	if output == "" {
		t.Error("List() returned empty string")
	}
}

func TestFormatter_CLI(t *testing.T) {
	domains := []*fuzzer.Domain{
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
			Whois: map[string]string{
				"registrar": "ICANN",
			},
			LSH: map[string]int{
				"ssdeep": 100,
			},
			PHash: 100,
		},
	}

	f := NewFormatter(domains)
	if f == nil {
		t.Fatal("Failed to create formatter")
	}

	output := f.cli()
	if output == "" {
		t.Error("CLI() returned empty string")
	}
}
