package formatter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ducksify/godnstwist/internal/fuzzer"
)

type Formatter struct {
	domains []*fuzzer.Domain
}

func NewFormatter(domains []*fuzzer.Domain) *Formatter {
	return &Formatter{
		domains: domains,
	}
}

func (f *Formatter) Format(format string) string {
	switch format {
	case "json":
		return f.json()
	case "csv":
		return f.csv()
	case "list":
		return f.list()
	case "cli":
		return f.cli()
	default:
		return ""
	}
}

func (f *Formatter) json() string {
	data, err := json.MarshalIndent(f.domains, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

func (f *Formatter) csv() string {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"fuzzer", "domain"}
	writer.Write(header)

	// Write data
	for _, domain := range f.domains {
		record := []string{
			domain.Fuzzer,
			domain.Domain,
		}
		writer.Write(record)
	}

	writer.Flush()
	return buf.String()
}

func (f *Formatter) list() string {
	var buf strings.Builder
	for _, domain := range f.domains {
		buf.WriteString(domain.Domain)
		buf.WriteString("\n")
	}
	return buf.String()
}

func (f *Formatter) cli() string {
	var buf strings.Builder

	// Find max lengths for alignment
	maxFuzzer := 0
	maxDomain := 0
	for _, domain := range f.domains {
		if len(domain.Fuzzer) > maxFuzzer {
			maxFuzzer = len(domain.Fuzzer)
		}
		if len(domain.Domain) > maxDomain {
			maxDomain = len(domain.Domain)
		}
	}

	// Format each domain
	for _, domain := range f.domains {
		// Format fuzzer and domain
		buf.WriteString(fmt.Sprintf("%-*s %-*s", maxFuzzer+1, domain.Fuzzer, maxDomain+1, domain.Domain))

		// Format additional information
		var info []string

		// DNS A records
		if a := domain.DNS["A"]; len(a) > 0 {
			info = append(info, strings.Join(a, ";"))
		}

		// GeoIP
		if domain.GeoIP != "" {
			info = append(info, fmt.Sprintf("/%s", domain.GeoIP))
		}

		// HTTP banner
		if banner := domain.Banner["http"]; banner != "" {
			info = append(info, fmt.Sprintf("HTTP:%s", banner))
		}

		// SMTP banner
		if banner := domain.Banner["smtp"]; banner != "" {
			info = append(info, fmt.Sprintf("SMTP:%s", banner))
		}

		// Add info or dash if no info
		if len(info) > 0 {
			buf.WriteString(strings.Join(info, " "))
		} else {
			buf.WriteString("-")
		}
		buf.WriteString("\n")
	}

	return buf.String()
}
