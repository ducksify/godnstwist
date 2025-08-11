# GoDNSTwist

A Go library for domain name permutation and DNS analysis, useful for detecting typosquatting, phishing domains, and corporate espionage attempts.

## Features

- **Domain Permutation**: Generate variations of a domain using multiple fuzzing algorithms
- **DNS Analysis**: Check DNS records, GeoIP location, and domain registration status
- **Multiple Output Formats**: Support for JSON, CSV, CLI table, and plain list formats
- **Concurrent Processing**: Multi-threaded scanning for improved performance
- **Banner Detection**: HTTP and SMTP service banner grabbing
- **Visual Similarity**: Web page visual comparison using perceptual hashing
- **Filtering Options**: Show only registered or unregistered domains

## Installation

```bash
go get github.com/ducksify/godnstwist
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/ducksify/godnstwist/pkg/dnstwist"
)

func main() {
    // Configure options
    options := dnstwist.Options{
        Domain:  "example.com",
        Threads: 10,
        Format:  "json",
    }

    // Create engine
    engine, err := dnstwist.New(options)
    if err != nil {
        log.Fatal(err)
    }

    // Get results
    results, err := engine.GetResults()
    if err != nil {
        log.Fatal(err)
    }

    // Format and display
    output := results.Format("cli")
    fmt.Print(output)
}
```

## Configuration Options

The `dnstwist.Options` struct provides comprehensive configuration:

```go
type Options struct {
    // Required
    Domain  string // Target domain to analyze
    Threads int    // Number of concurrent threads (must be > 0)

    // Output options
    Format string // Output format: "cli", "csv", "json", "list"
    Output string // Save output to file (optional)

    // Fuzzing options
    Fuzzers    string // Comma-separated fuzzing algorithms
    Dictionary string // Dictionary file for additional permutations
    TLD        string // TLD list file for domain swapping

    // DNS and network options
    Nameservers string // Custom DNS servers (comma-separated)
    UserAgent   string // Custom User-Agent string
    All         bool   // Show all DNS records instead of first ones

    // Analysis features
    Banners     bool   // Determine HTTP and SMTP service banners
    GeoIP       bool   // Perform GeoIP location lookup
    MXCheck     bool   // Check MX records for email interception
    Whois       bool   // Look up WHOIS information
    PHash       bool   // Evaluate visual similarity of web pages
    LSH         string // LSH algorithm for page similarity ("ssdeep", "tlsh")
    Screenshots string // Directory to save web page screenshots

    // Filtering options
    Registered   bool // Show only registered domains
    Unregistered bool // Show only unregistered domains

    // Advanced options
    LSHURL   string // Override URL for original page comparison
    PHashURL string // Override URL for visual comparison
}
```

## Usage Examples

### Basic Domain Analysis

```go
package main

import (
    "fmt"
    "log"

    "github.com/ducksify/godnstwist/pkg/dnstwist"
)

func main() {
    options := dnstwist.Options{
        Domain:  "github.com",
        Threads: 5,
        Format:  "cli",
    }

    engine, err := dnstwist.New(options)
    if err != nil {
        log.Fatal(err)
    }

    results, err := engine.GetResults()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d domain variations\n", len(results))
    fmt.Print(results.Format("cli"))
}
```

### Advanced Analysis with Multiple Features

```go
package main

import (
    "fmt"
    "log"

    "github.com/ducksify/godnstwist/pkg/dnstwist"
)

func main() {
    options := dnstwist.Options{
        Domain:      "example.com",
        Threads:     10,
        Format:      "json",
        Fuzzers:     "addition,omission,transposition,bitsquatting",
        Banners:     true,
        GeoIP:       true,
        MXCheck:     true,
        Whois:       true,
        Nameservers: "8.8.8.8:53,1.1.1.1:53",
        UserAgent:   "Mozilla/5.0 Custom Bot",
    }

    engine, err := dnstwist.New(options)
    if err != nil {
        log.Fatal(err)
    }

    results, err := engine.GetResults()
    if err != nil {
        log.Fatal(err)
    }

    // Process results
    for _, result := range results {
        fmt.Printf("Domain: %s (Fuzzer: %s)\n", result.Domain, result.Fuzzer)
        
        if len(result.DNS["A"]) > 0 {
            fmt.Printf("  IP: %s\n", result.DNS["A"][0])
        }
        
        if result.GeoIP != "" {
            fmt.Printf("  Location: %s\n", result.GeoIP)
        }
        
        if result.Banner["http"] != "" {
            fmt.Printf("  HTTP Banner: %s\n", result.Banner["http"])
        }
    }
}
```

### Filter for Registered Domains Only

```go
package main

import (
    "fmt"
    "log"

    "github.com/ducksify/godnstwist/pkg/dnstwist"
)

func main() {
    options := dnstwist.Options{
        Domain:     "google.com",
        Threads:    8,
        Registered: true, // Only show domains with DNS A records
        Fuzzers:    "addition,omission,hyphenation",
        GeoIP:      true,
    }

    engine, err := dnstwist.New(options)
    if err != nil {
        log.Fatal(err)
    }

    results, err := engine.GetResults()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d registered domain variations:\n", len(results))
    
    for _, result := range results {
        fmt.Printf("- %s (%s) - %s\n", 
            result.Domain, 
            result.DNS["A"][0], 
            result.GeoIP)
    }
}
```

### Export Results in Different Formats

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/ducksify/godnstwist/pkg/dnstwist"
)

func main() {
    options := dnstwist.Options{
        Domain:  "example.org",
        Threads: 4,
        Fuzzers: "addition,transposition",
    }

    engine, err := dnstwist.New(options)
    if err != nil {
        log.Fatal(err)
    }

    results, err := engine.GetResults()
    if err != nil {
        log.Fatal(err)
    }

    // Save as JSON
    jsonOutput := results.Format("json")
    err = os.WriteFile("results.json", []byte(jsonOutput), 0644)
    if err != nil {
        log.Fatal(err)
    }

    // Save as CSV
    csvOutput := results.Format("csv")
    err = os.WriteFile("results.csv", []byte(csvOutput), 0644)
    if err != nil {
        log.Fatal(err)
    }

    // Display as CLI table
    fmt.Print(results.Format("cli"))
}
```

### Error Handling and Validation

```go
package main

import (
    "fmt"
    "log"

    "github.com/ducksify/godnstwist/pkg/dnstwist"
)

func main() {
    options := dnstwist.Options{
        Domain:  "invalid-domain", // This will cause an error
        Threads: 1,
    }

    engine, err := dnstwist.New(options)
    if err != nil {
        fmt.Printf("Engine creation failed: %v\n", err)
        return
    }

    results, err := engine.GetResults()
    if err != nil {
        fmt.Printf("Analysis failed: %v\n", err)
        return
    }

    fmt.Printf("Analysis completed successfully with %d results\n", len(results))
}
```

## Fuzzing Algorithms

Available fuzzing algorithms (use with `Fuzzers` option):

- **addition**: Add characters to the domain
- **bitsquatting**: Flip bits in domain characters
- **homoglyph**: Replace characters with similar-looking ones
- **hyphenation**: Add hyphens between characters
- **insertion**: Insert characters between existing ones
- **omission**: Remove characters from the domain
- **repetition**: Repeat characters in the domain
- **replacement**: Replace characters with keyboard-adjacent ones
- **subdomain**: Split domain into subdomains
- **transposition**: Swap adjacent characters
- **vowel-swap**: Replace vowels with other vowels
- **tld-swap**: Swap the TLD with entries from a dictionary file

Example:

```go
options.Fuzzers = "addition,omission,transposition,bitsquatting,tld-swap"
```

### TLD-Swap Usage

The `tld-swap` fuzzer requires a TLD dictionary file. You can specify a custom file using the `TLD` option:

```go
options := dnstwist.Options{
    Domain:  "example.com",
    Fuzzers: "tld-swap",
    TLD:     "dictionaries/abused_tlds.dict", // Custom TLD file
    Threads: 10,
}
```

If no TLD file is specified, the fuzzer will use `dictionaries/common_tlds.dict` by default. If that file doesn't exist, it will fall back to a basic set of common TLDs.

The TLD dictionary file should contain one TLD per line, with comments starting with `//`:

```
// Common TLDs
com
net
org
edu
gov
// Add more TLDs here
```

## Output Formats

### CLI Format (Human-readable table)
```
original    example.com          93.184.216.34 /United States
addition    examplea.com         -
addition    exampleb.com         -
omission    exampl.com           192.0.2.1
```

### JSON Format

```json
[
  {
    "fuzzer": "original",
    "domain": "example.com",
    "dns": {
      "A": ["93.184.216.34"]
    },
    "geoip": "United States"
  }
]
```

### CSV Format

```csv
fuzzer,domain
original,example.com
addition,examplea.com
```

### List Format

```text
example.com
examplea.com
exampleb.com
```

## Result Structure

Each domain analysis returns a `Result` struct:

```go
type Result struct {
    Fuzzer string              // Fuzzing algorithm used
    Domain string              // Generated domain name
    DNS    map[string][]string // DNS records (A, AAAA, MX, etc.)
    GeoIP  string              // Geographic location
    Banner map[string]string   // Service banners (http, smtp)
    Whois  map[string]string   // WHOIS information
    LSH    map[string]int      // LSH similarity scores
    PHash  int                 // Perceptual hash for visual similarity
}

// Convenience methods for accessing DNS records:
func (r *Result) GetARecords() []string      // Returns A records
func (r *Result) GetMXRecords() []string     // Returns MX records
func (r *Result) GetNSRecords() []string     // Returns NS records
func (r *Result) HasARecords() bool          // Returns true if domain has A records
func (r *Result) HasMXRecords() bool         // Returns true if domain has MX records
func (r *Result) HasNSRecords() bool         // Returns true if domain has NS records

// Results filtering methods:
func (r Results) GetDomainsWithARecords() Results      // Returns only registered domains
func (r Results) GetDomainsWithoutARecords() Results   // Returns only unregistered domains
func (r Results) GetDomainsWithMXRecords() Results     // Returns domains with MX records
func (r Results) GetDomainsWithNSRecords() Results     // Returns domains with NS records
```

## Performance Tuning

- **Threads**: Increase for faster scanning (default: 10)
- **Fuzzers**: Limit algorithms to reduce permutations
- **Filtering**: Use `Registered`/`Unregistered` to reduce DNS queries
- **Custom DNS**: Use fast DNS servers with `Nameservers`

```go
options := dnstwist.Options{
    Domain:      "example.com",
    Threads:     20,                    // More threads
    Fuzzers:     "addition,omission",   // Fewer algorithms
    Registered:  true,                  // Filter early
    Nameservers: "1.1.1.1:53",        // Fast DNS
}
```

## Requirements

- Go 1.19 or later
- Internet connection for DNS queries and external services
- Optional: GeoIP database file for location lookup

## License

This project is licensed under the terms specified in the LICENSE file.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Command Line Tool

This library powers the `dnstwist` command-line tool. Install it with:

```bash
go install github.com/ducksify/godnstwist/cmd/dnstwist@latest
```

Use the CLI tool:
```bash
# Basic usage
dnstwist -d example.com

# Check for MX and NS records
dnstwist -d example.com --mxcheck --nscheck

# Advanced usage with multiple features
dnstwist -d example.com -f json -t 10 --banners --geoip
```

### Working with Results

Access DNS records and filter results:

```go
package main

import (
    "fmt"
    "log"

    "github.com/ducksify/godnstwist/pkg/dnstwist"
)

func main() {
    options := dnstwist.Options{
        Domain:  "example.com",
        Threads: 5,
        Fuzzers: "addition,omission",
    }

    engine, err := dnstwist.New(options)
    if err != nil {
        log.Fatal(err)
    }

    results, err := engine.GetResults()
    if err != nil {
        log.Fatal(err)
    }

    // Access individual results
    for _, result := range results {
        fmt.Printf("Domain: %s\n", result.Domain)
        
        // Get A records
        if aRecords := result.GetARecords(); len(aRecords) > 0 {
            fmt.Printf("  A Records: %v\n", aRecords)
        }
        
        // Get MX records
        if mxRecords := result.GetMXRecords(); len(mxRecords) > 0 {
            fmt.Printf("  MX Records: %v\n", mxRecords)
        }
        
        // Get NS records
        if nsRecords := result.GetNSRecords(); len(nsRecords) > 0 {
            fmt.Printf("  NS Records: %v\n", nsRecords)
        }
        
        // Check if domain is registered
        if result.HasARecords() {
            fmt.Printf("  Status: Registered\n")
        } else {
            fmt.Printf("  Status: Unregistered\n")
        }
    }

    // Filter results
    registered := results.GetDomainsWithARecords()
    unregistered := results.GetDomainsWithoutARecords()
    withMX := results.GetDomainsWithMXRecords()
    withNS := results.GetDomainsWithNSRecords()

    fmt.Printf("\nSummary:\n")
    fmt.Printf("  Total domains: %d\n", len(results))
    fmt.Printf("  Registered: %d\n", len(registered))
    fmt.Printf("  Unregistered: %d\n", len(unregistered))
    fmt.Printf("  With MX records: %d\n", len(withMX))
    fmt.Printf("  With NS records: %d\n", len(withNS))
}
```

### Advanced Result Processing

```go
package main

import (
    "fmt"
    "log"

    "github.com/ducksify/godnstwist/pkg/dnstwist"
)

func main() {
    options := dnstwist.Options{
        Domain:      "example.com",
        Threads:     10,
        Format:      "json",
        Fuzzers:     "addition,omission,transposition,bitsquatting",
        Banners:     true,
        GeoIP:       true,
        MXCheck:     true,
        NSCheck:     true,
        Whois:       true,
        Nameservers: "8.8.8.8:53,1.1.1.1:53",
        UserAgent:   "Mozilla/5.0 Custom Bot",
    }

    engine, err := dnstwist.New(options)
    if err != nil {
        log.Fatal(err)
    }

    results, err := engine.GetResults()
    if err != nil {
        log.Fatal(err)
    }

    // Process results
    for _, result := range results {
        fmt.Printf("Domain: %s (Fuzzer: %s)\n", result.Domain, result.Fuzzer)
        
        if len(result.DNS["A"]) > 0 {
            fmt.Printf("  IP: %s\n", result.DNS["A"][0])
        }
        
        if result.GeoIP != "" {
            fmt.Printf("  Location: %s\n", result.GeoIP)
        }
        
        if result.Banner["http"] != "" {
            fmt.Printf("  HTTP Banner: %s\n", result.Banner["http"])
        }
    }
}
```
