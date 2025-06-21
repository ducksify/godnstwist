# dnstwist

A domain name permutation engine for detecting typo squatting, phishing and corporate espionage. Written in Go.

[![Go Report Card](https://goreportcard.com/badge/github.com/ducksify/godnstwist)](https://goreportcard.com/report/github.com/ducksify/godnstwist)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ducksify/godnstwist)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- **Domain Permutation Algorithms**: Multiple fuzzing algorithms to generate domain variations
- **DNS Resolution**: Check domain registration status and DNS records
- **GeoIP Lookup**: Determine geographic location of domains
- **WHOIS Information**: Retrieve domain registration details
- **HTTP Banner Detection**: Identify web server and service information
- **Visual Similarity**: Compare web page screenshots for visual similarity
- **LSH Algorithm**: Evaluate web page similarity using Locality Sensitive Hashing
- **Multiple Output Formats**: CLI, CSV, JSON, and list formats
- **Concurrent Processing**: Multi-threaded scanning for faster results
- **Custom DNS Servers**: Support for custom DNS and DoH servers

## Installation

### From Source

```bash
git clone https://github.com/ducksify/dnstwist.git
cd dnstwist
go build -o bin/dnstwist cmd/dnstwist/main.go
```

### Using Go Install

```bash
go install github.com/ducksify/dnstwist/cmd/dnstwist@latest
```

## Usage

### Basic Usage

```bash
# Analyze a domain with default settings
dnstwist -d example.com

# Show help
dnstwist --help
```

### Command Line Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--domain` | `-d` | Domain name to analyze | (required) |
| `--all` | `-a` | Print all DNS records instead of the first ones | false |
| `--banners` | `-b` | Determine HTTP and SMTP service banners | false |
| `--dictionary` | | Generate more domains using dictionary file | |
| `--format` | `-f` | Output format (cli, csv, json, list) | cli |
| `--fuzzers` | | Fuzzing algorithms to use (comma-separated) | all |
| `--geoip` | `-g` | Perform GeoIP location lookup | false |
| `--lsh` | | Evaluate web page similarity with LSH algorithm (ssdeep, tlsh) | |
| `--lshurl` | | Override URL to fetch the original web page from | |
| `--mxcheck` | `-m` | Check if MX host can be used to intercept emails | false |
| `--output` | `-o` | Save output to file | |
| `--registered` | `-r` | Show only registered domain names | false |
| `--unregistered` | `-u` | Show only unregistered domain names | false |
| `--phash` | `-p` | Render web pages and evaluate visual similarity | false |
| `--phashurl` | | Override URL to render the original web page from | |
| `--screenshots` | `-s` | Save web page screenshots into directory | |
| `--threads` | `-t` | Number of concurrent threads | 10 |
| `--whois` | `-w` | Look up WHOIS database for creation date and registrar | false |
| `--tld` | | Swap TLD for the original domain from file | |
| `--nameservers` | `-n` | DNS or DoH servers to query (comma-separated) | |
| `--useragent` | | User-Agent string | Mozilla/5.0 dnstwist |

### Fuzzing Algorithms

The following fuzzing algorithms are available:

- **addition**: Add characters to the domain
- **bitsquatting**: Flip bits in domain characters
- **homoglyph**: Replace characters with similar looking ones
- **hyphenation**: Add hyphens between characters
- **insertion**: Insert characters between existing ones
- **omission**: Remove characters
- **repetition**: Repeat characters
- **replacement**: Replace characters with similar ones
- **subdomain**: Add subdomains
- **transposition**: Swap adjacent characters
- **vowel-swap**: Swap vowels

### Examples

#### Basic Domain Analysis

```bash
# Analyze example.com with all default fuzzers
dnstwist -d example.com
```

#### Filter Results

```bash
# Show only registered domains
dnstwist -d example.com -r

# Show only unregistered domains
dnstwist -d example.com -u
```

#### Custom Fuzzing

```bash
# Use specific fuzzing algorithms
dnstwist -d example.com --fuzzers "homoglyph,transposition,addition"

# Use dictionary-based fuzzing
dnstwist -d example.com --dictionary dictionaries/english.dict
```

#### Enhanced Analysis

```bash
# Full analysis with GeoIP, WHOIS, and banners
dnstwist -d example.com -g -w -b

# Check for email interception via MX records
dnstwist -d example.com -m
```

#### Output Formats

```bash
# JSON output
dnstwist -d example.com -f json

# CSV output
dnstwist -d example.com -f csv

# List format
dnstwist -d example.com -f list

# Save to file
dnstwist -d example.com -f json -o results.json
```

#### Visual Similarity Analysis

```bash
# Compare web page screenshots
dnstwist -d example.com -p

# Save screenshots to directory
dnstwist -d example.com -p -s screenshots/

# Use LSH algorithm for similarity
dnstwist -d example.com --lsh ssdeep
```

#### Custom DNS Servers

```bash
# Use custom DNS servers
dnstwist -d example.com -n "8.8.8.8,1.1.1.1"

# Use DoH servers
dnstwist -d example.com -n "https://dns.google/dns-query,https://cloudflare-dns.com/dns-query"
```

#### Performance Tuning

```bash
# Increase thread count for faster scanning
dnstwist -d example.com -t 20

# Show all DNS records
dnstwist -d example.com -a
```

## Output Formats

### CLI Format (Default)
```
Fuzzer        Domain           DNS A                    GeoIP
original      example.com      93.184.216.34           United States
homoglyph     еxample.com      93.184.216.34           United States
transposition exmaple.com      93.184.216.34           United States
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
    "geoip": "United States",
    "banner": {
      "http": "nginx/1.19.0"
    },
    "whois": {
      "registrar": "ICANN",
      "created": "1995-08-14"
    }
  }
]
```

### CSV Format
```csv
Fuzzer,Domain,DNS A,GeoIP,Banner HTTP,Whois Registrar
original,example.com,93.184.216.34,United States,nginx/1.19.0,ICANN
homoglyph,еxample.com,93.184.216.34,United States,nginx/1.19.0,ICANN
```

## Project Structure

```
dnstwist/
├── cmd/dnstwist/          # Main application entry point
├── pkg/
│   ├── dnstwist/         # Core engine and models
│   ├── fuzzer/           # Domain permutation algorithms
│   ├── scanner/          # DNS, WHOIS, and web scanning
│   └── formatter/        # Output formatting
├── dictionaries/         # Dictionary files for fuzzing
├── bin/                  # Compiled binaries
└── Dockerfile           # Docker configuration
```

## Dependencies

- **github.com/miekg/dns**: DNS client library
- **github.com/oschwald/geoip2-golang**: GeoIP2 database reader
- **github.com/spf13/cobra**: CLI framework

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

©ducksify - fegger@ducksify.com

## Acknowledgments

This project is based on and inspired by the original [dnstwist](https://github.com/elceef/dnstwist) project by [@elceef](https://github.com/elceef). The original Python implementation pioneered domain permutation techniques for detecting typo squatting, phishing attacks, and brand impersonation.

**Original dnstwist project:**
- **Repository**: https://github.com/elceef/dnstwist
- **Author**: [@elceef](https://github.com/elceef) (Marcin Ulikowski)
- **License**: Apache-2.0
- **Website**: https://dnstwist.it

This Go implementation maintains the core functionality and algorithms from the original project while providing:
- Improved performance through Go's concurrency model
- Better deployment options with static binaries
- Enhanced test coverage and maintainability
- Modern DNS and web technologies

We extend our gratitude to the original author and contributors for their groundbreaking work in domain security analysis.
