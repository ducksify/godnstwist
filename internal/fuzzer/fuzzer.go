package fuzzer

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var validFQDNRegex = regexp.MustCompile(`^([a-z0-9-]{1,63}\.)+[a-z]{2,63}$`)

type Domain struct {
	Fuzzer string
	Domain string
	DNS    map[string][]string
	GeoIP  string
	Banner map[string]string
	Whois  map[string]string
	LSH    map[string]int
	PHash  int
}

type Fuzzer struct {
	subdomainPart string
	domain        string
	tld           string
	domains       []*Domain
	mu            sync.RWMutex
}

func NewFuzzer(domain string) *Fuzzer {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil
	}

	tld := parts[len(parts)-1]
	domainPart := parts[len(parts)-2]
	subdomain := strings.Join(parts[:len(parts)-2], ".")

	return &Fuzzer{
		subdomainPart: subdomain,
		domain:        domainPart,
		tld:           tld,
		domains:       make([]*Domain, 0),
	}
}

func (f *Fuzzer) Generate(fuzzers string) error {
	// Add original domain
	f.addDomain("original", fmt.Sprintf("%s.%s", f.domain, f.tld))

	// Parse fuzzers
	fuzzerList := strings.Split(fuzzers, ",")
	if len(fuzzerList) == 0 || fuzzers == "" {
		fuzzerList = []string{
			"addition", "bitsquatting", "homoglyph", "hyphenation",
			"insertion", "omission", "repetition", "replacement",
			"subdomain", "transposition", "vowel-swap",
		}
	}

	// Apply each fuzzer
	for _, fuzzer := range fuzzerList {
		switch fuzzer {
		case "addition":
			f.addition()
		case "bitsquatting":
			f.bitsquatting()
		case "homoglyph":
			f.homoglyph()
		case "hyphenation":
			f.hyphenation()
		case "insertion":
			f.insertion()
		case "omission":
			f.omission()
		case "repetition":
			f.repetition()
		case "replacement":
			f.replacement()
		case "subdomain":
			f.subdomain()
		case "transposition":
			f.transposition()
		case "vowel-swap":
			f.vowelSwap()
		}
	}

	return nil
}

func (f *Fuzzer) addDomain(fuzzer, domain string) {
	if !validFQDNRegex.MatchString(domain) {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.domains = append(f.domains, &Domain{
		Fuzzer: fuzzer,
		Domain: domain,
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	})
}

func (f *Fuzzer) addition() {
	// Add characters to domain
	for i := 'a'; i <= 'z'; i++ {
		f.addDomain("addition", fmt.Sprintf("%s%c.%s", f.domain, i, f.tld))
	}
	for i := '0'; i <= '9'; i++ {
		f.addDomain("addition", fmt.Sprintf("%s%c.%s", f.domain, i, f.tld))
	}
}

func (f *Fuzzer) bitsquatting() {
	// Flip bits in domain characters
	for i := 0; i < len(f.domain); i++ {
		for bit := 0; bit < 8; bit++ {
			c := f.domain[i]
			flipped := c ^ (1 << bit)
			if flipped >= 'a' && flipped <= 'z' || flipped >= '0' && flipped <= '9' || flipped == '-' {
				newDomain := f.domain[:i] + string(flipped) + f.domain[i+1:]
				f.addDomain("bitsquatting", fmt.Sprintf("%s.%s", newDomain, f.tld))
			}
		}
	}
}

func (f *Fuzzer) homoglyph() {
	// Replace characters with similar looking ones
	homoglyphs := map[rune][]rune{
		'a': {'а', 'α', 'а'},
		'b': {'ь', 'в'},
		'c': {'с', 'ç'},
		'd': {'ԁ', 'd'},
		'e': {'е', 'е'},
		'g': {'ɡ', 'g'},
		'h': {'һ', 'h'},
		'i': {'і', 'i'},
		'j': {'ј', 'j'},
		'k': {'к', 'k'},
		'l': {'ӏ', 'l'},
		'm': {'м', 'm'},
		'n': {'п', 'n'},
		'o': {'о', 'ο'},
		'p': {'р', 'p'},
		'q': {'ԛ', 'q'},
		's': {'ѕ', 's'},
		't': {'т', 't'},
		'u': {'υ', 'u'},
		'v': {'ѵ', 'v'},
		'w': {'ԝ', 'w'},
		'x': {'х', 'x'},
		'y': {'у', 'y'},
		'z': {'z', 'z'},
	}

	for i, c := range f.domain {
		if replacements, ok := homoglyphs[c]; ok {
			for _, r := range replacements {
				newDomain := f.domain[:i] + string(r) + f.domain[i+1:]
				f.addDomain("homoglyph", fmt.Sprintf("%s.%s", newDomain, f.tld))
			}
		}
	}
}

func (f *Fuzzer) hyphenation() {
	// Add hyphens between characters
	for i := 1; i < len(f.domain); i++ {
		newDomain := f.domain[:i] + "-" + f.domain[i:]
		f.addDomain("hyphenation", fmt.Sprintf("%s.%s", newDomain, f.tld))
	}
}

func (f *Fuzzer) insertion() {
	// Insert characters between existing ones
	for i := 0; i < len(f.domain); i++ {
		for c := 'a'; c <= 'z'; c++ {
			newDomain := f.domain[:i] + string(c) + f.domain[i:]
			f.addDomain("insertion", fmt.Sprintf("%s.%s", newDomain, f.tld))
		}
		for c := '0'; c <= '9'; c++ {
			newDomain := f.domain[:i] + string(c) + f.domain[i:]
			f.addDomain("insertion", fmt.Sprintf("%s.%s", newDomain, f.tld))
		}
	}
}

func (f *Fuzzer) omission() {
	// Remove characters
	for i := 0; i < len(f.domain); i++ {
		newDomain := f.domain[:i] + f.domain[i+1:]
		f.addDomain("omission", fmt.Sprintf("%s.%s", newDomain, f.tld))
	}
}

func (f *Fuzzer) repetition() {
	// Repeat characters
	for i := 0; i < len(f.domain); i++ {
		newDomain := f.domain[:i] + string(f.domain[i]) + f.domain[i:]
		f.addDomain("repetition", fmt.Sprintf("%s.%s", newDomain, f.tld))
	}
}

func (f *Fuzzer) replacement() {
	// Replace characters with adjacent keyboard keys
	keyboard := map[rune]string{
		'a': "qwsz",
		'b': "vghn",
		'c': "xdfv",
		'd': "serfcx",
		'e': "wrsd",
		'f': "drtgvc",
		'g': "ftyhbv",
		'h': "gyujnb",
		'i': "ujko",
		'j': "huikmn",
		'k': "jiolm",
		'l': "kop",
		'm': "njk",
		'n': "bhjm",
		'o': "iklp",
		'p': "ol",
		'q': "wa",
		'r': "edft",
		's': "awedxz",
		't': "rfgy",
		'u': "yhji",
		'v': "cfgb",
		'w': "qase",
		'x': "zsdc",
		'y': "tghu",
		'z': "asx",
	}

	for i, c := range f.domain {
		if replacements, ok := keyboard[c]; ok {
			for _, r := range replacements {
				newDomain := f.domain[:i] + string(r) + f.domain[i+1:]
				f.addDomain("replacement", fmt.Sprintf("%s.%s", newDomain, f.tld))
			}
		}
	}
}

func (f *Fuzzer) subdomain() {
	// Add subdomains
	for i := 1; i < len(f.domain)-1; i++ {
		if f.domain[i] != '-' && f.domain[i-1] != '-' {
			newDomain := f.domain[:i] + "." + f.domain[i:]
			f.addDomain("subdomain", fmt.Sprintf("%s.%s", newDomain, f.tld))
		}
	}
}

func (f *Fuzzer) transposition() {
	// Swap adjacent characters
	for i := 0; i < len(f.domain)-1; i++ {
		newDomain := f.domain[:i] + string(f.domain[i+1]) + string(f.domain[i]) + f.domain[i+2:]
		f.addDomain("transposition", fmt.Sprintf("%s.%s", newDomain, f.tld))
	}
}

func (f *Fuzzer) vowelSwap() {
	// Swap vowels
	vowels := "aeiou"
	for i, c := range f.domain {
		if strings.ContainsRune(vowels, c) {
			for _, v := range vowels {
				if v != c {
					newDomain := f.domain[:i] + string(v) + f.domain[i+1:]
					f.addDomain("vowel-swap", fmt.Sprintf("%s.%s", newDomain, f.tld))
				}
			}
		}
	}
}

func (f *Fuzzer) Domains() []*Domain {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.domains
}
