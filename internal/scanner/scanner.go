package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ducksify/godnstwist/internal/fuzzer"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

type Scanner struct {
	config     *Config
	geoipDB    *geoip2.Reader
	dnsClient  *dns.Client
	nameserver string
}

type Config struct {
	All         bool
	Banners     bool
	GeoIP       bool
	LSH         string
	MXCheck     bool
	NSCheck     bool
	Nameservers string
	PHash       bool
	Screenshots string
	UserAgent   string
	Threads     int
}

func NewScanner(config *Config) *Scanner {
	s := &Scanner{
		config: config,
	}

	if config.GeoIP {
		db, err := geoip2.Open("GeoLite2-Country.mmdb")
		if err == nil {
			s.geoipDB = db
		}
	}

	if config.Nameservers != "" {
		s.nameserver = strings.Split(config.Nameservers, ",")[0]
	} else {
		s.nameserver = "8.8.8.8:53"
	}

	s.dnsClient = &dns.Client{
		Net: "udp",
	}

	return s
}

func (s *Scanner) Scan(domains []*fuzzer.Domain) []*fuzzer.Domain {
	var wg sync.WaitGroup
	results := make([]*fuzzer.Domain, len(domains))
	semaphore := make(chan struct{}, s.config.Threads)

	for i, domain := range domains {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(i int, domain *fuzzer.Domain) {
			defer wg.Done()
			defer func() { <-semaphore }()

			results[i] = s.scanDomain(domain)
		}(i, domain)
	}

	wg.Wait()
	return results
}

func (s *Scanner) scanDomain(domain *fuzzer.Domain) *fuzzer.Domain {
	// DNS A record lookup
	if err := s.lookupA(domain); err != nil {
		return domain
	}

	// GeoIP lookup
	if s.config.GeoIP && s.geoipDB != nil && len(domain.DNS["A"]) > 0 {
		if ip := net.ParseIP(domain.DNS["A"][0]); ip != nil {
			if record, err := s.geoipDB.Country(ip); err == nil {
				domain.GeoIP = record.Country.Names["en"]
			}
		}
	}

	// HTTP banner
	if s.config.Banners && len(domain.DNS["A"]) > 0 {
		// Use Punycode for Host header if available, otherwise use original domain
		hostHeader := domain.Domain
		if domain.Punycode != "" {
			hostHeader = domain.Punycode
		}
		if banner, err := s.getHTTPBanner(domain.DNS["A"][0], hostHeader); err == nil {
			domain.Banner["http"] = banner
		}
	}

	// MX record lookup
	if s.config.MXCheck {
		if err := s.lookupMX(domain); err == nil {
			if mxRecords := domain.DNS["MX"]; len(mxRecords) > 0 {
				if banner, err := s.getSMTPBanner(mxRecords[0]); err == nil {
					domain.Banner["smtp"] = banner
				}
			}
		}
	}

	// NS record lookup
	if s.config.NSCheck {
		s.lookupNS(domain)
	}

	return domain
}

func (s *Scanner) lookupA(domain *fuzzer.Domain) error {
	// Use Punycode for DNS resolution if available, otherwise use original domain
	dnsDomain := domain.Domain
	if domain.Punycode != "" {
		dnsDomain = domain.Punycode
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dnsDomain), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := s.dnsClient.Exchange(m, s.nameserver)
	if err != nil {
		return err
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS lookup failed with code %d", r.Rcode)
	}

	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			domain.DNS["A"] = append(domain.DNS["A"], a.A.String())
		}
	}

	return nil
}

func (s *Scanner) lookupMX(domain *fuzzer.Domain) error {
	// Use Punycode for DNS resolution if available, otherwise use original domain
	dnsDomain := domain.Domain
	if domain.Punycode != "" {
		dnsDomain = domain.Punycode
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dnsDomain), dns.TypeMX)
	m.RecursionDesired = true

	r, _, err := s.dnsClient.Exchange(m, s.nameserver)
	if err != nil {
		return err
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS lookup failed with code %d", r.Rcode)
	}

	for _, ans := range r.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			domain.DNS["MX"] = append(domain.DNS["MX"], mx.Mx)
		}
	}

	return nil
}

func (s *Scanner) lookupNS(domain *fuzzer.Domain) error {
	// Use Punycode for DNS resolution if available, otherwise use original domain
	dnsDomain := domain.Domain
	if domain.Punycode != "" {
		dnsDomain = domain.Punycode
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dnsDomain), dns.TypeNS)
	m.RecursionDesired = true

	r, _, err := s.dnsClient.Exchange(m, s.nameserver)
	if err != nil {
		return err
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS lookup failed with code %d", r.Rcode)
	}

	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			domain.DNS["NS"] = append(domain.DNS["NS"], ns.Ns)
		}
	}

	return nil
}

func (s *Scanner) getHTTPBanner(ip, host string) (string, error) {
	conn, err := net.DialTimeout("tcp", ip+":80", 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", host, s.config.UserAgent)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	response := string(buf[:n])
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[7:]), nil
		}
	}

	return "", nil
}

func (s *Scanner) getSMTPBanner(host string) (string, error) {
	conn, err := net.DialTimeout("tcp", host+":25", 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(buf[:n])), nil
}
