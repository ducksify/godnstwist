package scanner

import (
	"net"
	"testing"
	"time"

	"github.com/ducksify/godnstwist/internal/fuzzer"
	"github.com/miekg/dns"
)

func TestNewScanner(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("NewScanner() returned nil")
	}

	if s.config != config {
		t.Error("NewScanner() did not set config correctly")
	}
}

func TestNewScanner_WithGeoIP(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       true,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("NewScanner() returned nil")
	}

	// GeoIP database loading should fail gracefully if file doesn't exist
	if s.geoipDB != nil {
		t.Error("Expected GeoIP database to be nil when file doesn't exist")
	}
}

func TestNewScanner_WithMultipleNameservers(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53,1.1.1.1:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("NewScanner() returned nil")
	}

	expected := "8.8.8.8:53"
	if s.nameserver != expected {
		t.Errorf("Expected nameserver %s, got %s", expected, s.nameserver)
	}
}

func TestNewScanner_EmptyNameservers(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("NewScanner() returned nil")
	}

	expected := "8.8.8.8:53"
	if s.nameserver != expected {
		t.Errorf("Expected default nameserver %s, got %s", expected, s.nameserver)
	}
}

func TestScanner_Scan(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domains := []*fuzzer.Domain{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS:    make(map[string][]string),
			Banner: make(map[string]string),
			Whois:  make(map[string]string),
			LSH:    make(map[string]int),
		},
	}

	results := s.Scan(domains)
	if len(results) == 0 {
		t.Error("Scan() produced no results")
	}

	// Check if the original domain is in the results
	found := false
	for _, domain := range results {
		if domain.Domain == "example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Scan() did not include the original domain")
	}
}

func TestScanner_Scan_WithBanners(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     true,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domains := []*fuzzer.Domain{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS:    make(map[string][]string),
			Banner: make(map[string]string),
			Whois:  make(map[string]string),
			LSH:    make(map[string]int),
		},
	}

	results := s.Scan(domains)
	if len(results) == 0 {
		t.Error("Scan() produced no results")
	}
}

func TestScanner_Scan_WithMXCheck(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     true,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domains := []*fuzzer.Domain{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS:    make(map[string][]string),
			Banner: make(map[string]string),
			Whois:  make(map[string]string),
			LSH:    make(map[string]int),
		},
	}

	results := s.Scan(domains)
	if len(results) == 0 {
		t.Error("Scan() produced no results")
	}
}

func TestScanner_Scan_WithAllFeatures(t *testing.T) {
	config := &Config{
		All:         true,
		Banners:     true,
		GeoIP:       true,
		MXCheck:     true,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domains := []*fuzzer.Domain{
		{
			Fuzzer: "original",
			Domain: "example.com",
			DNS:    make(map[string][]string),
			Banner: make(map[string]string),
			Whois:  make(map[string]string),
			LSH:    make(map[string]int),
		},
	}

	results := s.Scan(domains)
	if len(results) == 0 {
		t.Error("Scan() produced no results")
	}
}

func TestScanner_lookupA(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "example.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	err := s.lookupA(domain)
	if err != nil {
		t.Fatalf("lookupA() failed: %v", err)
	}

	if len(domain.DNS["A"]) == 0 {
		t.Error("lookupA() returned no IP addresses")
	}
}

func TestScanner_lookupA_InvalidDomain(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "invalid-domain-that-does-not-exist-12345.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	err := s.lookupA(domain)
	if err == nil {
		t.Error("Expected lookupA() to fail for invalid domain")
	}
}

func TestScanner_lookupMX(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "example.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	err := s.lookupMX(domain)
	if err != nil {
		t.Fatalf("lookupMX() failed: %v", err)
	}

	if len(domain.DNS["MX"]) == 0 {
		t.Error("lookupMX() returned no MX records")
	}
}

func TestScanner_lookupMX_InvalidDomain(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "invalid-domain-that-does-not-exist-12345.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	err := s.lookupMX(domain)
	if err == nil {
		t.Error("Expected lookupMX() to fail for invalid domain")
	}
}

func TestScanner_getHTTPBanner(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	// Test with a known IP that should be unreachable
	banner, err := s.getHTTPBanner("192.0.2.1", "test.com")
	if err == nil {
		t.Error("Expected getHTTPBanner() to fail for unreachable IP")
	}
	if banner != "" {
		t.Error("Expected empty banner for failed connection")
	}
}

func TestScanner_getHTTPBanner_InvalidIP(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	// Test with invalid IP
	banner, err := s.getHTTPBanner("invalid-ip", "test.com")
	if err == nil {
		t.Error("Expected getHTTPBanner() to fail for invalid IP")
	}
	if banner != "" {
		t.Error("Expected empty banner for invalid IP")
	}
}

func TestScanner_getSMTPBanner(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	// Test with a known host that should be unreachable
	banner, err := s.getSMTPBanner("invalid-smtp-host-12345.com")
	if err == nil {
		t.Error("Expected getSMTPBanner() to fail for unreachable host")
	}
	if banner != "" {
		t.Error("Expected empty banner for failed connection")
	}
}

func TestScanner_scanDomain_WithGeoIP(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       true,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "example.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	result := s.scanDomain(domain)
	if result == nil {
		t.Fatal("scanDomain() returned nil")
	}
}

func TestScanner_scanDomain_WithBanners(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     true,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "example.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	result := s.scanDomain(domain)
	if result == nil {
		t.Fatal("scanDomain() returned nil")
	}
}

func TestScanner_scanDomain_WithMXCheck(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     true,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "example.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	result := s.scanDomain(domain)
	if result == nil {
		t.Fatal("scanDomain() returned nil")
	}
}

func TestScanner_scanDomain_WithAllFeatures(t *testing.T) {
	config := &Config{
		All:         true,
		Banners:     true,
		GeoIP:       true,
		MXCheck:     true,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "example.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	result := s.scanDomain(domain)
	if result == nil {
		t.Fatal("scanDomain() returned nil")
	}
}

func TestScanner_scanDomain_WithInvalidDomain(t *testing.T) {
	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: "8.8.8.8:53",
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "invalid-domain-that-does-not-exist-12345.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	result := s.scanDomain(domain)
	if result == nil {
		t.Fatal("scanDomain() returned nil")
	}
}

// Mock DNS server for testing
func startMockDNSServer(t *testing.T) (string, func()) {
	server := &dns.Server{
		Addr: ":0", // Use random port
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			msg := dns.Msg{}
			msg.SetReply(r)
			msg.Authoritative = true

			// Add A record for example.com
			if r.Question[0].Name == "example.com." && r.Question[0].Qtype == dns.TypeA {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("93.184.216.34"),
				})
			}

			// Add MX record for example.com
			if r.Question[0].Name == "example.com." && r.Question[0].Qtype == dns.TypeMX {
				msg.Answer = append(msg.Answer, &dns.MX{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Mx:  "mail.example.com.",
				})
			}

			w.WriteMsg(&msg)
		}),
	}

	// Start server
	go func() {
		if err := server.ListenAndServe(); err != nil {
			t.Logf("Mock DNS server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual address
	addr := server.PacketConn.LocalAddr().String()

	return addr, func() {
		server.Shutdown()
	}
}

func TestScanner_WithMockDNSServer(t *testing.T) {
	// Start mock DNS server
	addr, cleanup := startMockDNSServer(t)
	defer cleanup()

	config := &Config{
		All:         false,
		Banners:     false,
		GeoIP:       false,
		MXCheck:     false,
		Nameservers: addr,
		UserAgent:   "Mozilla/5.0",
		Threads:     4,
	}

	s := NewScanner(config)
	if s == nil {
		t.Fatal("Failed to create scanner")
	}

	domain := &fuzzer.Domain{
		Fuzzer: "original",
		Domain: "example.com",
		DNS:    make(map[string][]string),
		Banner: make(map[string]string),
		Whois:  make(map[string]string),
		LSH:    make(map[string]int),
	}

	// Test A record lookup
	err := s.lookupA(domain)
	if err != nil {
		t.Fatalf("lookupA() failed: %v", err)
	}

	if len(domain.DNS["A"]) == 0 {
		t.Error("lookupA() returned no IP addresses")
	}

	// Test MX record lookup
	err = s.lookupMX(domain)
	if err != nil {
		t.Fatalf("lookupMX() failed: %v", err)
	}

	if len(domain.DNS["MX"]) == 0 {
		t.Error("lookupMX() returned no MX records")
	}
}
