package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/jellydator/ttlcache/v2"
	"github.com/miekg/dns"
)

type stubUpstream struct {
	responses map[uint16][]dns.RR
}

func (s *stubUpstream) Exchange(req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	qtype := req.Question[0].Qtype
	resp.Answer = append(resp.Answer, s.responses[qtype]...)
	return resp, nil
}

func (s *stubUpstream) Address() string { return "stub" }

func (s *stubUpstream) Close() error { return nil }

type stubSystemResolver struct {
	addrs []net.IPAddr
}

func (s stubSystemResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return s.addrs, nil
}

type noopDialer struct{}

func (noopDialer) Dial(network, address string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (noopDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func newTestLogger() *CondLogger {
	return NewCondLogger(log.New(io.Discard, "TEST: ", 0), 50)
}

func newTestResolverWithUpstream(up upstream.Upstream) *ResolvingDialer {
	cache4 := ttlcache.NewCache()
	cache6 := ttlcache.NewCache()
	d := &ResolvingDialer{
		next:        noopDialer{},
		upstream:    up,
		cache4:      cache4,
		cache6:      cache6,
		timeout:     time.Second,
		logger:      newTestLogger(),
		preference:  IPPreferenceIPv4First,
		sysResolver: nil,
	}
	cache4.SetLoaderFunction(d.resolveA)
	cache6.SetLoaderFunction(d.resolveAAAA)
	cache4.SetCacheSizeLimit(DNS_CACHE_SIZE_LIMIT)
	cache6.SetCacheSizeLimit(DNS_CACHE_SIZE_LIMIT)
	cache4.SkipTTLExtensionOnHit(true)
	cache6.SkipTTLExtensionOnHit(true)
	return d
}

func TestResolvingDialerPrefersIPv4First(t *testing.T) {
	up := &stubUpstream{
		responses: map[uint16][]dns.RR{
			dns.TypeA:    {newARecord("example.com.", "203.0.113.10", 60)},
			dns.TypeAAAA: {newAAAARecord("example.com.", "2001:db8::10", 60)},
		},
	}
	d := newTestResolverWithUpstream(up)

	addr, err := d.ResolveHost(context.Background(), "example.com", IPPreferenceIPv4First)
	if err != nil {
		t.Fatalf("ResolveHost failed: %v", err)
	}
	if addr.String() != "203.0.113.10" {
		t.Fatalf("expected IPv4 address, got %s", addr)
	}
}

func TestResolvingDialerNoRotation(t *testing.T) {
	up := &stubUpstream{
		responses: map[uint16][]dns.RR{
			dns.TypeA: {
				newARecord("example.com.", "203.0.113.10", 60),
				newARecord("example.com.", "203.0.113.11", 60),
			},
		},
	}
	d := newTestResolverWithUpstream(up)

	first, err := d.ResolveHost(context.Background(), "example.com", IPPreferenceIPv4First)
	if err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	second, err := d.ResolveHost(context.Background(), "example.com", IPPreferenceIPv4First)
	if err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected stable answer, got %s and %s", first, second)
	}
}

func TestResolvingDialerSystemFallback(t *testing.T) {
	addr := net.IPAddr{IP: net.ParseIP("198.51.100.5")}
	d := &ResolvingDialer{
		next:        noopDialer{},
		sysResolver: stubSystemResolver{addrs: []net.IPAddr{addr}},
		timeout:     time.Second,
		logger:      newTestLogger(),
		preference:  IPPreferenceIPv4First,
	}

	resolved, err := d.ResolveHost(context.Background(), "fallback.example", IPPreferenceIPv4First)
	if err != nil {
		t.Fatalf("ResolveHost failed: %v", err)
	}
	if resolved.String() != "198.51.100.5" {
		t.Fatalf("unexpected address %s", resolved)
	}
}

func newARecord(name, ip string, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}
}

func newAAAARecord(name, ip string, ttl uint32) dns.RR {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(ip),
	}
}
