package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// redirectDialer sends every dial for a DNS server (port 53) to a local test
// server and records all other dial targets.
type redirectDialer struct {
	dnsAddr string
	dials   chan string
	fail    map[string]bool
	n       net.Dialer
}

func (r *redirectDialer) Dial(network, addr string) (net.Conn, error) {
	return r.DialContext(context.Background(), network, addr)
}

func (r *redirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if _, port, _ := net.SplitHostPort(addr); port == "53" {
		return r.n.DialContext(ctx, "tcp", r.dnsAddr)
	}
	if r.dials != nil {
		r.dials <- addr
	}
	if r.fail[addr] {
		return nil, errors.New("unreachable")
	}
	c1, c2 := net.Pipe()
	go io.Copy(io.Discard, c2)
	return c1, nil
}

func testLogger() *CondLogger {
	return NewCondLogger(log.New(io.Discard, "", 0), 10)
}

// startDNS runs a TCP DNS server with fixed zone data and counts queries.
func startDNS(t *testing.T, records map[string][]string, queries *int32) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: l, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		atomic.AddInt32(queries, 1)
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		rrs, known := records[q.Name]
		if !known {
			m.Rcode = dns.RcodeNameError
			soa, _ := dns.NewRR(". 3600 IN SOA a. b. 1 1 1 1 60")
			m.Ns = append(m.Ns, soa)
		}
		for _, s := range rrs {
			rr, err := dns.NewRR(s)
			if err != nil {
				t.Error(err)
				continue
			}
			if rr.Header().Rrtype == q.Qtype {
				m.Answer = append(m.Answer, rr)
			}
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return l.Addr().String()
}

func newTestResolver(t *testing.T, rd *redirectDialer) *TunnelResolvingDialer {
	d, err := NewTunnelResolvingDialer("", 2*time.Second, rd, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestResolveAllAddressesMinTTL(t *testing.T) {
	var q int32
	addr := startDNS(t, map[string][]string{
		"multi.test.": {"multi.test. 300 IN A 10.0.0.1", "multi.test. 60 IN A 10.0.0.2"},
	}, &q)
	d := newTestResolver(t, &redirectDialer{dnsAddr: addr})
	addrs, ttl, err := d.resolve("multi.test", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 || addrs[0] != "10.0.0.1" || addrs[1] != "10.0.0.2" {
		t.Fatalf("addrs = %v", addrs)
	}
	if ttl != 60*time.Second {
		t.Fatalf("ttl = %v, want 60s", ttl)
	}
}

func TestResolveZeroTTLClamped(t *testing.T) {
	var q int32
	addr := startDNS(t, map[string][]string{"zero.test.": {"zero.test. 0 IN A 10.0.0.1"}}, &q)
	d := newTestResolver(t, &redirectDialer{dnsAddr: addr})
	_, ttl, err := d.resolve("zero.test", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 {
		t.Fatalf("ttl = %v, zero TTL would never expire in ttlcache", ttl)
	}
}

func TestNegativeAnswerCached(t *testing.T) {
	var q int32
	addr := startDNS(t, map[string][]string{}, &q)
	d := newTestResolver(t, &redirectDialer{dnsAddr: addr})
	for i := 0; i < 3; i++ {
		_, err := d.DialContext(context.Background(), "tcp4", "missing.test:443")
		var neg *negativeAnswerError
		if !errors.As(err, &neg) {
			t.Fatalf("err = %v, want negative answer", err)
		}
	}
	if n := atomic.LoadInt32(&q); n != 1 {
		t.Fatalf("DNS queries = %d, want 1 (negative answer should be cached)", n)
	}
	_, ttl, _ := d.resolve("missing.test", dns.TypeA)
	if ttl != 60*time.Second {
		t.Fatalf("negative ttl = %v, want SOA minimum 60s", ttl)
	}
}

func TestDialTriesNextAddress(t *testing.T) {
	var q int32
	addr := startDNS(t, map[string][]string{
		"multi.test.": {"multi.test. 300 IN A 10.0.0.1", "multi.test. 300 IN A 10.0.0.2"},
	}, &q)
	rd := &redirectDialer{dnsAddr: addr, dials: make(chan string, 10), fail: map[string]bool{"10.0.0.1:443": true}}
	d := newTestResolver(t, rd)
	conn, err := d.DialContext(context.Background(), "tcp", "multi.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if a, b := <-rd.dials, <-rd.dials; a != "10.0.0.1:443" || b != "10.0.0.2:443" {
		t.Fatalf("dials = %s, %s", a, b)
	}
}

func TestDialFallsBackToIPv6(t *testing.T) {
	var q int32
	addr := startDNS(t, map[string][]string{"v6.test.": {"v6.test. 300 IN AAAA 2001:db8::1"}}, &q)
	rd := &redirectDialer{dnsAddr: addr, dials: make(chan string, 10)}
	d := newTestResolver(t, rd)
	conn, err := d.DialContext(context.Background(), "tcp", "v6.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := <-rd.dials; got != "[2001:db8::1]:443" {
		t.Fatalf("dialed %s", got)
	}
}

func TestDialIPv4DoesNotQueryIPv6(t *testing.T) {
	var q int32
	addr := startDNS(t, map[string][]string{"v4.test.": {"v4.test. 300 IN A 10.0.0.1"}}, &q)
	d := newTestResolver(t, &redirectDialer{dnsAddr: addr})
	conn, err := d.DialContext(context.Background(), "tcp", "v4.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if n := atomic.LoadInt32(&q); n != 1 {
		t.Fatalf("DNS queries = %d, want 1", n)
	}
}
