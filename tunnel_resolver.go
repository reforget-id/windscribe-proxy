package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jellydator/ttlcache/v2"
	"github.com/miekg/dns"
)

// TunnelResolvingDialer performs DNS resolution through the Windscribe tunnel
// with support for custom DoH upstream and fallback to TCP DNS
type TunnelResolvingDialer struct {
	next        ContextDialer
	dohURL      string
	httpClient  *http.Client
	cache4      *ttlcache.Cache
	cache6      *ttlcache.Cache
	logger      *CondLogger
	useFallback bool
	timeout     time.Duration
}

// NewTunnelResolvingDialer creates a resolver that routes DNS via the tunnel
// If dohUpstream is provided, it will be used as primary with TCP DNS as fallback
// If dohUpstream is empty, only TCP DNS (via tunnel) will be used
func NewTunnelResolvingDialer(dohUpstream string, timeout time.Duration, next ContextDialer, logger *CondLogger) (*TunnelResolvingDialer, error) {
	cache4 := ttlcache.NewCache()
	cache6 := ttlcache.NewCache()

	useFallback := false
	var httpClient *http.Client

	if dohUpstream != "" {
		// Create HTTP client that uses the tunnel for DoH requests
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext:           next.DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
			Timeout: timeout,
		}
		useFallback = true
		logger.Info("DNS via tunnel: primary=DoH(%s), fallback=TCP DNS", dohUpstream)
	} else {
		logger.Info("DNS via tunnel: TCP DNS only")
	}

	d := &TunnelResolvingDialer{
		next:        next,
		dohURL:      dohUpstream,
		httpClient:  httpClient,
		cache4:      cache4,
		cache6:      cache6,
		logger:      logger,
		useFallback: useFallback,
		timeout:     timeout,
	}

	cache4.SetLoaderFunction(d.resolveA)
	cache6.SetLoaderFunction(d.resolveAAAA)
	cache4.SetCacheSizeLimit(DNS_CACHE_SIZE_LIMIT)
	cache6.SetCacheSizeLimit(DNS_CACHE_SIZE_LIMIT)
	cache4.SkipTTLExtensionOnHit(true)
	cache6.SkipTTLExtensionOnHit(true)

	return d, nil
}

func (d *TunnelResolvingDialer) resolveA(domain string) (interface{}, time.Duration, error) {
	d.logger.Debug("resolveA(%#v) via tunnel", domain)
	return d.resolve(domain, dns.TypeA)
}

func (d *TunnelResolvingDialer) resolveAAAA(domain string) (interface{}, time.Duration, error) {
	d.logger.Debug("resolveAAAA(%#v) via tunnel", domain)
	return d.resolve(domain, dns.TypeAAAA)
}

func (d *TunnelResolvingDialer) resolve(domain string, typ uint16) (string, time.Duration, error) {
	if len(domain) == 0 {
		return "", 0, errors.New("empty domain name")
	}
	domain = absDomain(domain)

	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: domain, Qtype: typ, Qclass: dns.ClassINET},
	}

	var reply *dns.Msg
	var err error

	// Try DoH first if configured
	if d.dohURL != "" {
		reply, err = d.queryDoH(&req)
		if err != nil && d.useFallback {
			d.logger.Warning("DoH query failed for %s: %v, trying TCP DNS fallback", domain, err)
			reply, err = d.queryTCP(&req)
		}
	} else {
		// Use TCP DNS only
		reply, err = d.queryTCP(&req)
	}

	if err != nil {
		return "", 0, err
	}

	if reply.Rcode != dns.RcodeSuccess {
		return "", 0, fmt.Errorf("DNS query for %s failed: %s", domain, dns.RcodeToString[reply.Rcode])
	}

	// Parse response
	for _, rr := range reply.Answer {
		if a, ok := rr.(*dns.A); ok && typ == dns.TypeA {
			return a.A.String(), cacheTTL(a.Hdr.Ttl), nil
		}
		if aaaa, ok := rr.(*dns.AAAA); ok && typ == dns.TypeAAAA {
			return aaaa.AAAA.String(), cacheTTL(aaaa.Hdr.Ttl), nil
		}
	}
	return "", 0, errors.New("no data in DNS response")
}

// cacheTTL converts a DNS TTL to a cache duration. ttlcache treats a zero
// TTL as "never expire", so zero-TTL records are clamped to a small minimum.
func cacheTTL(ttl uint32) time.Duration {
	const minTTL = 1 * time.Second
	d := time.Duration(ttl) * time.Second
	if d < minTTL {
		return minTTL
	}
	return d
}

// queryDoH performs a DNS query over HTTPS
func (d *TunnelResolvingDialer) queryDoH(req *dns.Msg) (*dns.Msg, error) {
	pack, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Use DNS wire format over HTTPS (RFC 8484)
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, "POST", d.dohURL, bytes.NewReader(pack))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := d.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	reply := &dns.Msg{}
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return reply, nil
}

// Public DNS servers queried over TCP through the Windscribe tunnel
var tcpDNSServers = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}

// queryTCP performs a DNS query over TCP (routed through tunnel)
func (d *TunnelResolvingDialer) queryTCP(req *dns.Msg) (*dns.Msg, error) {
	pack, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	var lastErr error
	for _, server := range tcpDNSServers {
		reply, err := d.queryTCPServer(server, pack)
		if err != nil {
			lastErr = err
			d.logger.Debug("TCP DNS query via %s failed: %v", server, err)
			continue
		}
		d.logger.Debug("Successfully resolved via TCP DNS server %s", server)
		return reply, nil
	}

	return nil, fmt.Errorf("all DNS servers failed: %w", lastErr)
}

func (d *TunnelResolvingDialer) queryTCPServer(server string, pack []byte) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	conn, err := d.next.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", server, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(d.timeout))

	// DNS over TCP requires a 2-byte length prefix (RFC 1035 4.2.2)
	msg := make([]byte, 2+len(pack))
	binary.BigEndian.PutUint16(msg, uint16(len(pack)))
	copy(msg[2:], pack)
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("failed to write to %s: %w", server, err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read length from %s: %w", server, err)
	}
	buf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("failed to read from %s: %w", server, err)
	}

	reply := &dns.Msg{}
	if err := reply.Unpack(buf); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response from %s: %w", server, err)
	}
	if reply.Id != packedID(pack) {
		return nil, fmt.Errorf("DNS response ID mismatch from %s", server)
	}
	return reply, nil
}

// packedID extracts the message ID from a packed DNS message
func packedID(pack []byte) uint16 {
	return binary.BigEndian.Uint16(pack)
}

func (d *TunnelResolvingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if net.ParseIP(name) != nil || len(name) == 0 {
		// Address is already in numeric form
		return d.next.DialContext(ctx, network, address)
	}

	if len(network) == 0 {
		return d.next.DialContext(ctx, network, address)
	}

	name = absDomain(name)
	switch network[len(network)-1] {
	case '4':
		res, err := d.cache4.Get(name)
		if err != nil {
			return nil, err
		}
		name = res.(string)
	case '6':
		res, err := d.cache6.Get(name)
		if err != nil {
			return nil, err
		}
		name = res.(string)
	default:
		// Try IPv4 first
		res, err := d.cache4.Get(name)
		if err != nil {
			// Fall back to IPv6
			res, err = d.cache6.Get(name)
			if err != nil {
				return nil, err
			}
		}
		name = res.(string)
	}
	newAddress := net.JoinHostPort(name, port)
	d.logger.Debug("tunnel DNS resolve: %s => %s", address, newAddress)
	return d.next.DialContext(ctx, network, newAddress)
}

func (d *TunnelResolvingDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
