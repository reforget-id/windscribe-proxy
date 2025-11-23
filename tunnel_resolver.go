package main

import (
	"bytes"
	"context"
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

	// Parse response
	for _, rr := range reply.Answer {
		if a, ok := rr.(*dns.A); ok && typ == dns.TypeA {
			return a.A.String(), (time.Second * time.Duration(a.Hdr.Ttl)), nil
		}
		if aaaa, ok := rr.(*dns.AAAA); ok && typ == dns.TypeAAAA {
			return aaaa.AAAA.String(), (time.Second * time.Duration(aaaa.Hdr.Ttl)), nil
		}
	}
	return "", 0, errors.New("no data in DNS response")
}

// queryDoH performs a DNS query over HTTPS
func (d *TunnelResolvingDialer) queryDoH(req *dns.Msg) (*dns.Msg, error) {
	pack, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Use DNS wire format over HTTPS (RFC 8484)
	httpReq, err := http.NewRequest("POST", d.dohURL, bytes.NewReader(pack))
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	reply := &dns.Msg{}
	if err := reply.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return reply, nil
}

// queryTCP performs a DNS query over TCP (routed through tunnel)
// Uses public DNS servers that will be routed through the Windscribe tunnel
func (d *TunnelResolvingDialer) queryTCP(req *dns.Msg) (*dns.Msg, error) {
	// Use common public DNS servers that will be routed through the tunnel
	// Try Google DNS first, then Cloudflare, then Quad9
	servers := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}

	var lastErr error
	for _, server := range servers {
		conn, err := d.next.DialContext(context.Background(), "tcp", server)
		if err != nil {
			lastErr = fmt.Errorf("failed to dial %s: %w", server, err)
			d.logger.Debug("Failed to connect to DNS server %s: %v", server, err)
			continue
		}
		defer conn.Close()

		// Set deadline
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		pack, err := req.Pack()
		if err != nil {
			lastErr = fmt.Errorf("failed to pack DNS message: %w", err)
			continue
		}

		// DNS over TCP requires a 2-byte length prefix
		length := uint16(len(pack))
		lengthBytes := []byte{byte(length >> 8), byte(length & 0xff)}

		_, err = conn.Write(lengthBytes)
		if err != nil {
			lastErr = fmt.Errorf("failed to write length to %s: %w", server, err)
			d.logger.Debug("Failed to write length to %s: %v", server, err)
			continue
		}

		_, err = conn.Write(pack)
		if err != nil {
			lastErr = fmt.Errorf("failed to write to %s: %w", server, err)
			d.logger.Debug("Failed to write DNS query to %s: %v", server, err)
			continue
		}

		// Read 2-byte length prefix
		lenBuf := make([]byte, 2)
		_, err = io.ReadFull(conn, lenBuf)
		if err != nil {
			lastErr = fmt.Errorf("failed to read length from %s: %w", server, err)
			d.logger.Debug("Failed to read length from %s: %v", server, err)
			continue
		}
		respLength := int(lenBuf[0])<<8 | int(lenBuf[1])

		// Read response
		buf := make([]byte, respLength)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			lastErr = fmt.Errorf("failed to read from %s: %w", server, err)
			d.logger.Debug("Failed to read DNS response from %s: %v", server, err)
			continue
		}

		reply := &dns.Msg{}
		if err := reply.Unpack(buf); err != nil {
			lastErr = fmt.Errorf("failed to unpack DNS response: %w", err)
			d.logger.Debug("Failed to unpack DNS response from %s: %v", server, err)
			continue
		}

		d.logger.Debug("Successfully resolved via TCP DNS server %s", server)
		return reply, nil
	}

	return nil, fmt.Errorf("all DNS servers failed: %v", lastErr)
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
