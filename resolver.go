package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/jellydator/ttlcache/v2"
	"github.com/miekg/dns"
)

const (
	DOT                  = 0x2e
	DNS_CACHE_SIZE_LIMIT = 1024
)

type IPPreference string

const (
	IPPreferenceIPv4First IPPreference = "ipv4-first"
	IPPreferenceIPv6First IPPreference = "ipv6-first"
	IPPreferenceIPv4Only  IPPreference = "ipv4-only"
	IPPreferenceIPv6Only  IPPreference = "ipv6-only"
)

func (p IPPreference) String() string {
	if p == "" {
		return string(IPPreferenceIPv4First)
	}
	return string(p)
}

func (p *IPPreference) Set(value string) error {
	switch IPPreference(value) {
	case IPPreferenceIPv4First, IPPreferenceIPv6First, IPPreferenceIPv4Only, IPPreferenceIPv6Only:
		*p = IPPreference(value)
		return nil
	default:
		return fmt.Errorf("invalid IP preference: %s", value)
	}
}

func (p IPPreference) resolutionOrder() []ipFamily {
	switch p {
	case IPPreferenceIPv6Only:
		return []ipFamily{ipFamily6}
	case IPPreferenceIPv4Only:
		return []ipFamily{ipFamily4}
	case IPPreferenceIPv6First:
		return []ipFamily{ipFamily6, ipFamily4}
	default:
		return []ipFamily{ipFamily4, ipFamily6}
	}
}

type ipFamily int

const (
	ipFamily4 ipFamily = iota
	ipFamily6
)

type systemResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type HostResolver interface {
	ResolveHost(ctx context.Context, host string, preference IPPreference) (netip.Addr, error)
}

type ResolvingDialer struct {
	next        ContextDialer
	upstream    upstream.Upstream
	cache4      *ttlcache.Cache
	cache6      *ttlcache.Cache
	sysResolver systemResolver
	timeout     time.Duration
	logger      *CondLogger
	preference  IPPreference
}

func NewResolvingDialer(resolverAddress string, timeout time.Duration, next ContextDialer, logger *CondLogger, preference IPPreference) (*ResolvingDialer, error) {
	d := &ResolvingDialer{
		next:        next,
		sysResolver: net.DefaultResolver,
		timeout:     timeout,
		logger:      logger,
		preference:  preference,
	}

	if resolverAddress != "" {
		opts := &upstream.Options{Timeout: timeout}
		u, err := upstream.AddressToUpstream(resolverAddress, opts)
		if err != nil {
			return nil, err
		}
		d.upstream = u
		d.cache4 = ttlcache.NewCache()
		d.cache6 = ttlcache.NewCache()
		d.cache4.SetLoaderFunction(d.resolveA)
		d.cache6.SetLoaderFunction(d.resolveAAAA)
		d.cache4.SetCacheSizeLimit(DNS_CACHE_SIZE_LIMIT)
		d.cache6.SetCacheSizeLimit(DNS_CACHE_SIZE_LIMIT)
		d.cache4.SkipTTLExtensionOnHit(true)
		d.cache6.SkipTTLExtensionOnHit(true)
	}

	return d, nil
}

func (d *ResolvingDialer) resolveA(domain string) (interface{}, time.Duration, error) {
	d.logger.Debug("resolveA(%#v)", domain)
	return d.resolveRecord(domain, dns.TypeA)
}

func (d *ResolvingDialer) resolveAAAA(domain string) (interface{}, time.Duration, error) {
	d.logger.Debug("resolveAAAA(%#v)", domain)
	return d.resolveRecord(domain, dns.TypeAAAA)
}

func (d *ResolvingDialer) resolveRecord(domain string, typ uint16) (netip.Addr, time.Duration, error) {
	if d.upstream == nil {
		return netip.Addr{}, 0, errors.New("custom resolver not configured")
	}
	if len(domain) == 0 {
		return netip.Addr{}, 0, errors.New("empty domain name")
	}
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{{Name: domain, Qtype: typ, Qclass: dns.ClassINET}}
	reply, err := d.upstream.Exchange(&req)
	if err != nil {
		return netip.Addr{}, 0, err
	}

	for _, rr := range reply.Answer {
		switch v := rr.(type) {
		case *dns.A:
			addr, ok := netip.AddrFromSlice(v.A[:])
			if ok {
				return addr, time.Duration(v.Hdr.Ttl) * time.Second, nil
			}
		case *dns.AAAA:
			addr, ok := netip.AddrFromSlice(v.AAAA[:])
			if ok {
				return addr, time.Duration(v.Hdr.Ttl) * time.Second, nil
			}
		}
	}
	return netip.Addr{}, 0, errors.New("no data in DNS response")
}

func (d *ResolvingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if net.ParseIP(name) != nil || len(name) == 0 {
		return d.next.DialContext(ctx, network, address)
	}

	var pref IPPreference
	switch {
	case strings.HasSuffix(network, "4"):
		pref = IPPreferenceIPv4Only
	case strings.HasSuffix(network, "6"):
		pref = IPPreferenceIPv6Only
	default:
		pref = d.preference
	}

	ipAddr, err := d.ResolveHost(ctx, name, pref)
	if err != nil {
		return nil, err
	}

	newAddress := net.JoinHostPort(ipAddr.String(), port)
	d.logger.Debug("resolve rewrite: %s => %s", address, newAddress)
	return d.next.DialContext(ctx, network, newAddress)
}

func (d *ResolvingDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *ResolvingDialer) ResolveHost(ctx context.Context, host string, preference IPPreference) (netip.Addr, error) {
	if host == "" {
		return netip.Addr{}, errors.New("empty host")
	}

	if ip := net.ParseIP(host); ip != nil {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return netip.Addr{}, errors.New("invalid IP address")
		}
		return addr, nil
	}

	domain := absDomain(host)
	order := preference.resolutionOrder()
	var errs []error
	for _, fam := range order {
		addr, err := d.lookupFamily(ctx, domain, fam)
		if err == nil {
			return addr, nil
		}
		errs = append(errs, err)
	}

	return netip.Addr{}, errors.Join(errs...)
}

func (d *ResolvingDialer) lookupFamily(ctx context.Context, domain string, fam ipFamily) (netip.Addr, error) {
	if d.upstream != nil {
		cache := d.cache4
		if fam == ipFamily6 {
			cache = d.cache6
		}
		if cache == nil {
			return netip.Addr{}, errors.New("resolver cache not initialized")
		}
		res, err := cache.Get(domain)
		if err != nil {
			return netip.Addr{}, err
		}
		return res.(netip.Addr), nil
	}

	return d.resolveViaSystem(ctx, domain, fam)
}

func (d *ResolvingDialer) resolveViaSystem(ctx context.Context, domain string, fam ipFamily) (netip.Addr, error) {
	if d.sysResolver == nil {
		return netip.Addr{}, errors.New("system resolver is unavailable")
	}

	host := strings.TrimSuffix(domain, ".")
	ctx, cancel := d.contextWithTimeout(ctx)
	if cancel != nil {
		defer cancel()
	}

	ips, err := d.sysResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}

	for _, ip := range ips {
		if fam == ipFamily4 && ip.IP.To4() != nil {
			addr, _ := netip.AddrFromSlice(ip.IP.To4())
			return addr, nil
		}
		if fam == ipFamily6 && ip.IP.To16() != nil && ip.IP.To4() == nil {
			addr, _ := netip.AddrFromSlice(ip.IP.To16())
			return addr, nil
		}
	}

	return netip.Addr{}, errors.New("no data in DNS response")
}

func (d *ResolvingDialer) contextWithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if d.timeout <= 0 {
		return ctx, nil
	}
	return context.WithTimeout(ctx, d.timeout)
}

func absDomain(domain string) string {
	if domain == "" {
		return ""
	}
	domain = strings.ToLower(domain)
	if domain[len(domain)-1] != DOT {
		domain = domain + "."
	}
	return domain
}
