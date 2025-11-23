# DNS Tunneling Implementation

## Overview

This implementation adds DNS tunneling functionality to windscribe-proxy, routing all DNS queries through the Windscribe VPN tunnel. DNS requests appear to originate from the Windscribe server location rather than the user's local IP address.

## Key Features

1. **Auto-detection of Windows DNS Configuration**
   - Automatically detects DoH (DNS over HTTPS) endpoints configured in Windows
   - Reads DNS server settings from Windows registry
   - No manual configuration required on Windows systems

2. **Custom DoH Upstream Support**
   - Users can specify custom DoH providers via `-resolver` argument
   - Examples: NextDNS, Cloudflare, Google Public DNS
   - Format: `https://dns.nextdns.io/abc123` or `https://1.1.1.1/dns-query`

3. **Automatic Fallback**
   - Primary: DoH (if configured via `-resolver` or auto-detected)
   - Fallback: TCP DNS through tunnel (Google DNS 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9)
   - Ensures DNS resolution always works even if upstream fails

4. **Privacy Enhancement**
   - All DNS queries routed through Windscribe tunnel
   - DNS queries appear from Windscribe server IP, not user's IP
   - Compatible with DNS-based filtering services (NextDNS, AdGuard DNS, etc.)

## Files Added

### tunnel_resolver.go
Main DNS tunneling implementation:
- `TunnelResolvingDialer`: Wraps the ProxyDialer to resolve domains via tunnel
- `queryDoH()`: Performs DNS queries over HTTPS (RFC 8484)
- `queryTCP()`: Performs DNS queries over TCP through tunnel
- DNS response caching with TTL support
- IPv4-first resolution strategy

### windows_dns.go
Windows-specific DNS auto-detection:
- Reads DoH configuration from Windows registry
- Extracts DoH templates from `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohSettings`
- Detects DNS servers from network interface configuration
- Build tag: `//go:build windows`

### windows_dns_stub.go
Non-Windows platform stub:
- Provides no-op implementation for Linux, macOS, BSD
- Returns empty string (falls back to TCP DNS)
- Build tag: `//go:build !windows`

## Files Modified

### main.go
Integration changes:
- Updated `-resolver` flag description to reflect new DNS tunneling purpose
- Removed pre-tunnel resolver setup (lines that used ResolvingDialer before tunnel)
- Added DNS auto-detection logic when `-resolver` is empty
- Instantiate TunnelResolvingDialer wrapping the ProxyDialer
- Wire finalDialer (with DNS tunneling) into ProxyHandler

### README.md
Documentation updates:
- Added DNS tunneling to features list
- New "DNS Tunneling" section with usage examples
- Updated `-resolver` argument description
- Explained how auto-detection and custom DoH work

### go.mod
Dependency updates:
- Added `golang.org/x/sys` for Windows registry access
- Required by windows_dns.go for registry operations

## Architecture

```
Client Request
     ↓
ProxyHandler (receives HTTP/HTTPS requests)
     ↓
TunnelResolvingDialer (resolves domain names)
     ↓
     ├─ DoH Query (if configured) → via ProxyDialer → Windscribe Server → DoH Provider
     │                                      ↓
     │                              Response from DoH Provider IP = Windscribe Server IP
     │
     └─ TCP DNS Fallback → via ProxyDialer → Windscribe Server → 8.8.8.8/1.1.1.1/9.9.9.9
                                      ↓
                              Response from DNS Server IP = Windscribe Server IP
     ↓
ProxyDialer (establishes CONNECT tunnel to destination)
     ↓
Windscribe Server (443)
     ↓
Destination Server
```

## Usage Examples

### Auto-detection Mode (Windows)
```bash
# Automatically detects Windows DNS configuration
windscribe-proxy -username user -password pass -location Germany/Frankfurt
```

### Custom DoH Provider
```bash
# Use NextDNS with custom profile
windscribe-proxy -username user -password pass \
  -location Germany/Frankfurt \
  -resolver https://dns.nextdns.io/abc123

# Use Cloudflare DoH
windscribe-proxy -username user -password pass \
  -location Japan/Tokyo \
  -resolver https://1.1.1.1/dns-query
```

### TCP DNS Only (No DoH)
```bash
# Don't specify -resolver, and no DoH detected on Windows
# Falls back to TCP DNS (8.8.8.8, 1.1.1.1, 9.9.9.9) through tunnel
windscribe-proxy -username user -password pass -location US/New_York
```

## Testing Scenarios

### Scenario 1: NextDNS Integration
1. Configure NextDNS account with custom profile
2. Run: `windscribe-proxy -resolver https://dns.nextdns.io/YOUR_ID -location Germany/Frankfurt`
3. Browse websites through proxy
4. Check NextDNS dashboard → Queries should show from Frankfurt IP (Windscribe server)

### Scenario 2: Windows DoH Auto-detection
1. Configure DoH in Windows Settings → Network → DNS
2. Run: `windscribe-proxy -location Japan/Tokyo` (no -resolver)
3. Proxy auto-detects Windows DoH configuration
4. DNS queries routed through Tokyo server to configured DoH provider

### Scenario 3: Fallback Testing
1. Run with invalid DoH upstream: `-resolver https://invalid.example.com/dns-query`
2. Proxy attempts DoH, fails, falls back to TCP DNS (8.8.8.8)
3. DNS resolution continues to work through fallback

### Scenario 4: DNS Leak Testing
1. Run windscribe-proxy with NextDNS or custom DoH
2. Visit DNS leak test site (dnsleaktest.com)
3. Verify DNS servers shown match Windscribe server location (not user's ISP)

## Behavioral Notes

1. **Always On**: DNS tunneling is always active, cannot be disabled
2. **IPv4 Preference**: Resolves IPv4 (A records) first, falls back to IPv6 (AAAA)
3. **Caching**: DNS responses cached with TTL respect
4. **Logging**: TUNLDNS logger shows DNS resolution activity at debug level
5. **API Calls**: Windscribe API calls bypass tunnel DNS (use direct/pre-tunnel resolution)

## Compatibility

- **Windows**: Full auto-detection support including DoH
- **Linux/macOS/BSD**: No auto-detection, specify `-resolver` or use TCP DNS fallback
- **Official Client Parity**: Behavior matches official Windscribe client DNS handling

## Security Considerations

1. DNS queries encrypted via HTTPS tunnel to Windscribe server
2. DoH adds additional layer of encryption (HTTPS within HTTPS)
3. DNS responses appear from Windscribe server IP (not user's IP)
4. Prevents DNS leaks when using proxy
5. Compatible with DNS-based ad blocking and filtering services

## Performance

- DNS responses cached with TTL to reduce queries
- DoH may have slight latency overhead vs TCP DNS
- Automatic fallback ensures reliability
- Multiple TCP DNS servers (3) for redundancy

## Limitations

1. Auto-detection only works on Windows
2. Requires Windows 10/11 for DoH auto-detection
3. Non-Windows platforms must specify `-resolver` or use TCP DNS
4. DoH upstream must be accessible from Windscribe server location

## Future Enhancements (Potential)

- Auto-detection for macOS/Linux system DNS
- Support for DNS over TLS (DoT)
- Support for DNS over QUIC (DoQ)
- Custom fallback DNS server configuration
- DNS query statistics and monitoring
- Per-domain DNS routing rules
