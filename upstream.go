package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	PROXY_CONNECT_METHOD       = "CONNECT"
	PROXY_HOST_HEADER          = "Host"
	PROXY_AUTHORIZATION_HEADER = "Proxy-Authorization"
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ContextDialer interface {
	Dialer
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type ProxyDialer struct {
	address       string
	tlsServerName string
	auth          AuthProvider
	next          ContextDialer
	caPool        *x509.CertPool
	sni           string
}

func NewProxyDialer(address, tlsServerName, sni string, auth AuthProvider, caPool *x509.CertPool, nextDialer ContextDialer) *ProxyDialer {
	return &ProxyDialer{
		address:       address,
		tlsServerName: tlsServerName,
		auth:          auth,
		next:          nextDialer,
		caPool:        caPool,
		sni:           sni,
	}
}

func ProxyDialerFromURL(u *url.URL, next ContextDialer) (*ProxyDialer, error) {
	host := u.Hostname()
	port := u.Port()
	tlsServerName := ""
	var auth AuthProvider = nil

	switch strings.ToLower(u.Scheme) {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
		tlsServerName = host
	default:
		return nil, errors.New("unsupported proxy type")
	}

	address := net.JoinHostPort(host, port)

	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		authHeader := basic_auth_header(username, password)
		auth = func() string {
			return authHeader
		}
	}
	return NewProxyDialer(address, tlsServerName, "", auth, nil, next), nil
}

func (d *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("bad network specified for DialContext: only tcp is supported")
	}

	conn, err := d.next.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	// Bound TLS handshake and CONNECT exchange by the caller's context deadline
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	if d.tlsServerName != "" {
		// Custom cert verification logic:
		// DO NOT send SNI extension of TLS ClientHello
		// DO peer certificate verification against specified servername
		conn = tls.Client(conn, &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         d.sni,
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				opts := x509.VerifyOptions{
					DNSName:       d.tlsServerName,
					Intermediates: x509.NewCertPool(),
					Roots:         d.caPool,
				}
				if len(cs.PeerCertificates) == 0 {
					return errors.New("no peer certificates presented")
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		})
	}

	req := &http.Request{
		Method:     PROXY_CONNECT_METHOD,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RequestURI: address,
		Host:       address,
		Header: http.Header{
			PROXY_HOST_HEADER: []string{address},
		},
	}

	if d.auth != nil {
		req.Header.Set(PROXY_AUTHORIZATION_HEADER, d.auth())
	}

	rawreq, err := httputil.DumpRequest(req, false)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(rawreq)
	if err != nil {
		return nil, err
	}

	proxyResp, bconn, err := readResponse(conn, req)
	if err != nil {
		return nil, err
	}

	if proxyResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response from upstream proxy server: %s", proxyResp.Status)
	}

	conn.SetDeadline(time.Time{})
	ok = true
	return bconn, nil
}

func (d *ProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// readResponse reads the proxy's reply to a CONNECT request. It returns
// the response and a conn that must be used from now on: bytes the target
// sent right after the response headers may already sit in the read buffer,
// so they are replayed before further reads from the underlying conn.
func readResponse(conn net.Conn, req *http.Request) (*http.Response, net.Conn, error) {
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, nil, err
	}
	if br.Buffered() > 0 {
		return resp, &bufferedConn{Conn: conn, r: br}, nil
	}
	return resp, conn, nil
}

// bufferedConn is a net.Conn whose reads drain a bufio.Reader first
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

type FakeSNIDialer struct {
	caPool *x509.CertPool
	next   ContextDialer
	sni    string
}

func NewFakeSNIDialer(caPool *x509.CertPool, sni string, nextDialer ContextDialer) *FakeSNIDialer {
	return &FakeSNIDialer{
		caPool: caPool,
		next:   nextDialer,
		sni:    sni,
	}
}

func (d *FakeSNIDialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.next.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	name, _, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         d.sni,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				DNSName:       name,
				Intermediates: x509.NewCertPool(),
				Roots:         d.caPool,
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificates presented")
			}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
	return tls.Client(conn, tlsConfig), nil
}
