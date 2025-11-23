package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type recordingResolver struct {
	ip    netip.Addr
	mu    sync.Mutex
	hosts []string
}

func (r *recordingResolver) ResolveHost(ctx context.Context, host string, pref IPPreference) (netip.Addr, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, host)
	r.mu.Unlock()
	return r.ip, nil
}

type recordingDialer struct {
	mu     sync.Mutex
	dialed []string
}

func (d *recordingDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("non-ip host dialed: %s", host)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func newTestProxyHandler(dialer ContextDialer, resolver HostResolver) *ProxyHandler {
	logger := NewCondLogger(log.New(io.Discard, "TEST PROXY: ", 0), 50)
	return NewProxyHandler(dialer, resolver, IPPreferenceIPv4First, logger)
}

func TestProxyHandlerHTTPViaCONNECT(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("failed to parse backend url: %v", err)
	}

	host, port, err := net.SplitHostPort(backendURL.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	resolver := &recordingResolver{ip: netip.MustParseAddr(host)}
	dialer := &recordingDialer{}
	handler := newTestProxyHandler(dialer, resolver)

	clientHost := "example.local:" + port
	req := httptest.NewRequest(http.MethodGet, "http://"+clientHost+"/test", nil)
	req.Host = clientHost
	req.URL.Scheme = "http"
	req.URL.Host = clientHost
	req.RequestURI = "http://" + clientHost + "/test"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Fatalf("unexpected body %q", rr.Body.String())
	}

	if len(resolver.hosts) != 1 || resolver.hosts[0] != "example.local" {
		t.Fatalf("resolver was not invoked correctly: %#v", resolver.hosts)
	}
	if len(dialer.dialed) == 0 {
		t.Fatalf("dialer was not used")
	}
	dialHost, dialPort, err := net.SplitHostPort(dialer.dialed[0])
	if err != nil {
		t.Fatalf("invalid dialed address: %v", err)
	}
	if dialHost != host || dialPort != port {
		t.Fatalf("unexpected dial target %s:%s", dialHost, dialPort)
	}
}

func TestProxyHandlerCONNECTTunnel(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer backend.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		conn.Write([]byte(strings.ToUpper(string(buf))))
	}()

	host, port, _ := net.SplitHostPort(backend.Addr().String())
	resolver := &recordingResolver{ip: netip.MustParseAddr(host)}
	dialer := &recordingDialer{}
	handler := newTestProxyHandler(dialer, resolver)
	server := httptest.NewServer(handler)
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT secure.example:%s HTTP/1.1\r\nHost: secure.example:%s\r\n\r\n", port, port)
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("unexpected response line %q", line)
	}
	// drain headers
	for {
		l, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading headers: %v", err)
		}
		if l == "\r\n" {
			break
		}
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(reader, resp); err != nil {
		t.Fatalf("failed to read payload: %v", err)
	}
	if string(resp) != "PING" {
		t.Fatalf("unexpected payload %q", string(resp))
	}

	wg.Wait()
}
