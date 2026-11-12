package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// fakeProxy accepts one CONNECT, answers 200 and immediately sends a
// server-first banner in the same write, like an SMTP/SSH target would.
func fakeProxy(t *testing.T, status string, wantAuth string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		if req.Method != "CONNECT" || req.Header.Get("Proxy-Authorization") != wantAuth {
			io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
			return
		}
		io.WriteString(c, "HTTP/1.1 "+status+"\r\n\r\nBANNER\n")
		io.Copy(io.Discard, c)
	}()
	return l.Addr().String()
}

func TestProxyDialerKeepsBytesAfterHeaders(t *testing.T) {
	auth := basic_auth_header("u", "p")
	addr := fakeProxy(t, "200 OK", auth)
	d := NewProxyDialer(addr, "", "", func() string { return auth }, nil, &net.Dialer{})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "example.com:25")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "BANNER\n" {
		t.Fatalf("got %q, %v", line, err)
	}
}

func TestProxyDialerRejectsNon200(t *testing.T) {
	addr := fakeProxy(t, "200 OK", "expected")
	d := NewProxyDialer(addr, "", "", func() string { return "wrong" }, nil, &net.Dialer{})
	if _, err := d.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected error on 407")
	}
}

func TestProxyDialerHonoursContextDeadline(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(io.Discard, c) // never answers
		}
	}()
	d := NewProxyDialer(l.Addr().String(), "", "", nil, nil, &net.Dialer{})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("dial did not respect context deadline")
	}
}
