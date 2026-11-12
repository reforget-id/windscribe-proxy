package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerConnectTunnel(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()

	srv := httptest.NewServer(NewProxyHandler(&net.Dialer{}, testLogger()))
	defer srv.Close()

	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr())
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("resp = %v, err = %v", resp, err)
	}
	io.WriteString(c, "ping\n")
	if line, _ := br.ReadString('\n'); line != "ping\n" {
		t.Fatalf("echo got %q", line)
	}
}

func TestHandlerPlainHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		io.WriteString(w, "hello")
	}))
	defer origin.Close()

	req, _ := http.NewRequest("GET", origin.URL, nil)
	req.RequestURI = origin.URL
	rec := httptest.NewRecorder()
	NewProxyHandler(&net.Dialer{}, testLogger()).ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "hello" {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHandlerUpstreamErrorIs502(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	req, _ := http.NewRequest("GET", "http://"+dead+"/", nil)
	rec := httptest.NewRecorder()
	NewProxyHandler(&net.Dialer{}, testLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestHandlerRejectsRelativeURL(t *testing.T) {
	req := httptest.NewRequest("GET", "/relative", nil)
	req.URL.Host = ""
	rec := httptest.NewRecorder()
	NewProxyHandler(&net.Dialer{}, testLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Bad Request") {
		t.Fatalf("code = %d", rec.Code)
	}
}
