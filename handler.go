package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const BAD_REQ_MSG = "Bad Request\n"

type AuthProvider func() string

type ProxyHandler struct {
	logger       *CondLogger
	dialer       ContextDialer
	resolver     HostResolver
	ipPreference IPPreference
}

func NewProxyHandler(dialer ContextDialer, resolver HostResolver, pref IPPreference, logger *CondLogger) *ProxyHandler {
	return &ProxyHandler{
		logger:       logger,
		dialer:       dialer,
		resolver:     resolver,
		ipPreference: pref,
	}
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request) {
	host, port, err := splitAuthority(req.RequestURI, "443")
	if err != nil {
		s.logger.Error("Can't parse CONNECT request URI %q: %v", req.RequestURI, err)
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}

	conn, err := s.dialResolved(req.Context(), host, port)
	if err != nil {
		s.logger.Error("Can't satisfy CONNECT request: %v", err)
		http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
		return
	}
	defer conn.Close()
	closeOnDone(req.Context(), conn)

	if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
		localconn, _, err := hijack(wr)
		if err != nil {
			s.logger.Error("Can't hijack client connection: %v", err)
			http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
			return
		}
		defer localconn.Close()

		fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)
		proxy(req.Context(), localconn, conn)
		return
	}

	if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		proxyh2(req.Context(), req.Body, wr, conn)
		return
	}

	s.logger.Error("Unsupported protocol version: %s", req.Proto)
	http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request) {
	host, port, err := deriveHTTPDestination(req)
	if err != nil {
		s.logger.Error("Bad request destination: %v", err)
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}

	conn, err := s.dialResolved(req.Context(), host, port)
	if err != nil {
		s.logger.Error("HTTP tunnel dial error: %v", err)
		http.Error(wr, "Server Error", http.StatusBadGateway)
		return
	}
	defer conn.Close()
	closeOnDone(req.Context(), conn)

	outReq := req.Clone(req.Context())
	if outReq.URL != nil {
		clone := *outReq.URL
		clone.Scheme = ""
		clone.Host = ""
		outReq.URL = &clone
	}
	outReq.RequestURI = ""
	outReq.Close = true
	if outReq.Body == nil {
		outReq.Body = http.NoBody
	}
	if outReq.Host == "" {
		outReq.Host = host
	}

	if err := outReq.Write(conn); err != nil {
		s.logger.Error("HTTP forward write error: %v", err)
		http.Error(wr, "Server Error", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), outReq)
	if err != nil {
		s.logger.Error("HTTP forward read error: %v", err)
		http.Error(wr, "Server Error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	s.logger.Info("%v %v %v %v", req.RemoteAddr, req.Method, req.URL, resp.Status)
	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	flush(wr)
	copyBody(wr, resp.Body)
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v %v", req.RemoteAddr, req.Proto, req.Method, req.URL)

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || (req.URL.Scheme == "" && !isConnect)) && req.ProtoMajor < 2 ||
		(req.Host == "" && req.ProtoMajor == 2) {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}

	delHopHeaders(req.Header)
	if isConnect {
		s.HandleTunnel(wr, req)
		return
	}

	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
	}

	s.HandleRequest(wr, req)
}

func (s *ProxyHandler) dialResolved(ctx context.Context, host, port string) (net.Conn, error) {
	addr, err := s.resolver.ResolveHost(ctx, host, s.ipPreference)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(addr.String(), port)
	s.logger.Debug("dialResolved: %s => %s", host, target)
	return s.dialer.DialContext(ctx, "tcp", target)
}

func deriveHTTPDestination(req *http.Request) (string, string, error) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		return "", "", errors.New("missing host")
	}

	scheme := strings.ToLower(req.URL.Scheme)
	defaultPort := "80"
	if scheme == "https" {
		defaultPort = "443"
	}

	return splitAuthority(host, defaultPort)
}

func splitAuthority(authority, defaultPort string) (string, string, error) {
	if authority == "" {
		return "", "", errors.New("empty authority")
	}

	if strings.HasPrefix(authority, "[") {
		host, port, err := net.SplitHostPort(authority)
		if err == nil {
			return host, port, nil
		}
		if isMissingPortError(err) {
			return strings.Trim(authority, "[]"), defaultPort, nil
		}
		return "", "", err
	}

	if strings.Contains(authority, ":") {
		host, port, err := net.SplitHostPort(authority)
		if err == nil {
			return host, port, nil
		}
		if isMissingPortError(err) {
			return authority, defaultPort, nil
		}
		return "", "", err
	}

	return authority, defaultPort, nil
}

func isMissingPortError(err error) bool {
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return strings.Contains(addrErr.Error(), "missing port in address")
	}
	return false
}

func closeOnDone(ctx context.Context, conn net.Conn) {
	if ctx == nil {
		return
	}

	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		}
	}()
}
