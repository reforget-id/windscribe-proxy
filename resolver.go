package main

import "strings"

const (
	DOT                  = 0x2e
	DNS_CACHE_SIZE_LIMIT = 1024
)

func absDomain(domain string) string {
	if domain == "" {
		return ""
	}
	if domain[len(domain)-1] != DOT {
		domain = domain + "."
	}
	return strings.ToLower(domain)
}
