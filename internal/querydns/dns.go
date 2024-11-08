package querydns

import (
	"context"
	"fmt"
	"net"
	"time"
)

func GetARecords(domain string) ([]string, error) {
	// Create context with timeout to avoid hanging on slow DNS servers
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Use the resolver directly for more control
	resolver := &net.Resolver{
		PreferGo: true, // Use Go's built-in resolver
	}

	// LookupHost returns all IP addresses, both IPv4 and IPv6
	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		// Don't wrap "no such host" errors as they're expected for non-listed domains
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return []string{}, nil
		}
		return nil, fmt.Errorf("DNS lookup error: %w", err)
	}

	// Filter for IPv4 addresses only (A records)
	var aRecords []string
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			aRecords = append(aRecords, ip)
		}
	}

	return aRecords, nil
}
