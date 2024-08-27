package querydns

import (
	"fmt"
	"net"
)

func GetARecords(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("error looking up IP addresses: %w", err)
	}

	var aRecords []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			aRecords = append(aRecords, ipv4.String())
		}
	}

	return aRecords, nil
}
