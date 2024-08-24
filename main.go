package main

import (
	"fmt"
	"net"
)

func queryARecords(domain string) ([]string, error) {
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

func main() {
	domain := "sergnese.it.uribl.abuse.ro"
	records, err := queryARecords(domain)
	if err != nil {
		fmt.Printf("Error querying A records: %v\n", err)
		return
	}

	fmt.Printf("A records for %s:\n", domain)
	for _, record := range records {
		fmt.Println(record)
	}
}
