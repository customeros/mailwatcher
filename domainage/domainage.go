package domainage

import (
	"fmt"
	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
	"net"
	"strings"
	"time"
)

type DomainDates struct {
	CreationAge int    // Age since first creation in days
	UpdateAge   int    // Age since last update in days
	CreatedDate string // Original creation date string
	UpdatedDate string // Last updated date string
}

func GetDomainDates(domain string) (*DomainDates, error) {
	if !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("invalid domain format")
	}

	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	_, err := net.LookupHost(domain)
	if err != nil {
		return nil, fmt.Errorf("domain does not resolve: %v", err)
	}

	result, err := whois.Whois(domain)
	if err != nil {
		return nil, fmt.Errorf("error querying WHOIS: %v", err)
	}

	parsed, err := whoisparser.Parse(result)
	if err != nil {
		return nil, fmt.Errorf("error parsing WHOIS data: %v", err)
	}

	dates := &DomainDates{
		CreatedDate: parsed.Domain.CreatedDate,
		UpdatedDate: parsed.Domain.UpdatedDate,
	}

	// Parse dates using multiple formats
	formats := []string{
		time.RFC3339,
		"2006-01-02",
		"2006-01-02T15:04:05Z",
		"02-Jan-2006",
		"2006-01-02 15:04:05",
	}

	// Parse creation date
	var createdTime time.Time
	for _, format := range formats {
		if t, err := time.Parse(format, dates.CreatedDate); err == nil {
			createdTime = t
			break
		}
	}
	if !createdTime.IsZero() {
		dates.CreationAge = int(time.Since(createdTime).Hours() / 24)
	}

	// Parse update date
	var updatedTime time.Time
	for _, format := range formats {
		if t, err := time.Parse(format, dates.UpdatedDate); err == nil {
			updatedTime = t
			break
		}
	}
	if !updatedTime.IsZero() {
		dates.UpdateAge = int(time.Since(updatedTime).Hours() / 24)
	}

	return dates, nil
}
