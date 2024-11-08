package blscan

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/customeros/mailwatcher/domainage"
	"github.com/customeros/mailwatcher/internal/blacklists"
	"github.com/customeros/mailwatcher/internal/querydns"
)

type BlacklistResults struct {
	DomainAge     int
	MajorLists    int
	MinorLists    int
	SpamTrapLists int
}

func ScanBlacklists(lookupValue, listType string) *BlacklistResults {
	var results *BlacklistResults
	var err error

	switch listType {
	case "domain":
		results, err = scanDomainBlacklist(lookupValue)
	default:
		results, err = scanIpBlacklist(lookupValue, listType)
	}

	if err != nil {
		log.Printf("Scan error: %s", err)
		// Return empty results instead of nil if there's an error
		return &BlacklistResults{}
	}

	return results
}

func DomainOrIp(lookupValue string) string {
	ip := net.ParseIP(lookupValue)
	if ip == nil {
		return "domain"
	} else if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func scanIpBlacklist(ipAddress, listType string) (*BlacklistResults, error) {
	// Initialize results struct
	results := &BlacklistResults{}

	blacklist, err := blacklists.ReadBlacklistConfig("ip")
	if err != nil {
		return nil, fmt.Errorf("failed to read blacklist config: %w", err)
	}

	foundProvider := false
	for _, provider := range blacklist {
		list := provider.IPLists
		if len(list) == 0 {
			continue
		}
		foundProvider = true

		for _, bl := range list {
			// Skip IPv6 lists for now
			if listType == "ipv6" {
				continue
			}

			if bl.Type != listType {
				continue
			}

			listUrl := getBlacklistUrl(provider.Name, bl.Name, bl.URL)
			if listUrl == "" {
				continue
			}

			ip := net.ParseIP(ipAddress)
			if ip == nil {
				log.Printf("Invalid IP address: %s", ipAddress)
				continue
			}

			reversedIp, err := reverseIP(ip)
			if err != nil {
				log.Printf("Failed to reverse IP %s: %v", ipAddress, err)
				continue
			}

			query := fmt.Sprintf("%s.%s", reversedIp, listUrl)
			a, err := querydns.GetARecords(query)
			if err != nil {
				if !strings.Contains(err.Error(), "no such host") {
					log.Printf("DNS query error for %s: %v", query, err)
				}
				continue
			}

			if len(a) == 0 {
				continue
			}

			// Increment minor lists counter when found in blacklist
			results.MinorLists++
		}
	}

	// If no providers were found at all, return nil
	if !foundProvider {
		return nil, nil
	}

	return results, nil
}

func scanDomainBlacklist(domain string) (*BlacklistResults, error) {
	blacklist, err := blacklists.ReadBlacklistConfig("domain")
	if err != nil {
		return nil, fmt.Errorf("failed to read blacklist config: %w", err)
	}

	// Initialize results struct
	results := &BlacklistResults{}

	foundProvider := false
	for _, provider := range blacklist {
		list := provider.DomainLists
		if len(list) == 0 {
			continue
		}
		foundProvider = true

		for _, bl := range list {
			listUrl := getBlacklistUrl(provider.Name, bl.Name, bl.URL)
			if listUrl == "" {
				continue
			}

			query := fmt.Sprintf("%s.%s", domain, listUrl)
			a, err := querydns.GetARecords(query)
			if err != nil {
				log.Printf("DNS query failed for %s: %v", query, err)
				continue
			}

			if len(a) == 0 {
				continue
			}

			switch bl.Type {
			case "age":
				switch bl.Name {
				case "SEM Fresh Domain List":
					results.DomainAge = 5
				case "sem Fresh10 domain list":
					results.DomainAge = 10
				case "sem Fresh15 domain list":
					results.DomainAge = 15
				case "sem Fresh30 domain list":
					results.DomainAge = 30
				default:
					results.DomainAge = 1
				}
			case "major":
				results.MajorLists++
			case "minor":
				results.MinorLists++
			case "spam":
				results.SpamTrapLists++
			}
		}
	}

	// If no providers were found at all, return nil
	if !foundProvider {
		return nil, nil
	}

	// Check domain age if not set by blacklists
	if results.DomainAge == 0 {
		age, err := domainage.GetDomainDates(domain)
		if err != nil {
			log.Printf("Failed to get domain age for %s: %v", domain, err)
			// Return results even if age lookup fails
			return results, nil
		}
		results.DomainAge = age.CreationAge
	}

	return results, nil
}

func getBlacklistUrl(providerName, listName, listUrl string) string {
	switch {
	case providerName == "Abusix Mail Intelligence" && listName == "Abusix Domain Blacklist":
		return os.Getenv("ABUSIX_DOMAIN_BLACKLIST")
	case providerName == "Abusix Mail Intelligence" && listName == "Abusix Newly Observed Domains List":
		return os.Getenv("ABUSIX_NEWLY_OBSERVED_DOMAINS_LIST")
	default:
		return listUrl
	}
}

func reverseIP(ip net.IP) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("invalid IP address")
	}

	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0]), nil
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return "", fmt.Errorf("invalid IPv6 address")
	}

	var reversed []string
	for i := len(ip6) - 1; i >= 0; i-- {
		reversed = append(reversed, fmt.Sprintf("%02x", ip6[i]))
	}

	return strings.Join(reversed, "."), nil
}

