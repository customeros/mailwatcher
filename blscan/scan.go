package blscan

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/customeros/mailwatcher/internal/blacklists"
	"github.com/customeros/mailwatcher/internal/querydns"
)

func ScanBlacklists(lookupValue string, blacklist blacklists.Blacklist) (int, map[string]bool) {
	listType := domainOrIp(lookupValue)

	switch listType {
	case "domain":
		return scanDomainBlacklist(lookupValue, blacklist)
	default:
		return scanIpBlacklist(lookupValue, listType, blacklist)
	}
}

func scanIpBlacklist(ipAddress string, listType string, blacklist blacklists.Blacklist) (int, map[string]bool) {
	results := make(map[string]bool)
	count := 0
	for _, provider := range blacklist {
		list := provider.IPLists
		if len(list) > 0 {
			for _, bl := range list {
				if bl.Type == listType {
					listed := false
					listUrl := getBlacklistUrl(provider.Name, bl.Name, bl.URL)
					if listUrl == "" {
						continue
					}
					ip := net.ParseIP(ipAddress)
					if ip == nil {
						log.Printf("Invalid IP address: %s", ipAddress)
						continue
					}
					var query string
					if listType == "ipv4" {
						reversedIp, err := reverseIP(ip)
						if err != nil {
							log.Println(err)
							continue
						}
						query = fmt.Sprintf("%s.%s", reversedIp, listUrl)
					} else {
						fmt.Println("IPv6 to be implemented...")
						continue
					}
					a, err := querydns.GetARecords(query)
					if err != nil {
						continue
					}
					if len(a) > 0 {
						listed = true
						count++
					}
					results[bl.Name] = listed
				}
			}
		}
	}
	return count, results
}

func scanDomainBlacklist(domain string, blacklist blacklists.Blacklist) (int, map[string]bool) {
	results := make(map[string]bool)
	count := 0

	for _, provider := range blacklist {
		list := provider.DomainLists
		if len(list) > 0 {
			for _, bl := range list {
				listUrl := getBlacklistUrl(provider.Name, bl.Name, bl.URL)
				if listUrl != "" {
					listed := false
					query := fmt.Sprintf("%s.%s", domain, listUrl)
					a, _ := querydns.GetARecords(query)
					if len(a) > 0 {
						listed = true
						count++
					}
					results[bl.Name] = listed
				}
			}
		}
	}
	return count, results
}

func getBlacklistUrl(providerName, listName, listUrl string) string {
	if providerName == "Abusix Mail Intelligence" && listName == "Abusix Domain Blacklist" {
		return os.Getenv("ABUSIX_DOMAIN_BLACKLIST")
	}

	if providerName == "Abusix Mail Intelligence" && listName == "Abusix Newly Observed Domains List" {
		return os.Getenv("ABUSIX_NEWLY_OBSERVED_DOMAINS_LIST")
	}

	return listUrl
}

func domainOrIp(lookupValue string) string {
	ip := net.ParseIP(lookupValue)
	if ip == nil {
		return "domain"
	} else if ip.To4() != nil {
		return "ipv4"
	} else {
		return "ipv6"
	}
}

func reverseIP(ip net.IP) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("invalid IP address")
	}

	// Check if it's an IPv4 address
	if ip4 := ip.To4(); ip4 != nil {
		// Reverse the octets
		return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0]), nil
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return "", fmt.Errorf("invalid IPv6 address")
	}

	// Reverse the hex representation
	var reversed []string
	for i := len(ip6) - 1; i >= 0; i-- {
		reversed = append(reversed, fmt.Sprintf("%02x", ip6[i]))
	}

	// Join with dots
	return strings.Join(reversed, "."), nil
}
