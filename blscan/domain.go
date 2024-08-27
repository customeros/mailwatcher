package blscan

import (
	"fmt"
	"os"

	"github.com/customeros/mailwatcher/internal/blacklists"
	"github.com/customeros/mailwatcher/internal/querydns"
)

func ScanDomainBlacklists(domain string, blacklist blacklists.Blacklist) (int, map[string]bool) {
	results := make(map[string]bool)
	count := 0
	for _, provider := range blacklist {
		if len(provider.DomainLists) > 0 {
			for _, list := range provider.DomainLists {

				if provider.Name == "Abusix Mail Intelligence" && list.Name == "Abusix Domain Blacklist" {
					list.URL = os.Getenv("ABUSIX_DOMAIN_BLACKLIST")
				}

				if provider.Name == "Abusix Mail Intelligence" && list.Name == "Abusix Newly Observed Domains List" {
					list.URL = os.Getenv("ABUSIX_NEWLY_OBSERVED_DOMAINS_LIST")
				}

				if list.URL != "" {
					listed := false
					query := fmt.Sprintf("%s.%s", domain, list.URL)
					a, _ := querydns.GetARecords(query)
					if len(a) > 0 {
						listed = true
					}
					results[list.Name] = listed
					if listed == true {
						count += 1
					}
				}

			}
		}
	}
	return count, results
}
