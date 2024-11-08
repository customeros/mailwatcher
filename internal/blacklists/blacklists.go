package blacklists

import (
	"embed"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed domainLists.toml
var domainListFile embed.FS

//go:embed ipLists.toml
var ipListFile embed.FS

// BlacklistProvider represents a single blacklist provider
type BlacklistProvider struct {
	Name        string     `toml:"name"`
	Website     string     `toml:"website"`
	Lookup      string     `toml:"lookup"`
	DomainLists []ListInfo `toml:"domain_lists"`
	IPLists     []ListInfo `toml:"ip_lists"`
}

// ListInfo represents information about a specific blacklist
type ListInfo struct {
	Name string `toml:"name"`
	URL  string `toml:"url"`
	Type string `toml:"type"`
}

// Blacklist is a custom type that allows for direct access to providers
type Blacklist map[string]*BlacklistProvider

// ReadConfig reads and parses the TOML config file
func ReadBlacklistConfig(listType string) (Blacklist, error) {
	var config Blacklist
	var content []byte
	var err error

	// Read the file
	switch listType {
	case "domain":
		content, err = domainListFile.ReadFile("domainLists.toml")
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}
	case "ip":
		content, err = ipListFile.ReadFile("ipLists.toml")
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}
	default:
		return nil, fmt.Errorf("listType must be domain or ip")
	}

	// Decode the TOML data
	if _, err := toml.Decode(string(content), &config); err != nil {
		return nil, fmt.Errorf("error decoding TOML: %w", err)
	}

	// Convert keys to lowercase for case-insensitive access
	lowercaseConfig := make(Blacklist)
	for k, v := range config {
		lowercaseConfig[strings.ToLower(k)] = v
	}

	return lowercaseConfig, nil
}
