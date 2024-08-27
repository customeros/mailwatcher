package blacklists

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

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
func ReadBlacklistConfig(filename string) (Blacklist, error) {
	var config Blacklist

	// Read the file
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
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
