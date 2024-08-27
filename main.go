package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/customeros/mailwatcher/blscan"
	"github.com/customeros/mailwatcher/internal/blacklists"
)

func main() {
	flag.Parse()
	args := flag.Args()

	bl, err := blacklists.ReadBlacklistConfig("./internal/blacklists/blacklists.toml")
	if err != nil {
		log.Println("Cannot find blacklists.toml")
		os.Exit(1)
	}

	blcount := 0
	results := make(map[string]bool)

	if net.ParseIP(args[0]) == nil {
		blcount, results = blscan.ScanDomainBlacklists(args[0], bl)
	} else {
		fmt.Println("IP blacklist to be implemented")
	}

	fmt.Printf("%s found on %v blacklists...\n", args[0], blcount)
	jsonData, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(jsonData))
}
