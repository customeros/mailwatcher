package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/customeros/mailwatcher/blscan"
)

var version string = "dev"

func main() {
	flag.Parse()
	args := flag.Args()

	if args[0] == "version" {
		fmt.Printf("MailWatcher %s\n", version)
		return
	}

	fmt.Println("Searching known blacklists for", args[0])

	listType := blscan.DomainOrIp(args[0])
	results := blscan.ScanBlacklists(args[0], listType)

	jsonData, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(jsonData))
}
