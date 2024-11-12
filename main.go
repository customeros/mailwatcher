package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/customeros/mailwatcher/blscan"
	"github.com/customeros/mailwatcher/dmarkstats"
)

var version string = "dev"

func main() {
	flag.Parse()
	args := flag.Args()

	if args[0] == "version" {
		fmt.Printf("MailWatcher %s\n", version)
		return
	}

	if args[0] == "stats" {
		file, err := os.Open(args[1])
		if err != nil {
			panic(err)
		}
		defer file.Close()

		report, err := dmarcstats.AnalyzeDMARCReport(file)
		if err != nil {
			panic(err)
		}

		// Print as JSON
		json, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(json))
		return
	}

	fmt.Println("Searching known blacklists for", args[0])

	listType := blscan.DomainOrIp(args[0])
	results := blscan.ScanBlacklists(args[0], listType)

	jsonData, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(jsonData))
}
