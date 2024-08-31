package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/customeros/mailwatcher/blscan"
	"github.com/customeros/mailwatcher/internal/blacklists"
)

func main() {
	flag.Parse()
	args := flag.Args()
	version := "dev"

	if args[0] == "version" {
		fmt.Printf("MailWatcher %s\n", version)
		return
	}

	bl, err := blacklists.ReadBlacklistConfig()
	if err != nil {
		log.Println("Cannot find blacklists.toml")
		os.Exit(1)
	}

	blcount, results := blscan.ScanBlacklists(args[0], bl)

	fmt.Printf("%s found on %v blacklists...\n", args[0], blcount)
	jsonData, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(jsonData))
}
