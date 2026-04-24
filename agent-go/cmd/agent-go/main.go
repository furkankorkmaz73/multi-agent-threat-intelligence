package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/db"
	"github.com/furkankorkmaz309/threat-agent/internal/fetch"
	"github.com/joho/godotenv"
)

func main() {
	source := flag.String("source", "", "cve, urlhaus, dread")
	limit := flag.Int("limit", 20, "limit records to save (0 = no limit)")
	mode := flag.String("mode", "incremental", "cve fetch mode: incremental or full")
	days := flag.Int("days", 2, "how many days back to fetch in incremental mode")
	flag.Parse()

	appInstance := app.New()

	_ = godotenv.Load("../../../.env")
	db.Init(appInstance)

	if *source == "" {
		fmt.Println("[ERROR] Missing -source parameter")
		os.Exit(1)
	}

	fmt.Printf("[START] Processing: %s (Limit: %d)\n", *source, *limit)

	switch *source {
	case "cve":
		var (
			data interface{}
			err  error
		)

		cveData, fetchErr := fetch.FetchCVE(appInstance, os.Getenv("CVE_KEY"), *mode, *days)
		if fetchErr != nil {
			fmt.Printf("[ERROR] CVE: %v\n", fetchErr)
			os.Exit(2)
		}

		toSave := cveData.Vulnerabilities
		if *limit > 0 && len(toSave) > *limit {
			toSave = toSave[:*limit]
		}

		if err = db.SaveCVEMany(appInstance, toSave); err != nil {
			fmt.Printf("[ERROR] Save CVE: %v\n", err)
			os.Exit(3)
		}

		_ = data
		fmt.Printf("[SUCCESS] Saved %d CVE records\n", len(toSave))

	case "urlhaus":
		data, err := fetch.FetchURLHaus(appInstance)
		if err != nil {
			fmt.Printf("[ERROR] URLhaus: %v\n", err)
			os.Exit(2)
		}
		if *limit > 0 && len(data) > *limit {
			data = data[:*limit]
		}
		if err := db.SaveURLhausMany(appInstance, data); err != nil {
			fmt.Printf("[ERROR] Save URLhaus: %v\n", err)
			os.Exit(3)
		}
		fmt.Printf("[SUCCESS] Saved %d URLhaus records\n", len(data))

	case "dread":
		if err := fetch.FetchDread(appInstance); err != nil {
			fmt.Printf("[ERROR] Dread: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("[SUCCESS] Dread completed")

	default:
		fmt.Printf("[ERROR] Unknown source: %s\n", *source)
		os.Exit(1)
	}
}