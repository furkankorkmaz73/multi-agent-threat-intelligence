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
	limit := flag.Int("limit", 20, "limit records")
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
		data, err := fetch.FetchCVE(appInstance, os.Getenv("CVE_KEY"))
		if err != nil {
			fmt.Printf("[ERROR] CVE: %v\n", err)
			os.Exit(2)
		}
		toSave := data.Vulnerabilities
		if len(toSave) > *limit {
			toSave = toSave[:*limit]
		}
		_ = db.SaveCVEMany(appInstance, toSave)
		fmt.Printf("[SUCCESS] Saved %d CVE records\n", len(toSave))

	case "urlhaus":
		data, err := fetch.FetchURLHaus(appInstance)
		if err != nil {
			fmt.Printf("[ERROR] URLhaus: %v\n", err)
			os.Exit(2)
		}
		if len(data) > *limit {
			data = data[:*limit]
		}
		_ = db.SaveURLhausMany(appInstance, data)
		fmt.Printf("[SUCCESS] Saved %d URLhaus records\n", len(data))

	case "dread":
		if err := fetch.FetchDread(appInstance); err != nil {
			fmt.Printf("[ERROR] Dread: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("[SUCCESS] Dread completed")
	}
}
