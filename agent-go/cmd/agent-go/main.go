package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/db"
	"github.com/furkankorkmaz309/threat-agent/internal/fetch"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
	"github.com/joho/godotenv"
)

func loadEnvFiles() {
	if envFile := strings.TrimSpace(os.Getenv("ENV_FILE")); envFile != "" {
		_ = godotenv.Load(envFile)
		return
	}
	_ = godotenv.Load(".env", "../.env", "../../.env", "../../../.env")
}

func main() {
	source := flag.String("source", "", "cve, urlhaus, dread")
	limit := flag.Int("limit", 20, "limit records to save (0 = no limit)")
	mode := flag.String("mode", "incremental", "cve fetch mode: incremental or full")
	days := flag.Int("days", 2, "how many days back to fetch in incremental mode")
	fixtureFile := flag.String("fixture-file", "", "optional local fixture JSON file for deterministic ingestion")
	flag.Parse()

	appInstance := app.New()

	loadEnvFiles()
	if err := db.Init(appInstance); err != nil {
		fmt.Printf("[ERROR] Database initialization failed: %v\n", err)
		os.Exit(2)
	}

	if *source == "" {
		fmt.Println("[ERROR] Missing -source parameter")
		os.Exit(1)
	}

	fmt.Printf("[START] Processing: %s (Limit: %d)\n", *source, *limit)

	switch *source {
	case "cve":
		var cveData *models.CVEList
		if strings.TrimSpace(*fixtureFile) != "" {
			loaded, loadErr := loadCVEFixture(*fixtureFile)
			if loadErr != nil {
				fmt.Printf("[ERROR] CVE fixture: %v\n", loadErr)
				os.Exit(2)
			}
			cveData = loaded
		} else {
			loaded, fetchErr := fetch.FetchCVE(appInstance, os.Getenv("CVE_KEY"), *mode, *days)
			if fetchErr != nil {
				fmt.Printf("[ERROR] CVE: %v\n", fetchErr)
				os.Exit(2)
			}
			cveData = loaded
		}

		toSave := cveData.Vulnerabilities
		if *limit > 0 && len(toSave) > *limit {
			toSave = toSave[:*limit]
		}

		if err := db.SaveCVEMany(appInstance, toSave); err != nil {
			fmt.Printf("[ERROR] Save CVE: %v\n", err)
			os.Exit(3)
		}

		fmt.Printf("[SUCCESS] Saved %d CVE records\n", len(toSave))

	case "urlhaus":
		var data []models.URLhausResponse
		if strings.TrimSpace(*fixtureFile) != "" {
			loaded, loadErr := loadURLhausFixture(*fixtureFile)
			if loadErr != nil {
				fmt.Printf("[ERROR] URLhaus fixture: %v\n", loadErr)
				os.Exit(2)
			}
			data = loaded
		} else {
			loaded, err := fetch.FetchURLHaus(appInstance)
			if err != nil {
				fmt.Printf("[ERROR] URLhaus: %v\n", err)
				os.Exit(2)
			}
			data = loaded
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

func loadCVEFixture(path string) (*models.CVEList, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wrapped models.CVEList
	if err := json.Unmarshal(payload, &wrapped); err == nil && len(wrapped.Vulnerabilities) > 0 {
		return &wrapped, nil
	}
	var vulnerabilities []struct {
		CVE models.CVE `json:"cve" bson:"cve"`
	}
	if err := json.Unmarshal(payload, &vulnerabilities); err != nil {
		return nil, err
	}
	return &models.CVEList{ResultsPerPage: len(vulnerabilities), TotalResults: len(vulnerabilities), Vulnerabilities: vulnerabilities}, nil
}

func loadURLhausFixture(path string) ([]models.URLhausResponse, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wrapped map[string][]models.URLhausResponse
	if err := json.Unmarshal(payload, &wrapped); err == nil && len(wrapped) > 0 {
		var rows []models.URLhausResponse
		for _, values := range wrapped {
			rows = append(rows, values...)
		}
		return rows, nil
	}
	var flat []models.URLhausResponse
	if err := json.Unmarshal(payload, &flat); err != nil {
		return nil, err
	}
	return flat, nil
}
