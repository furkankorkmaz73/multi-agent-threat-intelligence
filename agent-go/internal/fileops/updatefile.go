package fileops

import (
	"context"
	"os"
	"sync"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/db"
	"github.com/furkankorkmaz309/threat-agent/internal/fetch"
)

func Update(CVEApiKey string) error {
	mongoURI := os.Getenv("MONGO_URI")
	client, err := db.InitDB(mongoURI)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.Background())

	appInstance := &app.App{
		MongoClient: client,
		Database:    "threat_intel",
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if err := fetch.FetchDread(appInstance); err != nil {
			appInstance.LogJSON("ERROR", "dread", err.Error())
		}
	}()

	go func() {
		defer wg.Done()
		appInstance.LogJSON("INFO", "cve", "Starting CVE sync")
		data, err := fetch.FetchCVE(appInstance, CVEApiKey)
		if err != nil {
			appInstance.LogJSON("ERROR", "cve", err.Error())
			return
		}
		if err := db.SaveCVEMany(appInstance, data.Vulnerabilities); err != nil {
			appInstance.LogJSON("ERROR", "db", err.Error())
		}
	}()

	go func() {
		defer wg.Done()
		appInstance.LogJSON("INFO", "urlhaus", "Starting URLHaus sync")
		data, err := fetch.FetchURLHaus(appInstance)
		if err != nil {
			appInstance.LogJSON("ERROR", "urlhaus", err.Error())
			return
		}
		if err := db.SaveURLhausMany(appInstance, data); err != nil {
			appInstance.LogJSON("ERROR", "db", err.Error())
		}
	}()

	wg.Wait()
	return nil
}
