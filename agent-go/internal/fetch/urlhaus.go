package fetch

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
)

func FetchURLHaus(appInstance *app.App) ([]models.URLhausResponse, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	url := "https://urlhaus.abuse.ch/downloads/json_recent/"

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rawData map[string][]models.URLhausResponse
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, err
	}

	var allURLs []models.URLhausResponse
	for _, list := range rawData {
		allURLs = append(allURLs, list...)
	}

	return allURLs, nil
}
