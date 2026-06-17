package fetch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
)

func FetchURLHaus(appInstance *app.App) ([]models.URLhausResponse, error) {
	started := time.Now()
	client := &http.Client{Timeout: 60 * time.Second}
	url := "https://urlhaus.abuse.ch/downloads/json_recent/"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequestWithRetry(client, req, 3, 1500*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("urlhaus request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var wrapped map[string][]models.URLhausResponse
	if err := json.Unmarshal(body, &wrapped); err == nil && len(wrapped) > 0 {
		var allURLs []models.URLhausResponse
		for _, list := range wrapped {
			allURLs = append(allURLs, list...)
		}
		elapsed := time.Since(started)
		appInstance.LogJSON("INFO", "urlhaus", fmt.Sprintf("source=urlhaus fetched=%d elapsed=%.3fs records_per_sec=%.1f", len(allURLs), elapsed.Seconds(), recordsPerSecond(len(allURLs), elapsed)))
		return allURLs, nil
	}

	var flat []models.URLhausResponse
	if err := json.Unmarshal(body, &flat); err != nil {
		return nil, err
	}
	elapsed := time.Since(started)
	appInstance.LogJSON("INFO", "urlhaus", fmt.Sprintf("source=urlhaus fetched=%d elapsed=%.3fs records_per_sec=%.1f", len(flat), elapsed.Seconds(), recordsPerSecond(len(flat), elapsed)))
	return flat, nil
}
