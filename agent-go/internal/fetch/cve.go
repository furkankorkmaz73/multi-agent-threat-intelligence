package fetch

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
)

func FetchCVE(appInstance *app.App, apiKey string) (*models.CVEList, error) {
	now := time.Now()
	startTime := now.Add(-48 * time.Hour).Format("2006-01-02T15:04:05.000")
	endTime := now.Format("2006-01-02T15:04:05.000")

	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	url := fmt.Sprintf("%s?lastModStartDate=%s&lastModEndDate=%s", baseURL, startTime, endTime)

	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data models.CVEList
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return &data, nil
}
