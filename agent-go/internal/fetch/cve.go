package fetch

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
)

func FetchCVE(appInstance *app.App, apiKey string, mode string, days int) (*models.CVEList, error) {
	now := time.Now().UTC()
	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	client := &http.Client{Timeout: 45 * time.Second}

	// Optional safety cap. Set NVD_MAX_FETCH=0 to fetch the full matching set.
	maxFetch := 0
	if raw := os.Getenv("NVD_MAX_FETCH"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			maxFetch = parsed
		}
	}
	resultsPerPage := 2000
	if maxFetch > 0 && maxFetch < resultsPerPage {
		resultsPerPage = maxFetch
	}

	params := url.Values{}
	params.Set("resultsPerPage", strconv.Itoa(resultsPerPage))

	switch mode {
	case "full":
		// full mode: no date filter; optional cap still applies if NVD_MAX_FETCH > 0
	case "incremental":
		if days <= 0 {
			days = 2
		}
		startTime := now.Add(-time.Duration(days) * 24 * time.Hour).Format("2006-01-02T15:04:05.000")
		endTime := now.Format("2006-01-02T15:04:05.000")
		params.Set("lastModStartDate", startTime)
		params.Set("lastModEndDate", endTime)
	default:
		return nil, fmt.Errorf("invalid mode: %s (use 'incremental' or 'full')", mode)
	}

	aggregated := &models.CVEList{}
	startIndex := 0

	for {
		params.Set("startIndex", strconv.Itoa(startIndex))
		finalURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

		req, err := http.NewRequest("GET", finalURL, nil)
		if err != nil {
			return nil, err
		}

		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err := doRequestWithRetry(client, req, 3, 2*time.Second)
		if err != nil {
			return nil, fmt.Errorf("nvd request failed: %w", err)
		}

		var page models.CVEList
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		if aggregated.TotalResults == 0 {
			aggregated.TotalResults = page.TotalResults
			aggregated.ResultsPerPage = page.ResultsPerPage
		}

		aggregated.Vulnerabilities = append(aggregated.Vulnerabilities, page.Vulnerabilities...)

		if maxFetch > 0 && len(aggregated.Vulnerabilities) >= maxFetch {
			aggregated.Vulnerabilities = aggregated.Vulnerabilities[:maxFetch]
			aggregated.StartIndex = 0
			break
		}

		startIndex += len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || startIndex >= page.TotalResults {
			aggregated.StartIndex = 0
			break
		}
	}

	appInstance.LogJSON("INFO", "cve", fmt.Sprintf("Fetched %d CVEs from NVD", len(aggregated.Vulnerabilities)))
	return aggregated, nil
}