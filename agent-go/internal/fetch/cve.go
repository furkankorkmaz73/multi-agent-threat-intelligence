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

var nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

func FetchCVE(appInstance *app.App, apiKey string, mode string, days int, fetchLimit ...int) (*models.CVEList, error) {
	now := time.Now().UTC()
	started := time.Now()
	client := &http.Client{Timeout: 45 * time.Second}

	maxFetch := 0
	if len(fetchLimit) > 0 {
		maxFetch = fetchLimit[0]
	}
	if raw := os.Getenv("NVD_MAX_FETCH"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			if parsed > 0 && (maxFetch <= 0 || parsed < maxFetch) {
				maxFetch = parsed
			}
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
	pages := 0

	for {
		params.Set("startIndex", strconv.Itoa(startIndex))
		finalURL := fmt.Sprintf("%s?%s", nvdBaseURL, params.Encode())

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
		pages++

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

	elapsed := time.Since(started)
	appInstance.LogJSON("INFO", "cve", fmt.Sprintf("source=cve fetched=%d pages=%d elapsed=%.3fs records_per_sec=%.1f", len(aggregated.Vulnerabilities), pages, elapsed.Seconds(), recordsPerSecond(len(aggregated.Vulnerabilities), elapsed)))
	return aggregated, nil
}

func recordsPerSecond(count int, elapsed time.Duration) float64 {
	if count <= 0 || elapsed <= 0 {
		return 0
	}
	return float64(count) / elapsed.Seconds()
}
