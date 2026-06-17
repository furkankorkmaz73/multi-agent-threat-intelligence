package fetch

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
)

func TestFetchCVELimitConstrainsResultsPerPage(t *testing.T) {
	t.Setenv("NVD_MAX_FETCH", "")
	var resultsPerPage string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resultsPerPage = r.URL.Query().Get("resultsPerPage")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"resultsPerPage": 50,
			"startIndex": 0,
			"totalResults": 1,
			"vulnerabilities": [
				{"cve": {"id": "CVE-2026-0001", "published": "2026-06-01T00:00:00.000", "lastModified": "2026-06-02T00:00:00.000", "descriptions": [], "metrics": {}}}
			]
		}`))
	}))
	defer server.Close()

	previousBaseURL := nvdBaseURL
	nvdBaseURL = server.URL
	defer func() { nvdBaseURL = previousBaseURL }()

	payload, err := FetchCVE(app.New(), "", "incremental", 2, 50)
	if err != nil {
		t.Fatalf("FetchCVE returned error: %v", err)
	}
	if resultsPerPage != "50" {
		t.Fatalf("expected resultsPerPage=50, got %q", resultsPerPage)
	}
	if got := len(payload.Vulnerabilities); got != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", got)
	}
}
