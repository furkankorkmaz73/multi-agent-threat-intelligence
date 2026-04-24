package fetch

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func doRequestWithRetry(client *http.Client, req *http.Request, attempts int, backoff time.Duration) (*http.Response, error) {
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		resp, err := client.Do(req)
		if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		} else if err != nil {
			lastErr = err
		}
		if attempt < attempts {
			time.Sleep(time.Duration(attempt) * backoff)
		}
	}
	return nil, lastErr
}
