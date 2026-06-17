package fetch

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
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
		retry := err != nil
		if resp != nil {
			retry = shouldRetryStatus(resp.StatusCode)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		} else if err != nil {
			lastErr = err
		}
		if !retry || attempt >= attempts {
			break
		}
		if delay := retryDelay(resp, attempt, backoff); delay > 0 {
			time.Sleep(delay)
		}
	}
	return nil, lastErr
}

func shouldRetryStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode >= 500
}

func retryDelay(resp *http.Response, attempt int, backoff time.Duration) time.Duration {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		if parsed, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
			return parsed
		}
	}
	return time.Duration(attempt) * backoff
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := when.Sub(now)
	if delay < 0 {
		return 0, true
	}
	return delay, true
}
