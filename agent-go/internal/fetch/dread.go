package fetch

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/app"
	"github.com/furkankorkmaz309/threat-agent/internal/db"
	"github.com/furkankorkmaz309/threat-agent/internal/models"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/stealth"
)

func FetchDread(appInstance *app.App) error {
	if !envBool("DREAD_ENABLED", false) {
		appInstance.LogJSON("INFO", "dread", "Dread crawling disabled; set DREAD_ENABLED=true and DREAD_ONION_URL to enable experimental collection")
		return nil
	}

	dreadBaseURL := strings.TrimRight(os.Getenv("DREAD_ONION_URL"), "/")
	if dreadBaseURL == "" {
		return fmt.Errorf("DREAD_ONION_URL is required when DREAD_ENABLED=true")
	}
	requestTimeout := time.Duration(envInt("DREAD_REQUEST_TIMEOUT_SECONDS", 90)) * time.Second

	u := launcher.New().
		Proxy("socks5://127.0.0.1:9050").
		Set("ignore-certificate-errors").
		Headless(true).
		MustLaunch()

	browser := rod.New().ControlURL(u).MustConnect()
	defer browser.MustClose()

	for p := 1; p <= 2; p++ {
		pageURL := fmt.Sprintf("%s/?p=%d", dreadBaseURL, p)
		appInstance.LogJSON("INFO", "dread", fmt.Sprintf("Scanning Dread Page %d", p))

		page := stealth.MustPage(browser)
		_ = rod.Try(func() { page.Timeout(requestTimeout).MustNavigate(pageURL) })

		if err := handleQueue(appInstance, page); err != nil {
			appInstance.LogJSON("ERROR", "dread", fmt.Sprintf("Main queue failed: %v", err))
			page.MustClose()
			continue
		}

		links := collectLinks(page)
		appInstance.LogJSON("INFO", "dread", fmt.Sprintf("Identified %d unique posts on page %d", len(links), p))
		page.MustClose()

		for _, path := range links {
			fullURL := dreadBaseURL + path
			scrapeDetail(appInstance, browser, fullURL, requestTimeout)
			time.Sleep(time.Duration(rand.Intn(4)+4) * time.Second)
		}
	}
	return nil
}

func handleQueue(appInstance *app.App, p *rod.Page) error {
	start := time.Now()
	for time.Since(start) < 10*time.Minute {
		var title string
		_ = rod.Try(func() { title = p.MustEval(`() => document.title`).String() })

		t := strings.ToLower(title)
		if t != "" && !strings.Contains(t, "queue") && !strings.Contains(t, "protection") {
			var ready bool
			_ = rod.Try(func() { ready = p.MustHas("body") })

			if ready {
				appInstance.LogJSON("INFO", "dread", "Access confirmed, waiting for render")
				time.Sleep(8 * time.Second)
				return nil
			}
		}
		appInstance.LogJSON("INFO", "dread", fmt.Sprintf("Queue active, Title: %s", title))
		time.Sleep(15 * time.Second)
	}
	return fmt.Errorf("queue timeout")
}

func collectLinks(p *rod.Page) []string {
	var links []string
	unique := make(map[string]bool)
	elements, _ := p.Elements("a")
	for _, el := range elements {
		href, _ := el.Attribute("href")
		if href != nil && strings.Contains(*href, "/post/") && !unique[*href] {
			unique[*href] = true
			links = append(links, *href)
		}
	}
	return links
}

func scrapeDetail(appInstance *app.App, b *rod.Browser, url string, requestTimeout time.Duration) {
	appInstance.LogJSON("INFO", "dread", fmt.Sprintf("Opening: %s", url))
	page := stealth.MustPage(b)
	defer page.MustClose()

	_ = rod.Try(func() { page.Timeout(requestTimeout).MustNavigate(url) })
	_ = handleQueue(appInstance, page)

	var titleEl, contentEl *rod.Element
	err := rod.Try(func() {
		titleEl, _ = page.Timeout(40 * time.Second).Element("h1, .post-title, .title")
		contentEl, _ = page.Timeout(10 * time.Second).Element(".content, .post-body, .post-content, div.md, #post-content")
	})

	if err != nil || titleEl == nil {
		appInstance.LogJSON("ERROR", "dread", fmt.Sprintf("Skip: Element not found on %s", url))
		return
	}

	post := models.DreadIntel{
		Title:     strings.TrimSpace(titleEl.MustText()),
		URL:       url,
		Source:    "Dread",
		CreatedAt: time.Now(),
		Processed: false,
	}

	if contentEl != nil {
		post.Content = strings.TrimSpace(contentEl.MustText())
	}

	if el, err := page.Element("a[href^='/u/']"); err == nil {
		post.Author = strings.TrimSpace(el.MustText())
	}
	if el, err := page.Element("a[href^='/d/']"); err == nil {
		post.Category = strings.TrimSpace(el.MustText())
	}

	if err := db.SaveDreadPost(appInstance, post); err != nil {
		appInstance.LogJSON("ERROR", "db", fmt.Sprintf("DB Error: %v", err))
	} else {
		appInstance.LogJSON("INFO", "dread", fmt.Sprintf("Success Scraped: %s", post.Title))
	}
}

func envBool(name string, defaultValue bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if value == "" {
		return defaultValue
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func envInt(name string, defaultValue int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}
