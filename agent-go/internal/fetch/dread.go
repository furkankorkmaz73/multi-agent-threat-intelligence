package fetch

import (
	"fmt"
	"math/rand"
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
	u := launcher.New().
		Proxy("socks5://127.0.0.1:9050").
		Set("ignore-certificate-errors").
		Headless(true).
		MustLaunch()

	browser := rod.New().ControlURL(u).MustConnect()
	defer browser.MustClose()

	dreadBaseURL := "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion"

	for p := 1; p <= 2; p++ {
		pageURL := fmt.Sprintf("%s/?p=%d", dreadBaseURL, p)
		appInstance.LogJSON("INFO", "dread", fmt.Sprintf("Scanning Dread Page %d", p))

		page := stealth.MustPage(browser)
		_ = rod.Try(func() { page.Timeout(2 * time.Minute).MustNavigate(pageURL) })

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
			scrapeDetail(appInstance, browser, fullURL)
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

func scrapeDetail(appInstance *app.App, b *rod.Browser, url string) {
	appInstance.LogJSON("INFO", "dread", fmt.Sprintf("Opening: %s", url))
	page := stealth.MustPage(b)
	defer page.MustClose()

	_ = rod.Try(func() { page.Timeout(90 * time.Second).MustNavigate(url) })
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
