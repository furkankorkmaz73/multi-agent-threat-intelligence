package db

import (
	"testing"
	"time"

	"github.com/furkankorkmaz309/threat-agent/internal/models"
	"go.mongodb.org/mongo-driver/bson"
)

var protectedPythonFields = []string{
	"analysis",
	"analysis_history",
	"job_lifecycle",
	"job_lifecycle_history",
	"analyzed_at",
	"processed",
}

func TestBuildCVEUpsertUsesUpdateAndDoesNotOverwritePythonOwnedFields(t *testing.T) {
	cve := models.CVE{
		ID:           "CVE-2026-9101",
		Published:    "2026-06-10T00:00:00.000",
		LastModified: "2026-06-11T00:00:00.000",
	}
	cve.Descriptions = append(cve.Descriptions, struct {
		Lang  string `json:"lang" bson:"lang"`
		Value string `json:"value" bson:"value"`
	}{Lang: "en", Value: "Remote code execution in Example Product."})
	enrichCVE(&cve)

	filter, update, err := buildCVEUpsert(cve)
	if err != nil {
		t.Fatalf("buildCVEUpsert returned error: %v", err)
	}

	if filter["_id"] != "CVE-2026-9101" {
		t.Fatalf("expected CVE identity filter on _id, got %#v", filter)
	}
	set := requireSet(t, update)
	requireProtectedFieldsAbsentFromSet(t, set)
	requireProcessedOnlyOnInsert(t, update)

	if _, exists := set["_id"]; exists {
		t.Fatalf("_id must not be included in $set for CVE upserts")
	}
	if set["published"] != cve.Published {
		t.Fatalf("expected published raw source field in $set, got %#v", set["published"])
	}
	if set["last_modified"] != cve.LastModified {
		t.Fatalf("expected last_modified raw source field in $set, got %#v", set["last_modified"])
	}
	if _, exists := set["metadata"]; !exists {
		t.Fatalf("expected collector metadata in $set")
	}
	if _, exists := set["normalized_fields"]; !exists {
		t.Fatalf("expected normalized fields in $set")
	}
}

func TestBuildURLhausUpsertUsesURLFilterAndDoesNotOverwritePythonOwnedFields(t *testing.T) {
	item := models.URLhausResponse{
		ID:          "UH-E2E-9101",
		DateAdded:   "2026-06-10 10:00:00",
		URL:         "https://malware.invalid/payload.exe",
		URLStatus:   "online",
		Threat:      "malware_download",
		Tags:        []string{"loader", "rce"},
		UrlhausLink: "https://urlhaus.abuse.ch/url/9101/",
		Reporter:    "researcher",
		Processed:   true,
	}
	enrichURLhaus(&item)

	filter, update, err := buildURLhausUpsert(item)
	if err != nil {
		t.Fatalf("buildURLhausUpsert returned error: %v", err)
	}

	if filter["url"] != item.URL {
		t.Fatalf("expected URLhaus identity filter on url, got %#v", filter)
	}
	set := requireSet(t, update)
	requireProtectedFieldsAbsentFromSet(t, set)
	requireProcessedOnlyOnInsert(t, update)

	if set["url"] != item.URL {
		t.Fatalf("expected url raw source field in $set, got %#v", set["url"])
	}
	if set["urlhaus_id"] != item.ID {
		t.Fatalf("expected urlhaus_id raw source field in $set, got %#v", set["urlhaus_id"])
	}
	if _, exists := set["metadata"]; !exists {
		t.Fatalf("expected collector metadata in $set")
	}
	if _, exists := set["normalized_fields"]; !exists {
		t.Fatalf("expected normalized fields in $set")
	}
}

func TestBuildDreadUpsertUsesURLFilterAndDoesNotOverwritePythonOwnedFields(t *testing.T) {
	post := models.DreadIntel{
		Title:     "Example exploit discussion",
		Content:   "Payload details",
		Author:    "analyst",
		Category:  "exploits",
		Source:    "Dread",
		URL:       "http://dread.invalid/post/9101",
		Processed: true,
		CreatedAt: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
	}
	enrichDread(&post)

	filter, update, err := buildDreadUpsert(post)
	if err != nil {
		t.Fatalf("buildDreadUpsert returned error: %v", err)
	}

	if filter["url"] != post.URL {
		t.Fatalf("expected Dread identity filter on url, got %#v", filter)
	}
	set := requireSet(t, update)
	requireProtectedFieldsAbsentFromSet(t, set)
	requireProcessedOnlyOnInsert(t, update)

	if set["url"] != post.URL {
		t.Fatalf("expected url raw source field in $set, got %#v", set["url"])
	}
	if set["title"] != post.Title {
		t.Fatalf("expected title raw source field in $set, got %#v", set["title"])
	}
	if _, exists := set["metadata"]; !exists {
		t.Fatalf("expected collector metadata in $set")
	}
	if _, exists := set["normalized_fields"]; !exists {
		t.Fatalf("expected normalized fields in $set")
	}
}

func TestCollectorUpsertUpdateDropsProtectedFieldsEvenIfPresent(t *testing.T) {
	update, err := collectorUpsertUpdate(bson.M{
		"url":                   "https://malware.invalid/payload.exe",
		"threat":                "malware",
		"analysis":              bson.M{"risk_score": 9.1},
		"analysis_history":      []bson.M{{"risk_score": 8.8}},
		"job_lifecycle":         bson.M{"state": "completed"},
		"job_lifecycle_history": []bson.M{{"state": "running"}},
		"analyzed_at":           time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		"processed":             true,
	})
	if err != nil {
		t.Fatalf("collectorUpsertUpdate returned error: %v", err)
	}

	set := requireSet(t, update)
	requireProtectedFieldsAbsentFromSet(t, set)
	requireProcessedOnlyOnInsert(t, update)
	if set["url"] != "https://malware.invalid/payload.exe" {
		t.Fatalf("expected non-protected collector field to remain in $set, got %#v", set["url"])
	}
	if set["threat"] != "malware" {
		t.Fatalf("expected non-protected collector field to remain in $set, got %#v", set["threat"])
	}
}

func requireSet(t *testing.T, update bson.M) bson.M {
	t.Helper()
	set, ok := update["$set"].(bson.M)
	if !ok {
		t.Fatalf("expected update to contain bson.M $set, got %#v", update["$set"])
	}
	return set
}

func requireProtectedFieldsAbsentFromSet(t *testing.T, set bson.M) {
	t.Helper()
	for _, field := range protectedPythonFields {
		if _, exists := set[field]; exists {
			t.Fatalf("protected Python-owned field %q must not be present in $set: %#v", field, set[field])
		}
	}
}

func requireProcessedOnlyOnInsert(t *testing.T, update bson.M) {
	t.Helper()
	if _, exists := requireSet(t, update)["processed"]; exists {
		t.Fatalf("processed must not be present in $set")
	}
	setOnInsert, ok := update["$setOnInsert"].(bson.M)
	if !ok {
		t.Fatalf("expected update to contain bson.M $setOnInsert, got %#v", update["$setOnInsert"])
	}
	processed, exists := setOnInsert["processed"]
	if !exists {
		t.Fatalf("expected processed default in $setOnInsert")
	}
	if processed != false {
		t.Fatalf("expected processed=false in $setOnInsert, got %#v", processed)
	}
}
