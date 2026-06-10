package main

import "testing"

func TestLoadCVEFixture(t *testing.T) {
	loaded, err := loadCVEFixture("../../testdata/e2e/cve_fixture.json")
	if err != nil {
		t.Fatalf("loadCVEFixture returned error: %v", err)
	}
	if got := len(loaded.Vulnerabilities); got != 2 {
		t.Fatalf("expected 2 CVEs, got %d", got)
	}
	if loaded.Vulnerabilities[0].CVE.ID != "CVE-2026-9101" {
		t.Fatalf("unexpected first CVE: %s", loaded.Vulnerabilities[0].CVE.ID)
	}
}

func TestLoadURLhausFixture(t *testing.T) {
	loaded, err := loadURLhausFixture("../../testdata/e2e/urlhaus_fixture.json")
	if err != nil {
		t.Fatalf("loadURLhausFixture returned error: %v", err)
	}
	if got := len(loaded); got != 2 {
		t.Fatalf("expected 2 URLhaus records, got %d", got)
	}
	if loaded[0].ID != "UH-E2E-9101" {
		t.Fatalf("unexpected first URLhaus id: %s", loaded[0].ID)
	}
}
