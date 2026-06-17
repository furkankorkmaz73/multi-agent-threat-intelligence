import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ApiError, createApiClient, describeApiError } from "../src/api.js";
import { AnalystDashboard, StatusPanel } from "../src/App.jsx";
import FindingTable from "../src/components/FindingTable.jsx";
import FindingDetail from "../src/components/FindingDetail.jsx";
import { filterAndSortFindings, detailEvidenceGroups } from "../src/viewModels.js";
import {
  criticalCorrelatedCveDetail,
  criticalCorrelatedCveSummary,
  emptyFindingsResponse,
  evaluationDiagnostics,
  forbiddenResponse,
  mediumCveSummary,
  offlineUrlhausIocSummary,
  statusOverview,
  unauthorizedResponse,
  urlhausIocSummary,
} from "../src/__fixtures__/apiFixtures.js";

test("API client injects x-api-key header without putting credentials in URLs", async () => {
  const requests = [];
  const client = createApiClient({
    baseUrl: "http://api.test",
    getApiKey: () => "test-analyst-key",
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return jsonResponse([criticalCorrelatedCveSummary]);
    },
  });

  await client.getTopFindings({ source: "cve", limit: 1 });

  assert.equal(requests[0].options.headers["x-api-key"], "test-analyst-key");
  assert.equal(requests[0].url.includes("test-analyst-key"), false);
});

test("API client classifies unauthorized and forbidden responses", async () => {
  const unauthorized = createApiClient({
    baseUrl: "http://api.test",
    fetchImpl: async () => jsonResponse(unauthorizedResponse, 401),
  });
  await assert.rejects(() => unauthorized.getTopFindings(), (error) => {
    assert.equal(error instanceof ApiError, true);
    assert.equal(error.status, 401);
    assert.equal(describeApiError(error).kind, "unauthorized");
    return true;
  });

  const forbidden = createApiClient({
    baseUrl: "http://api.test",
    fetchImpl: async () => jsonResponse(forbiddenResponse, 403),
  });
  await assert.rejects(() => forbidden.getStatusOverview(), (error) => {
    assert.equal(error.status, 403);
    assert.equal(describeApiError(error).kind, "forbidden");
    return true;
  });
});

test("API client rejects malformed finding summaries", async () => {
  const client = createApiClient({
    baseUrl: "http://api.test",
    fetchImpl: async () => jsonResponse([{ source: "cve" }]),
  });

  await assert.rejects(() => client.getTopFindings(), /Malformed finding summary/);
});

test("findings view model filters and sorts deterministically", () => {
  const rows = filterAndSortFindings([mediumCveSummary, urlhausIocSummary, criticalCorrelatedCveSummary], {
    riskLevel: "",
    sortBy: "risk_desc",
  });

  assert.deepEqual(rows.map((row) => row.entity_id), ["CVE-2026-9101", "CVE-2026-9102", "UH-E2E-9101"]);
  assert.equal(filterAndSortFindings(rows, { riskLevel: "CRITICAL" }).length, 1);
  assert.deepEqual(emptyFindingsResponse, []);
});

test("finding table renders list rows and evidence summary", () => {
  const html = renderToStaticMarkup(
    <FindingTable findings={[criticalCorrelatedCveSummary, mediumCveSummary]} selectedKey="" onSelect={() => {}} />,
  );

  assert.match(html, /CVE-2026-9101/);
  assert.match(html, /CRITICAL/);
  assert.match(html, /UH 1\/1/);
});

test("finding detail renders evidence, graph, critic, trace, and recommendations", () => {
  const html = renderToStaticMarkup(<FindingDetail detail={criticalCorrelatedCveDetail} loading={false} />);

  assert.match(html, /Correlation decisions/);
  assert.match(html, /Accepted evidence/);
  assert.match(html, /Rejected evidence/);
  assert.match(html, /Manual-review evidence/);
  assert.match(html, /Evidence diagnostics/);
  assert.match(html, /Operational risk by asset/);
  assert.match(html, /Generic risk/);
  assert.match(html, /asset-vpn-prod/);
  assert.match(html, /Relation summary/);
  assert.match(html, /Graph summary/);
  assert.match(html, /Critic review/);
  assert.match(html, /Execution plan/);
  assert.match(html, /Patch affected VPN gateway/);
});

test("detail evidence groups preserve accepted and rejected counts", () => {
  const groups = detailEvidenceGroups(criticalCorrelatedCveDetail);

  assert.equal(groups.counts.accepted, 1);
  assert.equal(groups.counts.rejected, 1);
  assert.equal(groups.counts.manualReview, 1);
  assert.equal(groups.accepted[0].acceptance_reason, "exact_cve");
});

test("analyst dashboard renders distribution and URLhaus charts from existing rows", () => {
  const html = renderToStaticMarkup(
    <AnalystDashboard
      findings={[criticalCorrelatedCveSummary, mediumCveSummary, urlhausIocSummary, offlineUrlhausIocSummary]}
      status={statusOverview}
      diagnostics={evaluationDiagnostics}
    />,
  );

  assert.match(html, /Risk distribution/);
  assert.match(html, /Confidence distribution/);
  assert.match(html, /Source coverage/);
  assert.match(html, /URLhaus status/);
  assert.match(html, /ONLINE/);
  assert.match(html, /OFFLINE/);
  assert.match(html, /Top malware\/tags/);
  assert.match(html, /ExampleLoader/);
});

test("finding detail handles missing optional fields and failed detail fetches", () => {
  const minimalDetail = {
    source: "cve",
    entity_id: "CVE-2026-EMPTY",
    risk_level: "LOW",
    risk_score: 2.1,
    confidence: 0.33,
    diagnosis: "Sparse finding.",
    evidence: {},
    feature_breakdown: {},
    graph_summary: {},
    explanation: [],
    recommendations: [],
  };
  const sparseHtml = renderToStaticMarkup(<FindingDetail detail={minimalDetail} loading={false} />);
  assert.match(sparseHtml, /No source-specific confidence breakdown available/);
  assert.match(sparseHtml, /No extracted entities/);

  const errorHtml = renderToStaticMarkup(<FindingDetail detail={null} loading={false} error={new Error("detail request failed")} />);
  assert.match(errorHtml, /Detail unavailable/);
  assert.match(errorHtml, /detail request failed/);
});

test("status panel renders unauthorized API state", () => {
  const error = new ApiError("Authentication required", { status: 401 });
  const html = renderToStaticMarkup(<StatusPanel status={null} error={error} onRefresh={() => {}} />);

  assert.match(html, /Operational status/);
  assert.match(html, /Authentication required/);
});

test("status panel renders operations health and unavailable metrics state", () => {
  const html = renderToStaticMarkup(
    <StatusPanel status={statusOverview} error={null} onRefresh={() => {}} health={{ status: "ok", database: "ok" }} />,
  );

  assert.match(html, /API health/);
  assert.match(html, /Unprocessed/);
  assert.match(html, /Performance metrics/);
  assert.match(html, /No persisted worker or benchmark metrics endpoint is available/);
});

test("status overview fixture preserves operator fields", async () => {
  const client = createApiClient({
    baseUrl: "http://api.test",
    getApiKey: () => "test-operator-key",
    fetchImpl: async () => jsonResponse(statusOverview),
  });

  const payload = await client.getStatusOverview();
  assert.equal(payload.sources.cve.processed, 2);
  assert.equal(payload.totals.analyzed, 4);
});

test("rendered frontend output does not leak API key strings", () => {
  const html = renderToStaticMarkup(<FindingDetail detail={criticalCorrelatedCveDetail} loading={false} />);
  assert.equal(html.includes("test-analyst-key"), false);
  assert.equal(html.includes("x-api-key"), false);
});

function jsonResponse(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}
