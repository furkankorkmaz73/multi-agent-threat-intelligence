import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ApiError, createApiClient, describeApiError } from "../src/api.js";
import FindingTable from "../src/components/FindingTable.jsx";
import FindingDetail from "../src/components/FindingDetail.jsx";
import { filterAndSortFindings, detailEvidenceGroups } from "../src/viewModels.js";
import {
  criticalCorrelatedCveDetail,
  criticalCorrelatedCveSummary,
  emptyFindingsResponse,
  forbiddenResponse,
  mediumCveSummary,
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
  assert.match(html, /Graph summary/);
  assert.match(html, /Critic review/);
  assert.match(html, /Execution plan/);
  assert.match(html, /Patch affected VPN gateway/);
});

test("detail evidence groups preserve accepted and rejected counts", () => {
  const groups = detailEvidenceGroups(criticalCorrelatedCveDetail);

  assert.equal(groups.counts.accepted, 1);
  assert.equal(groups.counts.rejected, 1);
  assert.equal(groups.accepted[0].acceptance_reason, "exact_cve");
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
