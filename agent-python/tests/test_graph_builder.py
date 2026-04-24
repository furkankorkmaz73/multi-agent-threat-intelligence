from analysis.graph_builder import GraphBuilder


def test_graph_summary_contains_extended_metrics():
    builder = GraphBuilder()
    graph = builder.build_entity_graph(
        entity_type="cve",
        entity_id="CVE-2026-1234",
        record={"published": "2026-04-10T00:00:00.000"},
        evidence={
            "keywords": ["vpn", "rce"],
            "cvss_score": 9.8,
            "llm_products": ["VPN Gateway"],
            "llm_vuln_type": "remote code execution",
            "llm_impact": "full compromise",
            "dread_categories": ["exploit_sale"],
            "sample_urlhaus_hits": [{"url": "http://bad.test", "threat": "malware_download", "tags": ["phishing"], "url_status": "online"}],
            "sample_dread_hits": [{"title": "selling exploit", "category": "exploit_sale", "matched_terms": ["rce"]}],
        },
    )
    summary = builder.summarize_graph(graph, root_node="cve:CVE-2026-1234")
    assert "root_pagerank" in summary
    assert "structural_strength" in summary
    assert summary["node_count"] >= 3
