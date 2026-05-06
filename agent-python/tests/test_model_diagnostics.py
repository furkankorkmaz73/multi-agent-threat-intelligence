from evaluation.model_diagnostics import bucket_counts, summarize_documents


def test_bucket_counts_groups_values():
    assert bucket_counts([0.1, 2.5, 4.1, 9.9, 12.0], [0, 2, 4, 6, 8, 10, 11]) == {
        "0-2": 1,
        "2-4": 1,
        "4-6": 1,
        "6-8": 0,
        "8-10": 1,
        "10-11": 0,
        "other": 1,
    }


def test_summarize_documents_detects_suppressed_high_cvss():
    docs = [
        {
            "_id": "CVE-HIGH-SUPPRESSED",
            "analysis": {
                "risk_score": 3.2,
                "risk_level": "LOW",
                "confidence": 0.5,
                "evidence": {"cvss_score": 9.8, "related_urlhaus_count": 0, "related_dread_count": 0},
                "feature_breakdown": {"age_penalty": 1.0},
            },
        },
        {
            "_id": "CVE-OK",
            "analysis": {
                "risk_score": 7.1,
                "risk_level": "HIGH",
                "confidence": 0.8,
                "evidence": {"cvss_score": 9.8, "related_urlhaus_count": 1, "related_dread_count": 0},
                "feature_breakdown": {"age_penalty": 0.1, "active_threat_score": 1.0},
            },
        },
    ]

    summary = summarize_documents(docs)

    assert summary["total_documents"] == 2
    assert summary["analyzed_documents"] == 2
    assert summary["risk_level_distribution"] == {"LOW": 1, "HIGH": 1}
    assert summary["accepted_urlhaus_evidence_total"] == 1
    assert summary["high_cvss_suppressed_examples"][0]["id"] == "CVE-HIGH-SUPPRESSED"
