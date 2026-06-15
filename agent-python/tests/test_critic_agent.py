from agents.critic import CriticAgent


def test_critic_warns_and_recommends_action_for_high_risk_low_confidence():
    review = CriticAgent().review(
        {
            "risk_score": 8.0,
            "confidence": 0.4,
            "feature_breakdown": {},
            "evidence": {"related_urlhaus_count": 0, "related_dread_count": 0},
            "graph_summary": {},
        }
    )

    assert review["status"] == "passed"
    assert any("confidence" in warning.lower() for warning in review["warnings"])
    assert any("analyst review" in action.lower() for action in review["recommended_actions"])


def test_critic_issues_when_graph_signal_lacks_accepted_evidence():
    review = CriticAgent().review(
        {
            "risk_score": 6.0,
            "confidence": 0.8,
            "feature_breakdown": {"graph_signal": 0.4},
            "evidence": {"related_urlhaus_count": 0, "related_dread_count": 0},
            "graph_summary": {"cross_source_edge_count": 0, "centrality_score": 0.0},
        }
    )

    assert review["status"] == "needs-review"
    assert any("graph_signal is positive" in issue for issue in review["issues"])


def test_critic_issues_when_rejected_correlation_feeds_signal():
    review = CriticAgent().review(
        {
            "risk_score": 6.0,
            "confidence": 0.7,
            "feature_breakdown": {"correlation_signal": 0.3},
            "evidence": {
                "related_urlhaus_count": 0,
                "related_dread_count": 0,
                "dread_match_stats": {
                    "accepted_evidence_count": 0,
                    "manual_review_evidence_count": 1,
                    "rejected_evidence_count": 0,
                },
            },
            "graph_summary": {},
        }
    )

    assert review["status"] == "needs-review"
    assert any("Rejected or manual-review correlation" in issue for issue in review["issues"])
