from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import pymongo

from api.mappers import evidence_summary as _evidence_summary
from config import DB_NAME, MONGO_URI, get_settings


SETTINGS = get_settings()


class APIRepository:
    def __init__(self) -> None:
        self.client = pymongo.MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=SETTINGS.database.server_selection_timeout_ms,
            connectTimeoutMS=SETTINGS.database.connect_timeout_ms,
        )
        self.db = self.client[DB_NAME]
        self.collections = {
            "cve": self.db["cve_intel"],
            "urlhaus": self.db["urlhaus_intel"],
            "dread": self.db["dread_intel"],
        }

    def ping(self) -> bool:
        try:
            self.client.admin.command("ping")
            return True
        except Exception:
            return False

    def get_recent_findings(self, source: str, limit: int = 10) -> List[Dict[str, Any]]:
        return list(
            self.collections[source]
            .find({"analysis": {"$exists": True}})
            .sort([("analysis.analyzed_at", pymongo.DESCENDING), ("_id", pymongo.DESCENDING)])
            .limit(limit)
        )

    def get_top_risky_findings(self, source: Optional[str] = None, limit: int = 10, mode: str = "top") -> List[Dict[str, Any]]:
        collections = [source] if source else ["cve", "urlhaus", "dread"]
        all_docs: List[Dict[str, Any]] = []
        for src in collections:
            for doc in self._candidate_top_findings(src, limit=limit, mode=mode):
                doc["_source"] = src
                all_docs.append(doc)

        def risk(doc: Dict[str, Any]) -> float:
            return float((doc.get("analysis", {}) or {}).get("risk_score", 0.0) or 0.0)

        def confidence(doc: Dict[str, Any]) -> float:
            return float((doc.get("analysis", {}) or {}).get("confidence", 0.0) or 0.0)

        def evidence_strength(doc: Dict[str, Any]) -> int:
            summary = _evidence_summary(doc.get("analysis", {}) or {})
            return (
                int(sum(1 for item in summary.values() if item is True) * 10)
                + int((summary.get("urlhaus_accepted") or 0) * 4)
                + int((summary.get("exact_cve_hits") or 0) * 8)
                + int((summary.get("high_signal_hits") or 0) * 6)
            )

        def analyzed_ts(doc: Dict[str, Any]) -> float:
            return _parse_datetime_sort_value((doc.get("analysis", {}) or {}).get("analyzed_at"))

        def published_ts(doc: Dict[str, Any]) -> float:
            return _parse_datetime_sort_value(doc.get("published") or doc.get("date_added") or doc.get("created_at"))

        if mode == "highest_confidence":
            all_docs.sort(key=lambda doc: (confidence(doc), risk(doc), analyzed_ts(doc)), reverse=True)
        elif mode == "active_evidence":
            all_docs.sort(key=lambda doc: (evidence_strength(doc), risk(doc), confidence(doc)), reverse=True)
        elif mode == "needs_review":
            all_docs.sort(key=lambda doc: (risk(doc) >= 6.5, risk(doc), 1.0 - confidence(doc), evidence_strength(doc)), reverse=True)
        elif mode == "recent_high":
            all_docs.sort(key=lambda doc: (published_ts(doc), risk(doc), confidence(doc)), reverse=True)
        else:
            all_docs.sort(key=lambda doc: (risk(doc), confidence(doc), analyzed_ts(doc)), reverse=True)
        return all_docs[:limit]

    def _candidate_top_findings(self, source: str, *, limit: int, mode: str) -> List[Dict[str, Any]]:
        collection = self.collections[source]
        query = {"analysis": {"$exists": True}}
        sort_spec = _mongo_sort_for_top_mode(source, mode)
        if not sort_spec:
            return list(collection.find(query))
        return list(collection.find(query).sort(sort_spec).limit(limit))

    def get_cve_analysis_docs(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        projection = {
            "_id": 1,
            "published": 1,
            "descriptions": 1,
            "analysis.risk_score": 1,
            "analysis.risk_level": 1,
            "analysis.confidence": 1,
            "analysis.counterfactuals": 1,
            "analysis.source_contributions": 1,
            "analysis.relation_summary": 1,
            "analysis.evidence.cvss_score": 1,
            "analysis.evidence.age_days": 1,
            "analysis.evidence.related_urlhaus_count": 1,
            "analysis.evidence.related_dread_count": 1,
            "analysis.evidence.keywords": 1,
            "analysis.feature_breakdown.base_cvss_component": 1,
            "analysis.feature_breakdown.recentness_bonus": 1,
            "analysis.feature_breakdown.urlhaus_correlation_bonus": 1,
            "analysis.feature_breakdown.dread_correlation_bonus": 1,
            "analysis.feature_breakdown.graph_bonus": 1,
            "analysis.feature_breakdown.pre_graph_score": 1,
            "analysis.feature_breakdown.final_score": 1,
            "analysis.feature_breakdown.urlhaus_avg_semantic_score": 1,
            "analysis.feature_breakdown.dread_avg_semantic_score": 1,
            "analysis.diagnosis": 1,
            "analysis.graph_summary.centrality_score": 1,
            "analysis.graph_summary.average_edge_confidence": 1,
            "analysis.graph_summary.structural_strength": 1,
            "analysis.critic_review.status": 1,
            "analysis.pipeline_version": 1,
            "analysis.persistence_meta": 1,
            "analysis.recommendations": 1,
        }
        cursor = self.collections["cve"].find({"analysis": {"$exists": True}}, projection).sort(
            [("analysis.risk_score", pymongo.DESCENDING), ("_id", pymongo.DESCENDING)]
        )
        if limit:
            cursor = cursor.limit(limit)
        return list(cursor)

    def get_finding_by_entity_id(self, source: str, entity_id: str) -> Optional[Dict[str, Any]]:
        query = {
            "analysis": {"$exists": True},
            "$or": [
                {"analysis.entity_id": entity_id},
                {"_id": entity_id},
                {"urlhaus_id": entity_id},
                {"url": entity_id},
                {"title": entity_id},
            ],
        }
        return self.collections[source].find_one(query)


def _mongo_sort_for_top_mode(source: str, mode: str) -> List[tuple[str, int]]:
    if mode == "top":
        return [
            ("analysis.risk_score", pymongo.DESCENDING),
            ("analysis.confidence", pymongo.DESCENDING),
            ("analysis.analyzed_at", pymongo.DESCENDING),
        ]
    if mode == "highest_confidence":
        return [
            ("analysis.confidence", pymongo.DESCENDING),
            ("analysis.risk_score", pymongo.DESCENDING),
            ("analysis.analyzed_at", pymongo.DESCENDING),
        ]
    if mode == "recent_high":
        return [
            (_published_sort_field(source), pymongo.DESCENDING),
            ("analysis.risk_score", pymongo.DESCENDING),
            ("analysis.confidence", pymongo.DESCENDING),
        ]
    return []


def _published_sort_field(source: str) -> str:
    if source == "urlhaus":
        return "date_added"
    if source == "dread":
        return "created_at"
    return "published"


def _parse_datetime_sort_value(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, datetime):
        return value.timestamp()
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return 0.0
