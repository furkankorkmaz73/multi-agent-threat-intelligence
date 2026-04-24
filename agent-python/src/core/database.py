from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pymongo
from pymongo.errors import PyMongoError

from config import APP_VERSION, DB_NAME, MONGO_URI, get_settings


SETTINGS = get_settings()


class DatabaseManager:
    def __init__(self) -> None:
        self.client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=SETTINGS.database.server_selection_timeout_ms, connectTimeoutMS=SETTINGS.database.connect_timeout_ms)
        self.db = self.client[DB_NAME]
        self.collections = {
            "cve": self.db["cve_intel"],
            "urlhaus": self.db["urlhaus_intel"],
            "dread": self.db["dread_intel"],
        }
        self._ensure_indexes()


    def _ensure_indexes(self) -> None:
        try:
            self.collections["cve"].create_index([("processed", pymongo.ASCENDING), ("_id", pymongo.ASCENDING)])
            self.collections["urlhaus"].create_index([("processed", pymongo.ASCENDING), ("url", pymongo.ASCENDING)])
            self.collections["dread"].create_index([("processed", pymongo.ASCENDING), ("url", pymongo.ASCENDING)])
            self.collections["cve"].create_index("normalized_fields.search_text")
            self.collections["urlhaus"].create_index("normalized_fields.search_text")
            self.collections["dread"].create_index("normalized_fields.search_text")
            self.collections["cve"].create_index("analysis.risk_score")
            self.collections["urlhaus"].create_index("analysis.risk_score")
            self.collections["dread"].create_index("analysis.risk_score")
        except Exception:
            # Index creation should never block app startup in constrained or mocked environments.
            pass

    def get_unprocessed(self, source: str, limit: int = 10) -> List[Dict[str, Any]]:
        return list(self.collections[source].find({"processed": False}).sort([("_id", pymongo.ASCENDING)]).limit(limit))

    def update_analysis(self, source: str, doc_id: Any, analysis_result: Dict[str, Any]) -> None:
        now = datetime.now(timezone.utc)
        persistence_meta = {
            "persisted_at": now,
            "pipeline_version": APP_VERSION,
            "source": source,
            "entity_id": analysis_result.get("entity_id"),
            "risk_score": analysis_result.get("risk_score"),
            "risk_level": analysis_result.get("risk_level"),
            "confidence": analysis_result.get("confidence"),
        }
        analysis_result.setdefault("persistence_meta", persistence_meta)
        history_entry = {
            "persisted_at": now,
            "pipeline_version": APP_VERSION,
            "risk_score": analysis_result.get("risk_score"),
            "risk_level": analysis_result.get("risk_level"),
            "confidence": analysis_result.get("confidence"),
            "semantic_signal": max(
                float(analysis_result.get("feature_breakdown", {}).get("urlhaus_avg_semantic_score", 0.0) or 0.0),
                float(analysis_result.get("feature_breakdown", {}).get("dread_avg_semantic_score", 0.0) or 0.0),
            ),
            "graph_centrality": float(analysis_result.get("graph_summary", {}).get("centrality_score", 0.0) or 0.0),
            "recommendation_count": len(analysis_result.get("recommendations", []) or []),
        }
        self.collections[source].update_one(
            {"_id": doc_id},
            {
                "$set": {"processed": True, "analysis": analysis_result, "analysis_updated_at": now},
                "$push": {"analysis_history": {"$each": [history_entry], "$slice": -10}},
            },
        )

    def get_recent_docs(self, source: str, limit: int = 100) -> List[Dict[str, Any]]:
        return list(self.collections[source].find({}).sort([("_id", pymongo.DESCENDING)]).limit(limit))


    def persist_analysis_result(self, source: str, original_doc: Dict[str, Any], analysis_result: Dict[str, Any]) -> Any:
        doc_id = self._resolve_doc_id(source=source, original_doc=original_doc, analysis_result=analysis_result)
        now = datetime.now(timezone.utc)
        persistence_meta = {
            "persisted_at": now,
            "pipeline_version": APP_VERSION,
            "source": source,
            "entity_id": analysis_result.get("entity_id"),
            "risk_score": analysis_result.get("risk_score"),
            "risk_level": analysis_result.get("risk_level"),
            "confidence": analysis_result.get("confidence"),
            "persist_mode": "api",
        }
        analysis_result = dict(analysis_result)
        analysis_result.setdefault("persistence_meta", persistence_meta)
        history_entry = {
            "persisted_at": now,
            "pipeline_version": APP_VERSION,
            "risk_score": analysis_result.get("risk_score"),
            "risk_level": analysis_result.get("risk_level"),
            "confidence": analysis_result.get("confidence"),
            "semantic_signal": max(
                float(analysis_result.get("feature_breakdown", {}).get("urlhaus_avg_semantic_score", 0.0) or 0.0),
                float(analysis_result.get("feature_breakdown", {}).get("dread_avg_semantic_score", 0.0) or 0.0),
            ),
            "graph_centrality": float(analysis_result.get("graph_summary", {}).get("centrality_score", 0.0) or 0.0),
            "recommendation_count": len(analysis_result.get("recommendations", []) or []),
        }
        base_doc = dict(original_doc)
        base_doc.setdefault("processed", True)
        base_doc.setdefault("created_at", now)
        self.collections[source].update_one(
            {"_id": doc_id},
            {
                "$set": {**base_doc, "processed": True, "analysis": analysis_result, "analysis_updated_at": now},
                "$push": {"analysis_history": {"$each": [history_entry], "$slice": -10}},
            },
            upsert=True,
        )
        return doc_id

    def get_status_overview(self) -> Dict[str, Any]:
        sources: Dict[str, Any] = {}
        totals = {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0}
        for source, collection in self.collections.items():
            total = int(collection.count_documents({}))
            processed = int(collection.count_documents({"processed": True}))
            analyzed = int(collection.count_documents({"analysis": {"$exists": True}}))
            unprocessed = max(total - processed, 0)
            avg_risk = 0.0
            docs = list(collection.find({"analysis.risk_score": {"$exists": True}}, {"analysis.risk_score": 1}).limit(250))
            if docs:
                avg_risk = round(sum(float((d.get("analysis", {}) or {}).get("risk_score", 0.0) or 0.0) for d in docs) / len(docs), 4)
            sources[source] = {
                "total": total,
                "processed": processed,
                "unprocessed": unprocessed,
                "analyzed": analyzed,
                "analysis_coverage": round(analyzed / max(total, 1), 4),
                "avg_risk_score": avg_risk,
            }
            totals["total"] += total
            totals["processed"] += processed
            totals["unprocessed"] += unprocessed
            totals["analyzed"] += analyzed
        totals["analysis_coverage"] = round(totals["analyzed"] / max(totals["total"], 1), 4)
        return {"sources": sources, "totals": totals, "pipeline_version": APP_VERSION}

    def search_analyzed_findings(self, source: str, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        query = (query or "").strip()
        if not query:
            return []
        escaped = re.escape(query)
        cursor = self.collections[source].find(
            {
                "analysis": {"$exists": True},
                "$or": [
                    {"_id": {"$regex": escaped, "$options": "i"}},
                    {"title": {"$regex": escaped, "$options": "i"}},
                    {"url": {"$regex": escaped, "$options": "i"}},
                    {"analysis.entity_id": {"$regex": escaped, "$options": "i"}},
                    {"analysis.diagnosis": {"$regex": escaped, "$options": "i"}},
                    {"normalized_fields.search_text": {"$regex": escaped, "$options": "i"}},
                ],
            }
        ).sort([("analysis.risk_score", pymongo.DESCENDING), ("_id", pymongo.DESCENDING)]).limit(limit)
        return list(cursor)

    def _resolve_doc_id(self, source: str, original_doc: Dict[str, Any], analysis_result: Dict[str, Any]) -> Any:
        candidates = [
            analysis_result.get("entity_id"),
            original_doc.get("_id"),
            original_doc.get("urlhaus_id"),
            original_doc.get("url"),
            original_doc.get("title"),
        ]
        for candidate in candidates:
            if candidate not in (None, ""):
                return candidate
        return f"{source}-{int(datetime.now(timezone.utc).timestamp())}"

    def find_related_urlhaus(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return self._find_related("urlhaus", keywords, fields=["url", "threat", "tags", "normalized_fields.search_text"], limit=limit)

    def find_related_dread(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return self._find_related("dread", keywords, fields=["title", "content", "category", "normalized_fields.search_text"], limit=limit)

    def find_related_cves(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return self._find_related("cve", keywords, fields=["_id", "descriptions.value", "normalized_fields.search_text"], limit=limit)

    def _find_related(self, source: str, keywords: List[str], fields: List[str], limit: int) -> List[Dict[str, Any]]:
        terms = [term for term in keywords[: SETTINGS.retrieval.search_field_limit] if term]
        if not terms:
            return []

        regex_clauses = []
        for term in terms:
            escaped = re.escape(term)
            for field in fields:
                regex_clauses.append({field: {"$regex": escaped, "$options": "i"}})

        try:
            cursor = self.collections[source].find({"$or": regex_clauses}).limit(limit)
            return list(cursor)
        except PyMongoError:
            return []
