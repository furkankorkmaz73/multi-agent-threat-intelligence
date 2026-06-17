from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pymongo
from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import PyMongoError

from config import APP_VERSION, DB_NAME, MONGO_URI, get_settings


SETTINGS = get_settings()
CVE_ID_RE = re.compile(r"^cve-\d{4}-\d{4,7}$", re.I)
SUCCESSFUL_JOB_STATES = {"completed", "completed_with_warnings"}
URLHAUS_RETRIEVAL_WEAK_TERMS = {
    "affected", "allow", "allows", "application", "arbitrary", "attack",
    "attacker", "buffer", "client", "code", "crafted", "denial", "error",
    "escalation", "execution", "flaw", "http", "https", "issue", "linux",
    "only", "overflow", "privilege", "remote", "server", "service",
    "software", "supporting", "system", "tcp", "these", "udp", "user",
    "users", "vulnerability", "vulnerabilities", "web", "windows",
}
URLHAUS_RETRIEVAL_STRONG_TERMS = {
    "0day", "backdoor", "botnet", "cobaltstrike", "dropper", "exploit",
    "loader", "malware", "ransomware", "rce", "stealer", "trojan",
    "webshell", "zeroday",
}
VERSION_LIKE_RE = re.compile(r"^v?\d+(?:[._-]\d+){0,4}$", re.I)
FINDING_SUMMARY_PROJECTION = {
    "_id": 1,
    "urlhaus_id": 1,
    "url": 1,
    "title": 1,
    "published": 1,
    "date_added": 1,
    "created_at": 1,
    "analysis.entity_id": 1,
    "analysis.risk_level": 1,
    "analysis.risk_score": 1,
    "analysis.confidence": 1,
    "analysis.diagnosis": 1,
    "analysis.analyzed_at": 1,
    "analysis.pipeline_version": 1,
    "analysis.persistence_meta": 1,
    "analysis.evidence.cvss_score": 1,
    "analysis.evidence.age_days": 1,
    "analysis.evidence.related_dread_count": 1,
    "analysis.evidence.related_urlhaus_count": 1,
    "analysis.evidence.urlhaus_match_stats.accepted_match_count": 1,
    "analysis.evidence.urlhaus_match_stats.rejected_match_count": 1,
    "analysis.evidence.urlhaus_match_stats.exact_cve_hits": 1,
    "analysis.evidence.urlhaus_match_stats.high_signal_hits": 1,
    "analysis.evidence.urlhaus_match_stats.shared_terms": 1,
}


def _object_id_candidate(value: Any) -> Optional[ObjectId]:
    if isinstance(value, ObjectId):
        return None
    if not isinstance(value, str):
        return None
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        return None


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
            self.collections["cve"].create_index("normalized_fields.keywords")
            self.collections["urlhaus"].create_index("normalized_fields.keywords")
            self.collections["dread"].create_index("normalized_fields.keywords")
            self.collections["cve"].create_index("analysis.risk_score")
            self.collections["urlhaus"].create_index("analysis.risk_score")
            self.collections["dread"].create_index("analysis.risk_score")
            self.collections["cve"].create_index("job_lifecycle.idempotency_key")
            self.collections["urlhaus"].create_index("job_lifecycle.idempotency_key")
            self.collections["dread"].create_index("job_lifecycle.idempotency_key")
        except Exception:
            # Index creation should never block app startup in constrained or mocked environments.
            pass

    def get_unprocessed(self, source: str, limit: int = 10) -> List[Dict[str, Any]]:
        return list(self.collections[source].find({"processed": False}).sort([("_id", pymongo.ASCENDING)]).limit(limit))

    def update_job_lifecycle(self, source: str, doc_id: Any, job_lifecycle: Dict[str, Any]) -> None:
        now = datetime.now(timezone.utc)
        self.collections[source].update_one(
            self._job_lifecycle_filter(source, doc_id),
            self._job_lifecycle_update(job_lifecycle, now),
        )

    def claim_job_lifecycle(self, source: str, doc_id: Any, job_lifecycle: Dict[str, Any], *, now: datetime, force: bool = False) -> Optional[Dict[str, Any]]:
        collection = self.collections[source]
        identity_filter = self._job_lifecycle_filter(source, doc_id)
        if force:
            matched = collection.find_one_and_update(
                identity_filter,
                self._job_lifecycle_update(job_lifecycle, now),
            )
            return job_lifecycle if matched else None

        unclaimed_filter = {
            "$and": [
                identity_filter,
                {
                    "$or": [
                        {"job_lifecycle": {"$exists": False}},
                        {"job_lifecycle": None},
                    ]
                },
            ]
        }
        matched = collection.find_one_and_update(
            unclaimed_filter,
            self._job_lifecycle_update(job_lifecycle, now),
        )
        if matched is not None:
            return job_lifecycle

        retry_at = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
        retry_due_filter = {
            "$and": [
                identity_filter,
                {"job_lifecycle.idempotency_key": job_lifecycle.get("idempotency_key")},
                {"job_lifecycle.state": "retry_scheduled"},
                {"job_lifecycle.retry_at": {"$lte": retry_at.isoformat()}},
            ]
        }
        matched = collection.find_one_and_update(
            retry_due_filter,
            {
                "$set": {
                    "job_lifecycle.state": "running",
                    "job_lifecycle.updated_at": retry_at.isoformat(),
                    "job_lifecycle_updated_at": retry_at,
                    "processed": False,
                },
                "$push": {
                    "job_lifecycle_history": {
                        "$each": [
                            self._job_lifecycle_history_entry(
                                {
                                    **job_lifecycle,
                                    "state": "running",
                                },
                                retry_at,
                            )
                        ],
                        "$slice": -20,
                    }
                },
            },
        )
        if matched and matched.get("job_lifecycle"):
            return matched["job_lifecycle"]
        return None

    def _job_lifecycle_update(self, job_lifecycle: Dict[str, Any], now: datetime) -> Dict[str, Any]:
        processed = job_lifecycle.get("state") in SUCCESSFUL_JOB_STATES
        return {
            "$set": {
                "job_lifecycle": job_lifecycle,
                "job_lifecycle_updated_at": now,
                "processed": processed,
            },
            "$push": {
                "job_lifecycle_history": {
                    "$each": [self._job_lifecycle_history_entry(job_lifecycle, now)],
                    "$slice": -20,
                }
            },
        }

    def _job_lifecycle_history_entry(self, job_lifecycle: Dict[str, Any], now: datetime) -> Dict[str, Any]:
        return {
            "state": job_lifecycle.get("state"),
            "attempt_count": job_lifecycle.get("attempt_count"),
            "updated_at": now,
            "last_error": job_lifecycle.get("last_error"),
        }

    def _job_lifecycle_filter(self, source: str, doc_id: Any) -> Dict[str, Any]:
        identities: List[Dict[str, Any]] = [{"_id": doc_id}]
        object_id = _object_id_candidate(doc_id)
        if object_id is not None:
            identities.append({"_id": object_id})

        text_id = str(doc_id)
        if source == "urlhaus":
            identities.extend([{"urlhaus_id": text_id}, {"url": text_id}])
        elif source == "dread":
            identities.extend([{"url": text_id}, {"title": text_id}])

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for identity in identities:
            key = tuple((field, str(value), type(value).__name__) for field, value in identity.items())
            if key not in seen:
                deduped.append(identity)
                seen.add(key)
        if len(deduped) == 1:
            return deduped[0]
        return {"$or": deduped}

    def get_job_lifecycle_by_idempotency(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        for collection in self.collections.values():
            if not hasattr(collection, "find_one"):
                continue
            doc = collection.find_one({"job_lifecycle.idempotency_key": idempotency_key}, {"job_lifecycle": 1})
            if doc and doc.get("job_lifecycle"):
                return doc["job_lifecycle"]
        return None

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
            if hasattr(collection, "aggregate"):
                avg_cursor = list(collection.aggregate([
                    {"$match": {"analysis.risk_score": {"$exists": True}}},
                    {"$group": {"_id": None, "avg_risk_score": {"$avg": "$analysis.risk_score"}}},
                ]))
                if avg_cursor:
                    avg_risk = round(float(avg_cursor[0].get("avg_risk_score") or 0.0), 4)
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
            },
            FINDING_SUMMARY_PROJECTION,
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
        terms = _urlhaus_retrieval_terms(keywords)
        if not terms:
            return []
        return self._find_related("urlhaus", terms, fields=["url", "threat", "tags", "normalized_fields.search_text"], limit=limit)

    def find_related_dread(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return self._find_related("dread", keywords, fields=["title", "content", "category", "normalized_fields.search_text"], limit=limit)

    def find_related_cves(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return self._find_related("cve", keywords, fields=["_id", "descriptions.value", "normalized_fields.search_text"], limit=limit)

    def _find_related(self, source: str, keywords: List[str], fields: List[str], limit: int) -> List[Dict[str, Any]]:
        terms = [term for term in keywords[: SETTINGS.retrieval.search_field_limit] if term]
        if not terms:
            return []

        projection = _related_projection(source, fields)
        indexed_terms = _indexed_keyword_terms(terms)
        results: List[Dict[str, Any]] = []
        if indexed_terms:
            try:
                cursor = _find_with_projection(
                    self.collections[source],
                    {"normalized_fields.keywords": {"$in": indexed_terms}},
                    projection,
                ).limit(limit)
                results = list(cursor)
                if len(results) >= limit:
                    return results[:limit]
            except PyMongoError:
                results = []

        regex_clauses = []
        for term in terms:
            escaped = re.escape(term)
            for field in fields:
                regex_clauses.append({field: {"$regex": escaped, "$options": "i"}})

        try:
            cursor = _find_with_projection(self.collections[source], {"$or": regex_clauses}, projection).limit(limit)
            return _dedupe_related([*results, *list(cursor)], limit=limit)
        except PyMongoError:
            return results[:limit]


def _urlhaus_retrieval_terms(keywords: List[str]) -> List[str]:
    terms: List[str] = []
    seen: set[str] = set()
    for keyword in keywords:
        for token in _keyword_tokens(keyword):
            normalized = token.lower().strip("._-")
            if not _is_urlhaus_strong_retrieval_term(normalized):
                continue
            if normalized not in seen:
                seen.add(normalized)
                terms.append(normalized)
            if len(terms) >= SETTINGS.retrieval.search_field_limit:
                return terms
    return terms


def _indexed_keyword_terms(keywords: List[str]) -> List[str]:
    terms: List[str] = []
    seen: set[str] = set()
    for keyword in keywords:
        for token in _keyword_tokens(keyword):
            normalized = token.lower().strip("._-")
            if not _is_indexed_keyword_term(normalized):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            terms.append(normalized)
            if len(terms) >= SETTINGS.retrieval.search_field_limit:
                return terms
    return terms


def _is_indexed_keyword_term(term: str) -> bool:
    if not term:
        return False
    if CVE_ID_RE.fullmatch(term):
        return True
    if term in URLHAUS_RETRIEVAL_STRONG_TERMS:
        return True
    if len(term) < 4:
        return False
    if term in URLHAUS_RETRIEVAL_WEAK_TERMS:
        return False
    if term.isdigit() or VERSION_LIKE_RE.fullmatch(term):
        return False
    return len(term) >= 5


def _related_projection(source: str, fields: List[str]) -> Dict[str, int]:
    projection = {"_id": 1, "normalized_fields.keywords": 1, "normalized_fields.search_text": 1}
    for field in fields:
        projection[field] = 1
    if source == "urlhaus":
        projection.update({
            "urlhaus_id": 1,
            "url": 1,
            "threat": 1,
            "tags": 1,
            "url_status": 1,
            "date_added": 1,
            "urlhaus_link": 1,
        })
    elif source == "dread":
        projection.update({
            "title": 1,
            "content": 1,
            "category": 1,
            "author": 1,
            "url": 1,
            "created_at": 1,
        })
    elif source == "cve":
        projection.update({
            "descriptions": 1,
            "published": 1,
            "last_modified": 1,
            "metrics": 1,
        })
    return projection


def _dedupe_related(rows: List[Dict[str, Any]], *, limit: int) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = str(row.get("_id") or row.get("urlhaus_id") or row.get("url") or row.get("title") or id(row))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
        if len(deduped) >= limit:
            break
    return deduped


def _find_with_projection(collection: Any, query: Dict[str, Any], projection: Dict[str, int]) -> Any:
    try:
        return collection.find(query, projection)
    except TypeError:
        return collection.find(query)


def _keyword_tokens(value: Any) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    return re.findall(r"cve-\d{4}-\d{4,7}|[A-Za-z0-9][A-Za-z0-9_.-]*", text, flags=re.I)


def _is_urlhaus_strong_retrieval_term(term: str) -> bool:
    if not term:
        return False
    if CVE_ID_RE.fullmatch(term):
        return True
    if term in URLHAUS_RETRIEVAL_STRONG_TERMS:
        return True
    if len(term) < 4:
        return False
    if term in URLHAUS_RETRIEVAL_WEAK_TERMS:
        return False
    if term.isdigit() or VERSION_LIKE_RE.fullmatch(term):
        return False
    return len(term) >= 5
