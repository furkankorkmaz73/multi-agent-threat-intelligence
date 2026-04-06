import os
import re
from pathlib import Path
from typing import Any, Dict, List

import pymongo
from dotenv import load_dotenv

env_path = Path(__file__).resolve().parents[3] / ".env"
load_dotenv(dotenv_path=env_path)


class DatabaseManager:
    def __init__(self) -> None:
        self.client = pymongo.MongoClient(
            os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
        )
        self.db = self.client["threat_intel"]
        self.collections = {
            "cve": self.db["cve_intel"],
            "urlhaus": self.db["urlhaus_intel"],
            "dread": self.db["dread_intel"],
        }

    def get_unprocessed(self, source: str, limit: int = 10) -> List[Dict[str, Any]]:
        return list(
            self.collections[source]
            .find({"processed": False})
            .sort([("_id", pymongo.ASCENDING)])
            .limit(limit)
        )

    def update_analysis(
        self,
        source: str,
        doc_id: Any,
        analysis_result: Dict[str, Any],
    ) -> None:
        self.collections[source].update_one(
            {"_id": doc_id},
            {
                "$set": {
                    "processed": True,
                    "analysis": analysis_result,
                }
            },
        )

    def get_recent_docs(
        self,
        source: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        return list(
            self.collections[source]
            .find({})
            .sort([("_id", pymongo.DESCENDING)])
            .limit(limit)
        )

    def find_related_urlhaus(
        self,
        keywords: List[str],
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        if not keywords:
            return []

        regex_clauses = []
        for kw in keywords[:10]:
            escaped = re.escape(kw)
            regex_clauses.extend(
                [
                    {"url": {"$regex": escaped, "$options": "i"}},
                    {"threat": {"$regex": escaped, "$options": "i"}},
                    {"tags": {"$regex": escaped, "$options": "i"}},
                ]
            )

        query = {"$or": regex_clauses}
        return list(self.collections["urlhaus"].find(query).limit(limit))

    def find_related_dread(
        self,
        keywords: List[str],
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        if not keywords:
            return []

        regex_clauses = []
        for kw in keywords[:10]:
            escaped = re.escape(kw)
            regex_clauses.extend(
                [
                    {"title": {"$regex": escaped, "$options": "i"}},
                    {"content": {"$regex": escaped, "$options": "i"}},
                    {"category": {"$regex": escaped, "$options": "i"}},
                ]
            )

        query = {"$or": regex_clauses}
        return list(self.collections["dread"].find(query).limit(limit))

    def find_related_cves(
        self,
        keywords: List[str],
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        if not keywords:
            return []

        regex_clauses = []
        for kw in keywords[:10]:
            escaped = re.escape(kw)
            regex_clauses.extend(
                [
                    {"_id": {"$regex": escaped, "$options": "i"}},
                    {"descriptions.value": {"$regex": escaped, "$options": "i"}},
                ]
            )

        query = {"$or": regex_clauses}
        return list(self.collections["cve"].find(query).limit(limit))