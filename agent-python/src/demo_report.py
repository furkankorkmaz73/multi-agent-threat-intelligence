import argparse
import os
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

import pymongo
from dotenv import load_dotenv


env_path = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(dotenv_path=env_path)


class DemoReport:
    def __init__(self) -> None:
        mongo_uri = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client["threat_intel"]
        self.collections = {
            "cve": self.db["cve_intel"],
            "urlhaus": self.db["urlhaus_intel"],
            "dread": self.db["dread_intel"],
        }

    def fetch_records(
        self,
        source: str,
        limit: int = 5,
        only_analyzed: bool = True,
    ) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {}
        if only_analyzed:
            query["analysis"] = {"$exists": True}

        cursor = (
            self.collections[source]
            .find(query)
            .sort([("_id", pymongo.DESCENDING)])
            .limit(limit)
        )

        return list(cursor)

    def render(self, source: str, limit: int = 5) -> None:
        records = self.fetch_records(source=source, limit=limit, only_analyzed=True)

        print("=" * 90)
        print(f" THREAT-AGENT DEMO REPORT | SOURCE={source.upper()} | LIMIT={limit}")
        print("=" * 90)

        if not records:
            print("Analiz edilmiş kayıt bulunamadı.")
            print()
            return

        for idx, record in enumerate(records, start=1):
            self._print_record(idx, source, record)
            print("-" * 90)

        print()

    def _print_record(self, idx: int, source: str, record: Dict[str, Any]) -> None:
        analysis = record.get("analysis", {})
        evidence = analysis.get("evidence", {})

        entity_id = self._resolve_entity_id(source, record, analysis)
        risk_level = analysis.get("risk_level", "N/A")
        risk_score = analysis.get("risk_score", "N/A")
        confidence = analysis.get("confidence", "N/A")
        diagnosis = analysis.get("diagnosis", "N/A")
        explanation = analysis.get("explanation", [])
        recommendations = analysis.get("recommendations", [])

        print(f"[{idx}] {entity_id}")
        print(f"Risk Level : {risk_level}")
        print(f"Risk Score : {risk_score}")
        print(f"Confidence : {confidence}")
        print(f"Diagnosis  : {diagnosis}")

        if source == "cve":
            print(f"CVSS       : {evidence.get('cvss_score', 'N/A')} ({evidence.get('cvss_version', 'N/A')})")
            print(f"Age Days   : {evidence.get('age_days', 'N/A')}")
            print(f"Keywords   : {self._safe_join(evidence.get('keywords', []))}")
            print(f"Products   : {self._safe_join(evidence.get('llm_products', []))}")
            print(f"Vuln Type  : {evidence.get('llm_vuln_type', 'N/A')}")
            print(f"Impact     : {evidence.get('llm_impact', 'N/A')}")
            print(f"URLhaus    : {evidence.get('related_urlhaus_count', 0)} related record")
            print(f"Dread      : {evidence.get('related_dread_count', 0)} related record")

        elif source == "urlhaus":
            print(f"URL        : {record.get('url', 'N/A')}")
            print(f"Threat     : {record.get('threat', 'N/A')}")
            print(f"Tags       : {self._safe_join(record.get('tags', []))}")
            print(f"Status     : {record.get('url_status', 'N/A')}")
            print(f"Related CVE: {evidence.get('related_cve_count', 0)}")
            print(f"Related DW : {evidence.get('related_dread_count', 0)}")

        elif source == "dread":
            print(f"Title      : {record.get('title', 'N/A')}")
            print(f"Author     : {record.get('author', 'N/A')}")
            print(f"Category   : {record.get('category', 'N/A')}")
            print(f"Classes    : {self._safe_join(evidence.get('categories', []))}")
            print(f"LLM Class  : {evidence.get('llm_category', 'N/A')}")
            print(f"Rel. CVE   : {evidence.get('related_cve_count', 0)}")
            print(f"Rel. URLH  : {evidence.get('related_urlhaus_count', 0)}")

        if explanation:
            print("Explanation:")
            for item in explanation[:3]:
                print(f"  - {self._wrap(item)}")

        if recommendations:
            print("Recommendations:")
            for item in recommendations[:4]:
                print(f"  - {self._wrap(item)}")

    def _resolve_entity_id(
        self,
        source: str,
        record: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> str:
        if source == "cve":
            return str(record.get("_id", analysis.get("entity_id", "unknown-cve")))
        if source == "urlhaus":
            return str(
                analysis.get("entity_id")
                or record.get("urlhaus_id")
                or record.get("url")
                or record.get("_id", "unknown-urlhaus")
            )
        if source == "dread":
            return str(
                record.get("title")
                or analysis.get("entity_id")
                or record.get("_id", "unknown-dread")
            )
        return str(record.get("_id", "unknown"))

    def _safe_join(self, items: Optional[List[Any]]) -> str:
        if not items:
            return "-"
        return ", ".join(str(x) for x in items[:8])

    def _wrap(self, text: str, width: int = 75) -> str:
        return textwrap.fill(str(text), width=width, subsequent_indent="    ")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Threat-Agent demo output")
    parser.add_argument(
        "--source",
        choices=["cve", "urlhaus", "dread", "all"],
        default="all",
        help="Which source to display",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Number of records per source",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = DemoReport()

    if args.source == "all":
        for source in ["cve", "urlhaus", "dread"]:
            report.render(source=source, limit=args.limit)
    else:
        report.render(source=args.source, limit=args.limit)


if __name__ == "__main__":
    main()