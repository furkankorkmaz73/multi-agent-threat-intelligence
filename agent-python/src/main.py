import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from core.database import DatabaseManager
from agents.diagnostic import DiagnosticAgent
from agents.recommender import RecommenderAgent

env_path = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(dotenv_path=env_path)


def run_agent_loop() -> None:
    db = DatabaseManager()
    thinker = DiagnosticAgent()
    recommender = RecommenderAgent()

    print(f"[{datetime.now()}] Intelligence Core started...")

    while True:
        cycle_processed = 0

        for source in ["cve", "urlhaus", "dread"]:
            pending = db.get_unprocessed(source, limit=20)

            if not pending:
                continue

            print(f"[INFO] Pending {source}: {len(pending)}")

            for doc in pending:
                doc_id = doc["_id"]
                print(f"[PROCESS] Handling {source}: {doc_id}")

                try:
                    analysis = thinker.analyze(source, doc, db=db)
                    if analysis is None:
                        print(f"[SKIP] No analysis result for {source}: {doc_id}")
                        continue

                    analysis["recommendations"] = recommender.suggest(
                        analysis_result=analysis,
                        source=source,
                        original_doc=doc,
                    )
                    analysis["source"] = source
                    analysis["analyzed_at"] = datetime.now(timezone.utc)

                    db.update_analysis(source, doc_id, analysis)

                    print(
                        f"[DONE] {source}:{doc_id} | "
                        f"Level={analysis['risk_level']} | "
                        f"Score={analysis['risk_score']} | "
                        f"Confidence={analysis['confidence']}"
                    )

                    cycle_processed += 1

                except Exception as exc:
                    print(f"[ERROR] Failed processing {source}:{doc_id} -> {exc}")

        if cycle_processed == 0:
            print("[IDLE] No new records found. Sleeping...")
            time.sleep(10)
        else:
            print(f"[CYCLE] Processed {cycle_processed} document(s).")
            time.sleep(5)


if __name__ == "__main__":
    run_agent_loop()