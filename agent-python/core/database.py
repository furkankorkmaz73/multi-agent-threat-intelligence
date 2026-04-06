import pymongo
import os
from dotenv import load_dotenv

load_dotenv()

class DatabaseManager:
    def __init__(self):
        self.client = pymongo.MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"))
        self.db = self.client["threat_intel"]
        self.collections = {
            "cve": self.db["cve_intel"],
            "urlhaus": self.db["urlhaus_intel"],
            "dread": self.db["dread_intel"]
        }

    def get_unprocessed(self, source, limit=10):
        return list(self.collections[source].find({"processed": False}).limit(limit))

    def update_analysis(self, source, doc_id, analysis_result):
        self.collections[source].update_one(
            {"_id": doc_id},
            {
                "$set": {
                    "processed": True,
                    "analysis": analysis_result
                }
            }
        )