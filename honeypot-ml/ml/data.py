import logging
from pymongo import MongoClient, ASCENDING, DESCENDING
from dotenv import load_dotenv
import os
import certifi

load_dotenv()
logger = logging.getLogger(__name__)

class MongoDBHandler:
    def __init__(self):
        uri = os.getenv("MONGO_URI")
        if not uri:
            logger.critical("MONGO_URI not found in environment variables")
            raise ValueError("MONGO_URI not found in environment variables")
        try:
            self.client = MongoClient(
                uri,
                tls=True,
                tlsCAFile=certifi.where(),
                tlsAllowInvalidCertificates=False,
                connectTimeoutMS=30000,
                serverSelectionTimeoutMS=1000
            )
            self.client.admin.command('ping')
            self.db = self.client.Honey
            self._create_indexes()
            logger.info("✅ Connected to MongoDB Atlas! Collections: %s", self.db.list_collection_names())
        except Exception as e:
            logger.critical(f"❌ Connection failed: {e}")
            raise

    def _create_indexes(self):
        try:
            self.db.records.create_index(
                [("source_ip", ASCENDING), ("timestamp", DESCENDING)],
                name="ip_time_index",
                background=True
            )
            logger.info("Indexes created on records collection.")
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")

    def get_historical_data(self, limit=5000):
        try:
            return list(self.db.records.find().limit(limit))
        except Exception as e:
            logger.error(f"Error fetching historical data: {e}")
            return []

    def stream_logs(self, resume_token=None):
        try:
            with self.db.records.watch(resume_after=resume_token) as stream:
                for change in stream:
                    yield {'log': change['fullDocument'], 'token': stream.resume_token}
        except Exception as e:
            logger.error(f"Error streaming logs: {e}")
            raise

if __name__ == "__main__":
    try:
        db_handler = MongoDBHandler()
    except Exception as e:
        logger.critical(f"🔥 Critical failure: {e}")


