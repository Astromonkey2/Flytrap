import pandas as pd
import json
import time
from pymongo import MongoClient
import os

# 1️⃣ Connect to MongoDB
client = MongoClient("mongodb+srv://gurleenbatra14:caT3UWUhsicwY3Wo@gurleen.tsoo9.mongodb.net/?tls=true&tlsAllowInvalidCertificates=true&tlsVersion=TLS1_2")
db = client["Honey"]
collection = db["records"]

# 2️⃣ File paths
csv_file = r"C:\Users\svaad\heralding\log_auth.csv"
json_file = r"C:\Users\svaad\heralding\log_auth.json"  # JSON file path

last_modified = None

while True:
    if os.path.exists(csv_file):
        current_modified = os.path.getmtime(csv_file)  # Get last modified time

        if last_modified is None or current_modified > last_modified:
            print("🔄 Detected changes in log_auth.csv. Converting and uploading as JSON...")

            # 3️⃣ Read CSV and convert to JSON
            log_auth_df = pd.read_csv(csv_file)
            log_auth_df.to_json(json_file, orient="records", indent=4)  # Save JSON locally

            # 4️⃣ Read JSON and upload to MongoDB
            with open(json_file, "r", encoding="utf-8") as f:
                log_auth_data = json.load(f)

            collection.insert_many(log_auth_data)
            last_modified = current_modified  # Update last modified time
            
            print("✅ Data uploaded as JSON successfully!")

    time.sleep(300)  # Check every 5 minutes (300 seconds)
