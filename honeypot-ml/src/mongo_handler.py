from pymongo import MongoClient
from datetime import datetime

# 1️⃣ Connect to MongoDB
client = MongoClient("mongodb+srv://<username>:<password>@cluster.mongodb.net/")
db = client["hackathon_db"]
collection = db["attack_logs"]

# 2️⃣ Function to upload data
def upload_attack_data(timestamp, duration, session_id, source_ip, source_port, destination_ip, destination_port, protocol, num_auth_attempts):
    attack_data = {
        "timestamp": timestamp,
        "duration": duration,
        "session_id": session_id,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "num_auth_attempts": num_auth_attempts
    }

    # 3️⃣ Insert into MongoDB
    collection.insert_one(attack_data)
    print("🚀 Data uploaded successfully!")

