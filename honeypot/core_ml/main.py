import time 
import joblib
from dotenv import load_dotenv
import os
import logging
from datetime import datetime

from data import MongoDBHandler
from Feature import FeatureExtractor
from model import AdaptiveAttackDetector
from response import ResponseEngine
from Performance_Checker import PerformanceMonitor

# Configuration
load_dotenv()
# We force threshold to 0 so every log is classified by our heuristics
THRESHOLD = float(os.getenv("THRESHOLD", 0.0))
# Report every 10 logs
REPORT_INTERVAL = int(os.getenv("REPORT_INTERVAL", 10))
MODEL_PATH = os.getenv("MODEL_PATH", "model.pkl")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("attack_detection.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Global dictionary to track last seen time per IP for interarrival calculation
last_seen = {}

def initialize_model(feature_extractor):
    detector = AdaptiveAttackDetector(threshold=THRESHOLD)
    try:
        with open(MODEL_PATH, 'rb') as f:
            detector = joblib.load(f)
        logger.info("Loaded existing model from %s", MODEL_PATH)
    except (FileNotFoundError, EOFError) as e:
        logger.warning("Error loading saved model: %s. Initializing new model.", str(e))
        try:
            db = MongoDBHandler()
            historical_logs = db.get_historical_data(limit=1000)
            if not historical_logs:
                logger.warning("No historical logs available for initial training.")
            else:
                valid_logs = [log for log in historical_logs if log and isinstance(log, dict) and 'source_ip' in log]
                logger.info("Training with %d valid historical logs", len(valid_logs))
                for log in valid_logs:
                    try:
                        ip = log.get('source_ip', 'unknown')
                        current_time = datetime.fromisoformat(log['timestamp'])
                        if ip in last_seen:
                            interarrival = (current_time - last_seen[ip]).total_seconds()
                        else:
                            interarrival = 100  # assume high if first occurrence
                        last_seen[ip] = current_time
                        
                        features = feature_extractor.transform(log)
                        features['interarrival_time'] = interarrival
                        
                        # Heuristic labeling:
                        if features.get('commands') and len(features.get('commands')) > 0:
                            label = 'command_injection'
                        else:
                            if features.get('interarrival_time', 100) < 3:
                                label = 'brute_force'
                            else:
                                label = 'suspicious'
                        
                        detector.process_log(features)
                        detector.train_classifier([features], [label])
                    except Exception as e:
                        logger.error("Error training on historical log %s: %s", log.get('_id', 'unknown'), str(e))
                logger.info("Initial training completed with %d logs", len(valid_logs))
        except Exception as e:
            logger.error("Failed to initialize with historical data: %s", str(e))
    return detector

def save_model(detector):
    try:
        with open(MODEL_PATH, 'wb') as f:
            joblib.dump(detector, f)
        logger.info("Model saved to %s", MODEL_PATH)
    except Exception as e:
        logger.error("Failed to save model: %s", str(e))

def main():
    try:
        logger.info("Starting system initialization...")
        db = MongoDBHandler()
        logger.info("MongoDBHandler initialized.")
        fe = FeatureExtractor()
        logger.info("FeatureExtractor initialized.")
        model = initialize_model(fe)
        logger.info("AdaptiveAttackDetector initialized.")
        responder = ResponseEngine()
        logger.info("ResponseEngine initialized.")
        monitor = PerformanceMonitor()
        logger.info("PerformanceMonitor initialized.")
        resume_token = None
        logger.info("System initialized successfully.")
    except Exception as e:
        logger.critical("Failed to initialize system: %s", str(e))
        raise

    try:
        while True:
            try:
                for change in db.stream_logs(resume_token):
                    if change is None:
                        logger.warning("Received None from stream, skipping.")
                        continue
                    if not isinstance(change, dict):
                        logger.error("Unexpected data structure from stream_logs: %s", type(change))
                        continue
                    log = change.get('log')
                    resume_token = change.get('token')
                    if log is None:
                        logger.warning("Received log entry with missing 'log' field: %s", change)
                        continue
                    try:
                        ip = log.get('source_ip', 'unknown')
                        current_time = datetime.fromisoformat(log['timestamp'])
                        if ip in last_seen:
                            interarrival = (current_time - last_seen[ip]).total_seconds()
                        else:
                            interarrival = 100
                        last_seen[ip] = current_time
                        
                        features = fe.transform(log)
                        features['interarrival_time'] = interarrival
                        
                        # Use improved model: get anomaly score, attack type, and feature importance
                        score, attack_type, feature_importance = model.process_log(features)
                        is_attack = True  # All logs are malicious in this scenario
                        monitor.update(score, is_attack, true_label=None)
                        
                        # Log top features for this anomaly
                        top_features = list(feature_importance.items())[:5]
                        logger.info(f"Top contributing features: {top_features}")
                        
                        try:
                            location = fe.get_location(ip)
                        except Exception as e:
                            logger.warning("GeoIP lookup failed for IP %s: %s", ip, str(e))
                            location = "Unknown"
                        context = {"ip": ip, "location": location, "top_features": top_features}
                        
                        # Determine heuristic label
                        if features.get('commands') and len(features.get('commands')) > 0:
                            heuristic_label = 'command_injection'
                        else:
                            if interarrival < 3:
                                heuristic_label = 'brute_force'
                            else:
                                heuristic_label = 'suspicious'
                        
                        # Override classifier prediction if it returns None or "normal"
                        if attack_type is None or attack_type.lower() == "normal":
                            attack_type = heuristic_label
                        
                        # Automatically update the classifier if it doesn't match the heuristic label
                        if attack_type.lower() != heuristic_label.lower():
                            model.train_classifier([features], [heuristic_label])
                            logger.info("Auto-updated classifier: changed %s to %s for log from %s", 
                                        attack_type, heuristic_label, ip)
                            attack_type = heuristic_label
                        
                        actions = responder.determine_response(attack_type, score, context)
                        logger.info("Detected attack from %s (score: %.2f, type: %s, interarrival: %.2f). Actions: %s",
                                    ip, score, attack_type, interarrival, actions)
                        success_rate = 0.75
                        responder.update_strategy(attack_type, success_rate)
                        
                        if len(monitor.log_entries) % REPORT_INTERVAL == 0 and len(monitor.log_entries) > 0:
                            save_model(model)
                            monitor.generate_report()
                            logger.info("Generated performance report after %d logs.", len(monitor.log_entries))
                    except Exception as e:
                        logger.error("Error processing log from %s: %s", log.get('source_ip', 'unknown') if log else 'unknown', str(e))
                        continue
            except Exception as e:
                logger.warning("Stream interrupted: %s. Reconnecting in 5 seconds...", str(e))
                time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Received shutdown signal. Saving final state...")
        save_model(model)
        monitor.generate_report()
        logger.info("Final performance report generated. System shutting down.")

if __name__ == "__main__":
    main()

