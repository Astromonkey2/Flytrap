import logging
from datetime import datetime
import numpy as np
from collections import defaultdict
import csv
import os
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

class ResponseEngine:
    """
    Decides and logs responses to detected attacks, with adaptive thresholds and strategies.
    """
    def __init__(self, initial_thresholds: Optional[Dict[str, float]] = None, learning_rate: float = 0.1):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        default_thresholds = {'brute_force': 0.7, 'command_injection': 0.9, 'suspicious': 0.5}
        thresholds = initial_thresholds or default_thresholds
        self.strategies = {
            'brute_force': {
                'actions': ['temp_block', 'captcha'],
                'threshold': thresholds.get('brute_force', 0.7),
                'learned_response': ['temp_block', 'captcha'],
                'success_history': [],
                'last_updated': datetime.now()
            },
            'command_injection': {
                'actions': ['perm_block', 'deep_inspection'],
                'threshold': thresholds.get('command_injection', 0.9),
                'learned_response': ['perm_block', 'deep_inspection'],
                'success_history': [],
                'last_updated': datetime.now()
            },
            'suspicious': {
                'actions': ['monitor'],
                'threshold': thresholds.get('suspicious', 0.5),
                'learned_response': ['monitor'],
                'success_history': [],
                'last_updated': datetime.now()
            }
        }
        self.learning_rate = learning_rate
        self.feedback_memory = defaultdict(list)
        self.logger.info("ResponseEngine initialized successfully")

    def determine_response(self, attack_type: str, confidence: float, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Determine the appropriate response for a detected attack, given its type, confidence, and context.
        """
        try:
            if attack_type not in self.strategies:
                self.logger.warning("Unknown attack type: %s", attack_type)
                return ['alert']
            strategy = self.strategies[attack_type]
            self.logger.info("Determining response for %s with confidence %.2f", attack_type, confidence)
            effective_threshold = self._adjust_threshold(attack_type, confidence)
            if confidence > effective_threshold:
                actions = strategy['learned_response'] or strategy['actions']
                self.logger.info("Using response for %s: %s", attack_type, actions)
            else:
                actions = ['alert']
                self.logger.info("Low confidence, issuing alert for %s", attack_type)
            self._log_response(attack_type, confidence, actions, context)
            return actions
        except Exception as e:
            self.logger.error("Error determining response: %s", e)
            return ['alert']

    def _adjust_threshold(self, attack_type: str, current_confidence: float) -> float:
        strategy = self.strategies[attack_type]
        success_history = strategy['success_history']
        if len(success_history) < 5:
            return strategy['threshold']
        success_rate = np.mean(success_history[-5:])
        self.logger.debug("Success rate for %s: %.2f", attack_type, success_rate)
        if success_rate < 0.5:
            adjusted_threshold = max(0.1, strategy['threshold'] - self.learning_rate)
        elif success_rate > 0.8:
            adjusted_threshold = min(0.99, strategy['threshold'] + self.learning_rate)
        else:
            adjusted_threshold = strategy['threshold']
        strategy['threshold'] = adjusted_threshold
        strategy['last_updated'] = datetime.now()
        self.logger.info("Adjusted threshold for %s to %.2f", attack_type, adjusted_threshold)
        return adjusted_threshold

    def update_strategy(self, attack_type: str, success_rate: float, feedback: Optional[Dict[str, Any]] = None) -> None:
        try:
            if attack_type not in self.strategies:
                self.logger.warning("Unknown attack type for strategy update: %s", attack_type)
                return
            strategy = self.strategies[attack_type]
            strategy['success_history'].append(success_rate)
            self.feedback_memory[attack_type].append(feedback or {})
            self.logger.info("Updating strategy for %s with success rate %.2f", attack_type, success_rate)
            if success_rate < 0.5:
                self._evolve_strategy(attack_type, success_rate)
            elif len(strategy['success_history']) > 10:
                strategy['success_history'] = strategy['success_history'][-10:]
            strategy['last_updated'] = datetime.now()
        except Exception as e:
            self.logger.error("Error updating strategy: %s", e)

    def _evolve_strategy(self, attack_type: str, success_rate: float) -> None:
        strategy = self.strategies[attack_type]
        self.logger.info("Evolving strategy for %s due to low success rate %.2f", attack_type, success_rate)
        if attack_type == 'brute_force' and 'honeypot_deception' not in strategy['actions']:
            strategy['actions'].append('honeypot_deception')
            self.logger.info("Added honeypot_deception to %s strategy", attack_type)
        elif attack_type == 'command_injection' and 'malware_scan' not in strategy['actions']:
            strategy['actions'].append('malware_scan')
            self.logger.info("Added malware_scan to %s strategy", attack_type)
        elif attack_type == 'suspicious' and 'alert' not in strategy['actions']:
            strategy['actions'].append('alert')
            self.logger.info("Added alert to suspicious strategy", attack_type)
        strategy['learned_response'] = strategy['actions'].copy()

    def _log_response(self, attack_type: str, confidence: float, actions: List[str], context: Optional[Dict[str, Any]]) -> None:
        log_entry = {
            'timestamp': datetime.now(),
            'attack_type': attack_type,
            'confidence': confidence,
            'actions': actions,
            'context': context or {}
        }
        self.logger.info("Response logged: %s", log_entry)
        # Only log to CSV if actions != ['alert']
        if actions != ['alert']:
            ip = context.get("ip", "Unknown") if context else "Unknown"
            location = context.get("location", "Unknown") if context else "Unknown"
            top_features = context.get("top_features", []) if context else []
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            protection_instructions = {
                'brute_force': "Temporarily block the IP and require captcha verification to mitigate rapid brute force attempts.",
                'command_injection': "Permanently block the IP and initiate deep network inspection to prevent command injection and potential malware.",
                'suspicious': "Monitor the IP activity closely and analyze further to determine if additional actions are necessary."
            }
            recommended_steps = protection_instructions.get(attack_type, ", ".join(actions))
            csv_filename = "malicious_attempts.csv"
            file_exists = os.path.isfile(csv_filename)
            try:
                with open(csv_filename, "a", newline="") as csvfile:
                    writer = csv.writer(csvfile)
                    if not file_exists:
                        writer.writerow(["IP", "Time", "Attack Type", "Location", "Top Features", "Recommended Steps"])
                    writer.writerow([ip, timestamp_str, attack_type, location, str(top_features), recommended_steps])
                self.logger.info("Malicious attempt logged to CSV with recommended steps and top features.")
            except Exception as csv_err:
                self.logger.error("Error writing to CSV: %s", csv_err)







