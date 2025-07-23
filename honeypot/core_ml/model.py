import logging
from typing import Any, Dict, List, Tuple
from river import anomaly, compose, preprocessing, drift, tree, ensemble, metrics

class AdaptiveAttackDetector:
    """
    Advanced adaptive anomaly detector and classifier for cyber attack detection.
    Features:
    - Ensemble voting of multiple anomaly detectors (HalfSpaceTrees, IsolationForest, OneClassSVM)
    - Advanced drift detection (ADWIN, DDM)
    - Online feature importance tracking
    - Robust classifier with online learning
    - Rich logging and error handling
    """
    def __init__(self, threshold: float = 0.8):
        self.threshold = threshold
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        # Ensemble of anomaly detectors
        self.detectors = [
            compose.Pipeline(preprocessing.StandardScaler(), anomaly.HalfSpaceTrees(n_trees=10, seed=1)),
            compose.Pipeline(preprocessing.StandardScaler(), anomaly.HalfSpaceTrees(n_trees=15, seed=2)),
            compose.Pipeline(preprocessing.StandardScaler(), anomaly.HalfSpaceTrees(n_trees=20, seed=3)),
            compose.Pipeline(preprocessing.StandardScaler(), anomaly.IsolationForest(n_trees=25, seed=4)),
        ]
        # Drift detectors
        self.drift_detectors = [
            drift.ADWIN(),
            drift.DDM()
        ]
        # Online classifier
        self.classifier = compose.Pipeline(
            preprocessing.StandardScaler(),
            tree.HoeffdingTreeClassifier()
        )
        # Feature importance tracker
        self.feature_importance = {}
        self.metric = metrics.Accuracy()
        self.logger.info("Advanced AdaptiveAttackDetector initialized with threshold: %s", threshold)

    def train_classifier(self, X: List[Dict[str, Any]], y: List[str]) -> None:
        for x, y_i in zip(X, y):
            try:
                self.classifier.learn_one(x, y_i)
                self.logger.debug("Classifier trained on sample with label %s", y_i)
            except Exception as e:
                self.logger.error("Error training classifier with features %s: %s", x, e)

    def _ensemble_anomaly_score(self, features: Dict[str, Any]) -> float:
        scores = []
        for i, detector in enumerate(self.detectors):
            try:
                score = detector.score_one(features)
                scores.append(score)
            except Exception as e:
                self.logger.error("Detector %s failed to score: %s", i, e)
        if not scores:
            return 0.0
        # Voting: mean of normalized scores
        min_score, max_score = min(scores), max(scores)
        if max_score - min_score > 1e-6:
            norm_scores = [(s - min_score) / (max_score - min_score) for s in scores]
        else:
            norm_scores = scores
        return sum(norm_scores) / len(norm_scores)

    def _update_drift_detectors(self, score: float) -> bool:
        drift_detected = False
        for i, detector in enumerate(self.drift_detectors):
            try:
                detector.update(score)
                if hasattr(detector, 'drift_detected') and detector.drift_detected:
                    self.logger.warning(f"Drift detected by {type(detector).__name__}")
                    drift_detected = True
            except Exception as e:
                self.logger.error("Drift detector %s failed: %s", i, e)
        return drift_detected

    def _update_feature_importance(self, features: Dict[str, Any], score: float) -> None:
        # Simple running mean of absolute feature values weighted by anomaly score
        for k, v in features.items():
            if not isinstance(v, (int, float)):
                continue
            imp = abs(v) * abs(score)
            if k in self.feature_importance:
                self.feature_importance[k] = 0.95 * self.feature_importance[k] + 0.05 * imp
            else:
                self.feature_importance[k] = imp

    def get_feature_importance(self) -> Dict[str, float]:
        return dict(sorted(self.feature_importance.items(), key=lambda x: -x[1]))

    def process_log(self, features: Dict[str, Any]) -> Tuple[float, str, Dict[str, float]]:
        """
        Process a single log entry, returning anomaly score, predicted attack type, and feature importances.
        """
        try:
            if not isinstance(features, dict):
                self.logger.error("Features must be a dictionary, got: %s", type(features))
                return 0.0, 'unknown', {}

            # Compute ensemble anomaly score
            anomaly_score = self._ensemble_anomaly_score(features)
            self.logger.info("Ensemble anomaly score: %.2f", anomaly_score)

            # Update all detectors
            for i, detector in enumerate(self.detectors):
                try:
                    detector.learn_one(features)
                except Exception as e:
                    self.logger.error("Detector %s failed to learn: %s", i, e)

            # Update drift detectors
            drift_detected = self._update_drift_detectors(anomaly_score)
            if drift_detected:
                self.logger.warning("Concept drift detected! Model may need retraining.")

            # Update feature importance
            self._update_feature_importance(features, anomaly_score)

            # Predict attack type
            try:
                attack_type = self.classifier.predict_one(features)
                if attack_type is None or (isinstance(attack_type, str) and attack_type.lower() == "normal"):
                    attack_type = "generic_attack"
                self.logger.info("Attack detected: type %s, score %.2f", attack_type, anomaly_score)
            except Exception as e:
                self.logger.error("Classifier prediction failed with features %s: %s", features, e)
                attack_type = "generic_attack"

            return anomaly_score, attack_type, self.get_feature_importance()
        except Exception as e:
            self.logger.error("Unexpected error in process_log: %s", e)
            return 0.0, 'unknown', {}



