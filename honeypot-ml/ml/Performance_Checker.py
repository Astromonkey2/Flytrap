import logging
import matplotlib.pyplot as plt
from matplotlib import dates as mdates
import numpy as np
from sklearn import metrics
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """
    Tracks and visualizes detection performance, including score distributions and ROC curves.
    """
    def __init__(self):
        self.log_entries = []

    def update(self, score: float, is_attack: bool, true_label: Optional[bool] = None) -> None:
        entry = {
            'timestamp': datetime.now(),
            'score': score,
            'is_attack': is_attack,
            'true_label': true_label
        }
        self.log_entries.append(entry)
        logger.debug(f"PerformanceMonitor updated: {entry}")

    def generate_report(self) -> None:
        labeled_entries = [entry for entry in self.log_entries if entry['true_label'] is not None]
        has_labels = len(labeled_entries) > 0

        fig = plt.figure(1, figsize=(15, 10))
        plt.clf()

        # Plot 1: Score distribution
        ax1 = fig.add_subplot(2, 2, 1)
        scores = [entry['score'] for entry in self.log_entries]
        ax1.hist(scores, bins=50, alpha=0.7)
        ax1.set_title('Anomaly Score Distribution')
        ax1.set_xlabel('Score')
        ax1.set_ylabel('Count')
        if has_labels:
            true_attack_scores = [entry['score'] for entry in labeled_entries if entry['true_label']]
            non_attack_scores = [entry['score'] for entry in labeled_entries if not entry['true_label']]
            ax1.hist(true_attack_scores, bins=50, alpha=0.5, color='red', label='True Attacks')
            ax1.hist(non_attack_scores, bins=50, alpha=0.5, color='green', label='Non-Attacks')
            ax1.legend()

        # Plot 2: Cumulative attack counts
        ax2 = fig.add_subplot(2, 2, 2)
        timestamps_all = [entry['timestamp'] for entry in self.log_entries]
        detected_attacks_all = [1 if entry['is_attack'] else 0 for entry in self.log_entries]
        cumulative_detected = np.cumsum(detected_attacks_all)
        ax2.plot(timestamps_all, cumulative_detected, label='Detected Attacks')
        ax2.set_title('Cumulative Attack Counts')
        ax2.set_xlabel('Time')
        ax2.set_ylabel('Count')
        ax2.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
        ax2.legend()

        # Plot 3: Performance metrics (if labels are available)
        if has_labels:
            y_true = [entry['true_label'] for entry in labeled_entries]
            y_pred = [entry['is_attack'] for entry in labeled_entries]
            ax3 = fig.add_subplot(2, 2, 3)
            cm = metrics.confusion_matrix(y_true, y_pred)
            ax3.matshow(cm, cmap=plt.cm.Blues)
            ax3.set_title('Confusion Matrix')
            ax3.set_xticks([0, 1])
            ax3.set_yticks([0, 1])
            ax3.set_xticklabels(['Non-Attack', 'Attack'])
            ax3.set_yticklabels(['Non-Attack', 'Attack'])
            precision = metrics.precision_score(y_true, y_pred)
            recall = metrics.recall_score(y_true, y_pred)
            ax3.text(0, -1, f'Precision: {precision:.2f}, Recall: {recall:.2f}', ha='center', va='center', size=12)

            ax4 = fig.add_subplot(2, 2, 4)
            fpr, tpr, _ = metrics.roc_curve(y_true, [entry['score'] for entry in labeled_entries])
            roc_auc = metrics.roc_auc_score(y_true, [entry['score'] for entry in labeled_entries])
            ax4.plot(fpr, tpr, label=f'AUC = {roc_auc:.2f}')
            ax4.set_title('ROC Curve')
            ax4.set_xlabel('False Positive Rate')
            ax4.set_ylabel('True Positive Rate')
            ax4.legend(loc='lower right')
        else:
            ax3 = fig.add_subplot(2, 2, 3)
            ax3.text(0.5, 0.5, 'No true labels available for performance metrics.', ha='center', va='center', size=12)
            ax3.axis('off')
            ax4 = fig.add_subplot(2, 2, 4)
            ax4.text(0.5, 0.5, 'No true labels available for ROC curve.', ha='center', va='center', size=12)
            ax4.axis('off')

        try:
            fig.savefig('monitoring_report.png', bbox_inches='tight')
            logger.info("Performance report saved as monitoring_report.png")
        except Exception as e:
            logger.error(f"Error saving performance report: {e}")
        plt.close(fig)



