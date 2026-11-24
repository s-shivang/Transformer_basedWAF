"""
Comprehensive Unit Tests for Evaluation Integrity and Generalization Pipeline.

Verifies:
1. Group Isolation: Zero group overlap across all cross-validation folds.
2. LOAFO Isolation: Zero held-out attack family leakage in training data.
3. Threshold Calibration: Correct operating point selection and FPR boundary enforcement.
4. Shadow Validator Metrics: Correct calculation of disruption and interception rates.
5. Representation Token Integrity: Correct structural token serialization.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import unittest
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features
from src.evaluation.group_cv import evaluate_predictions
from src.evaluation.calibrate_threshold import evaluate_threshold_point


class TestEvaluationIntegrity(unittest.TestCase):

    def test_group_isolation_no_leakage(self):
        """Asserts that StratifiedGroupKFold strictly prevents group ID crossing."""
        n_samples = 300
        n_groups = 30
        y = np.random.randint(0, 2, size=n_samples)
        groups = np.repeat(np.arange(n_groups), n_samples // n_groups)

        sgkf = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
        for fold, (train_idx, val_idx) in enumerate(sgkf.split(np.zeros(n_samples), y, groups)):
            train_groups = set(groups[train_idx])
            val_groups = set(groups[val_idx])
            overlap = train_groups.intersection(val_groups)
            self.assertEqual(
                len(overlap), 0, f"Fold {fold} has {len(overlap)} overlapping groups!"
            )

    def test_loafo_attack_family_isolation(self):
        """Asserts that a held-out attack family is completely excluded from training."""
        sample_data = pd.DataFrame({
            "payload": ["union select 1", "alert(1)", "../../etc/passwd", "cat /etc", "normal_val"],
            "attack_type": ["sqli", "xss", "path-traversal", "cmdi", "norm"],
            "label": [1, 1, 1, 1, 0],
        })

        for held_out in ["sqli", "xss", "path-traversal", "cmdi"]:
            attack_train = sample_data[
                (sample_data["attack_type"] != "norm") & (sample_data["attack_type"] != held_out)
            ]
            attack_test = sample_data[sample_data["attack_type"] == held_out]

            # Assert 0 held-out samples in train
            self.assertEqual(
                len(attack_train[attack_train["attack_type"] == held_out]),
                0,
                f"Held-out attack family '{held_out}' leaked into training set!",
            )
            # Assert test has only held-out family
            self.assertTrue(
                all(attack_test["attack_type"] == held_out),
                f"Non-held-out samples leaked into test set for '{held_out}'!",
            )

    def test_threshold_calibration_logic(self):
        """Asserts correct metric and FPR calculation across candidate thresholds."""
        y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
        y_prob = np.array([0.05, 0.10, 0.15, 0.80, 0.85, 0.70, 0.80, 0.90, 0.95, 0.99])

        # At high threshold (0.90): only true positives above 0.90 detected, zero false positives
        res_high = evaluate_threshold_point(y_true, y_prob, 0.90)
        self.assertEqual(res_high["fpr"], 0.0)
        self.assertEqual(res_high["confusion_matrix"]["fp"], 0)
        self.assertEqual(res_high["confusion_matrix"]["tp"], 3)  # 0.90, 0.95, 0.99

        # At low threshold (0.10): high recall, higher FPR
        res_low = evaluate_threshold_point(y_true, y_prob, 0.10)
        self.assertEqual(res_low["recall"], 1.0)
        self.assertGreater(res_low["fpr"], 0.0)

    def test_shadow_validator_metric_formulas(self):
        """Asserts exact formula computation for benign disruption and attack interception."""
        # Scenario: 100 benign requests, 5 false alarms; 50 attacks, 45 intercepted
        y_true = np.array([0] * 100 + [1] * 50)
        y_pred = np.array([0] * 95 + [1] * 5 + [1] * 45 + [0] * 5)
        y_prob = y_pred.astype(float)

        metrics = evaluate_predictions(y_true, y_pred, y_prob)

        expected_fpr = 5.0 / 100.0  # 0.05
        expected_recall = 45.0 / 50.0  # 0.90
        expected_accuracy = (95 + 45) / 150.0  # 0.9333

        self.assertAlmostEqual(metrics["fpr"], expected_fpr, places=4)
        self.assertAlmostEqual(metrics["recall"], expected_recall, places=4)
        self.assertAlmostEqual(metrics["accuracy"], round(expected_accuracy, 4), places=4)

    def test_representation_token_structure(self):
        """Asserts that build_features creates compliant structural tokens."""
        raw_http = (
            "POST /login.php?lang=en HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 21\r\n\r\n"
            "user=admin&pass=secret"
        )
        req = parse_raw_http(raw_http)
        feat_d = build_features(req, "structured")

        self.assertIn("[METHOD] POST", feat_d)
        self.assertIn("[PATH] /login.php", feat_d)
        self.assertIn("[PARAM]", feat_d)
        self.assertIn("lang=en", feat_d)
        self.assertIn("user=admin", feat_d)


if __name__ == "__main__":
    unittest.main()
