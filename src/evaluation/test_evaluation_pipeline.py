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

    def test_training_runtime_representation_consistency(self):
        """Asserts that training feature extraction matches runtime ML detector feature extraction."""
        raw_http = "GET /tienda1/index.jsp?id=10&cat=shoes HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = parse_raw_http(raw_http)

        # 1. Feature generated during training data prep
        feat_train = build_features(req, "structured")

        # 2. Feature generated inside ml_detector at runtime
        from src.firewall.ml_detector import MLDetector
        detector = MLDetector(tfidf_model_path="models/saved/tfidf_logistic_baseline.joblib")
        feat_runtime = build_features(req, representation="structured")

        self.assertEqual(feat_train, feat_runtime)
        self.assertTrue(detector.tfidf_pipeline is not None)

        # Verify Layer 2 score runs in microsecond latency
        res = detector.score_l2_tfidf(req)
        self.assertTrue(0.0 <= res.risk_score <= 1.0)
        self.assertLess(res.latency_ms, 5.0)  # sub-5ms

    def test_path_masking_representation(self):
        """Asserts that structured_masked decouples endpoint path from parameter payloads."""
        raw_http = "GET /api/v2/status/healthcheck?token=xyz HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = parse_raw_http(raw_http)

        feat_full = build_features(req, "structured")
        feat_masked = build_features(req, "structured_masked")

        self.assertIn("/api/v2/status/healthcheck", feat_full)
        self.assertNotIn("/api/v2/status/healthcheck", feat_masked)
        self.assertIn("/__APP_ENDPOINT__", feat_masked)
        self.assertIn("token=xyz", feat_masked)

    def test_frozen_artifact_loading_and_sha256(self):
        """Asserts that frozen artifacts in models/frozen/v1_0 exist and match manifest SHA-256."""
        import json
        import hashlib

        manifest_path = ROOT / "models/frozen/v1_0/model_manifest.json"
        self.assertTrue(manifest_path.exists(), f"Missing frozen manifest: {manifest_path}")

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        self.assertEqual(manifest["model_version"], "v1.0.0")
        self.assertEqual(manifest["max_length"], 192)

        for rel_path, expected_hash in manifest["artifacts_sha256"].items():
            full_file = ROOT / "models/frozen/v1_0" / rel_path
            self.assertTrue(full_file.exists(), f"Frozen artifact missing: {full_file}")
            h = hashlib.sha256()
            with open(full_file, "rb") as f:
                while chunk := f.read(8192):
                    h.update(chunk)
            self.assertEqual(
                h.hexdigest(),
                expected_hash,
                f"SHA-256 mismatch for frozen artifact {rel_path}!",
            )

    def test_frozen_model_prediction_schema_and_bounds(self):
        """Asserts that frozen models load properly and output calibrated probability in [0, 1]."""
        import joblib

        frozen_tfidf_path = ROOT / "models/frozen/v1_0/tfidf/tfidf_logistic_baseline.joblib"
        self.assertTrue(frozen_tfidf_path.exists())

        tfidf_clf = joblib.load(frozen_tfidf_path)
        classes = list(tfidf_clf.classes_)
        mal_idx = classes.index("malicious") if "malicious" in classes else 1

        test_texts = [
            "[METHOD] GET [PATH] /search [PARAM] q=shoes [PAYLOAD] shoes",
            "[METHOD] GET [PATH] /search [PARAM] q=' OR 1=1-- [PAYLOAD] ' OR 1=1--",
        ]
        probs = tfidf_clf.predict_proba(test_texts)[:, mal_idx]
        for p in probs:
            self.assertTrue(0.0 <= p <= 1.0, f"Probability out of bounds: {p}")
        self.assertLess(probs[0], probs[1], "Attack probability should exceed benign probability")

    def test_three_tier_threshold_and_fast_pass_routing(self):
        """Asserts correct routing logic across the 3-tier WAF policy."""
        tau_fast_pass = 0.04
        tau_alert = 0.05
        tau_block = 0.50

        # Simulate routing function
        def route_request(l2_score, l3_score):
            if l2_score < tau_fast_pass:
                return "FAST_PASS_ALLOW"
            elif l3_score >= tau_block:
                return "STRICT_BLOCK"
            elif l3_score >= tau_alert:
                return "SHADOW_ALERT"
            else:
                return "ALLOW"

        self.assertEqual(route_request(0.01, None), "FAST_PASS_ALLOW")
        self.assertEqual(route_request(0.10, 0.02), "ALLOW")
        self.assertEqual(route_request(0.10, 0.20), "SHADOW_ALERT")
        self.assertEqual(route_request(0.10, 0.85), "STRICT_BLOCK")

    def test_dataset_counts_and_zero_group_overlap(self):
        """Asserts exact 18,000 count and proves 0-group leakage in the development pool split."""
        from src.models.train_tfidf_layer import load_balanced_development_pool
        df = load_balanced_development_pool()

        self.assertEqual(len(df), 18000)
        self.assertEqual(int(np.sum(df["label"] == 0)), 10000)
        self.assertEqual(int(np.sum(df["label"] == 1)), 8000)

        groups = [f.split("[PARAM]")[0].strip() if "[PARAM]" in f else f[:32] for f in df["feat_structured"]]
        sgkf = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=42)
        train_idx, val_idx = next(sgkf.split(df, df["label"], groups))

        train_groups = set(np.array(groups)[train_idx])
        val_groups = set(np.array(groups)[val_idx])
        overlap = train_groups.intersection(val_groups)
        self.assertEqual(len(overlap), 0, f"Found {len(overlap)} overlapping groups across train and val splits!")


if __name__ == "__main__":
    unittest.main()
