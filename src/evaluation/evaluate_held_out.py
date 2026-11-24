import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
from typing import Dict, Any, List
import pandas as pd
import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc,
)

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features
from src.models.transformer_waf import TransformerWAFClassifier
from src.firewall.rules_engine import RulesEngine
from src.firewall.decision_engine import CentralDecisionEngine
from src.firewall.ml_detector import MLDetector
from src.firewall.anomaly_detector import BehavioralAnomalyDetector
HELD_OUT_PATH = ROOT / "data/processed/csic_held_out_test.parquet"
AI_WAF_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
MODEL_DIR = ROOT / "models/saved/transformer_waf"
REPORT_PATH = ROOT / "reports/final_pipeline_evaluation_report.json"


def measure_percentile_latencies(durations_ms: List[float]) -> Dict[str, float]:
    arr = np.array(durations_ms)
    return {
        "mean_ms": round(float(np.mean(arr)), 3),
        "p50_ms": round(float(np.percentile(arr, 50)), 3),
        "p95_ms": round(float(np.percentile(arr, 95)), 3),
        "p99_ms": round(float(np.percentile(arr, 99)), 3),
    }


def evaluate_transformer_on_dataset(
    classifier: TransformerWAFClassifier,
    requests_raw: List[str],
    labels: List[int],
    dataset_name: str,
    threshold: float = 0.50,
) -> Dict[str, Any]:
    print(f"\n[Evaluating] {dataset_name} ({len(requests_raw):,} samples)...")
    
    # 1. Parse & build features with timing
    parse_times = []
    feat_times = []
    infer_times = []
    structured_texts = []

    print("  Parsing raw requests...")
    for text in requests_raw:
        t0 = time.perf_counter()
        req = parse_raw_http(text)
        parse_times.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        feat = build_features(req, "structured")
        feat_times.append((time.perf_counter() - t1) * 1000.0)
        structured_texts.append(feat)

    # 2. Batch Inference
    print("  Running Transformer inference...")
    batch_size = 32
    all_probs = []
    for i in range(0, len(structured_texts), batch_size):
        batch = structured_texts[i : i + batch_size]
        t2 = time.perf_counter()
        probs = classifier.predict_proba(batch)
        dur = (time.perf_counter() - t2) * 1000.0
        infer_times.extend([dur / len(batch)] * len(batch))
        all_probs.extend(probs)

    # 3. Metrics at thresholds
    def get_metrics_at_tau(tau: float) -> Dict[str, Any]:
        p_arr = [1 if p >= tau else 0 for p in all_probs]
        acc_val = float(accuracy_score(labels, p_arr))
        prec_val = float(precision_score(labels, p_arr, pos_label=1, zero_division=0))
        rec_val = float(recall_score(labels, p_arr, pos_label=1, zero_division=0))
        f1_val = float(f1_score(labels, p_arr, pos_label=1, zero_division=0))
        cm_val = confusion_matrix(labels, p_arr, labels=[0, 1])
        c_tn, c_fp, c_fn, c_tp = cm_val.ravel()
        fpr_val = float(c_fp / (c_fp + c_tn)) if (c_fp + c_tn) > 0 else 0.0
        return {
            "threshold": tau,
            "accuracy": round(acc_val, 4),
            "precision": round(prec_val, 4),
            "recall": round(rec_val, 4),
            "f1": round(f1_val, 4),
            "false_positive_rate": round(fpr_val, 4),
            "confusion_matrix": [[int(c_tn), int(c_fp)], [int(c_fn), int(c_tp)]],
        }

    metrics_default = get_metrics_at_tau(threshold)
    metrics_strict = get_metrics_at_tau(0.20)
    metrics_standard = get_metrics_at_tau(0.03)

    # PR-AUC & ROC-AUC
    precision_vals, recall_vals, _ = precision_recall_curve(labels, all_probs)
    pr_auc = float(auc(recall_vals, precision_vals))
    roc_auc = float(roc_auc_score(labels, all_probs)) if len(set(labels)) > 1 else 1.0

    print(f"  Results for {dataset_name} at threshold {threshold}:")
    print(f"    Accuracy:  {metrics_default['accuracy']:.4f} | Precision: {metrics_default['precision']:.4f} | Recall: {metrics_default['recall']:.4f} | F1: {metrics_default['f1']:.4f} | FPR: {metrics_default['false_positive_rate']:.4f}")
    print(f"    PR-AUC:    {pr_auc:.4f} | ROC-AUC:   {roc_auc:.4f}")
    print(f"    Confusion Matrix: {metrics_default['confusion_matrix']}")
    print(f"  At Calibrated Strict Threshold (tau=0.20):")
    print(f"    Accuracy:  {metrics_strict['accuracy']:.4f} | Precision: {metrics_strict['precision']:.4f} | Recall: {metrics_strict['recall']:.4f} | F1: {metrics_strict['f1']:.4f} | FPR: {metrics_strict['false_positive_rate']:.4f}")

    return {
        "dataset": dataset_name,
        "rows": len(labels),
        "threshold": threshold,
        "accuracy": metrics_default["accuracy"],
        "precision": metrics_default["precision"],
        "recall": metrics_default["recall"],
        "f1": metrics_default["f1"],
        "false_positive_rate": metrics_default["false_positive_rate"],
        "pr_auc": round(pr_auc, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": metrics_default["confusion_matrix"],
        "calibrated_evaluations": {
            "strict_tau_0_20": metrics_strict,
            "standard_tau_0_03": metrics_standard,
        },
        "latency_profile": {
            "parsing": measure_percentile_latencies(parse_times),
            "feature_building": measure_percentile_latencies(feat_times),
            "transformer_inference": measure_percentile_latencies(infer_times),
        },
    }


def evaluate_end_to_end_firewall(
    engine: CentralDecisionEngine,
    requests_raw: List[str],
    labels: List[int],
    sample_size: int = 1000,
) -> Dict[str, Any]:
    """Evaluates the full 4-layer firewall decision engine latency & decisions."""
    print(f"\n[End-to-End Firewall] Benchmarking {sample_size} requests across all 4 layers...")
    indices = np.random.choice(len(requests_raw), min(sample_size, len(requests_raw)), replace=False)
    
    total_latencies = []
    actions_count = {"BLOCK": 0, "ALLOW": 0, "CHALLENGE": 0, "MONITOR": 0}
    blocked_by_layer = {}

    for idx in indices:
        raw_text = requests_raw[idx]
        req = parse_raw_http(raw_text)
        res = engine.inspect_request(req, client_id=f"bench_client_{idx}")
        total_latencies.append(res.latency_ms)
        actions_count[res.action] = actions_count.get(res.action, 0) + 1
        for lyr in res.triggered_layers:
            blocked_by_layer[lyr] = blocked_by_layer.get(lyr, 0) + 1

    profile = measure_percentile_latencies(total_latencies)
    print(f"  End-to-end Firewall Latency: p50={profile['p50_ms']} ms, p95={profile['p95_ms']} ms, p99={profile['p99_ms']} ms")
    print(f"  Action Distribution: {actions_count}")

    return {
        "sample_size": len(indices),
        "latency_percentiles": profile,
        "actions_distribution": actions_count,
        "layer_triggers": blocked_by_layer,
    }


def main():
    if not HELD_OUT_PATH.exists():
        raise FileNotFoundError(f"Sealed Held-Out partition not found: {HELD_OUT_PATH}")
    if not MODEL_DIR.exists():
        raise FileNotFoundError(f"Trained Transformer model directory not found: {MODEL_DIR}")

    print("=" * 70)
    print("PHASE 3 & 4: SEALED POST-HOC HELD-OUT EVALUATION & FIREWALL BENCHMARK")
    print("=" * 70)
    print("[Scientific Integrity Notice] Evaluating on the Post-Hoc Held-Out CSIC Partition.")

    classifier = TransformerWAFClassifier(str(MODEL_DIR))

    # 1. Load Sealed Post-Hoc Held-Out CSIC Partition
    print(f"Loading Held-Out CSIC dataset: {HELD_OUT_PATH}...")
    held_out_df = pd.read_parquet(HELD_OUT_PATH)
    held_out_raw = held_out_df["request_text"].tolist()
    held_out_labels = [1 if str(l).lower() in ("malicious", "anomalous") else 0 for l in held_out_df["label"]]

    held_out_results = evaluate_transformer_on_dataset(
        classifier=classifier,
        requests_raw=held_out_raw,
        labels=held_out_labels,
        dataset_name="Post-Hoc Held-Out CSIC Partition (Sealed)",
        threshold=0.50,
    )

    # 2. Evaluate In-Domain AI WAF Validation sample
    in_domain_results = None
    if AI_WAF_PATH.exists():
        ai_df = pd.read_parquet(AI_WAF_PATH).dropna().sample(min(3000, 5000), random_state=42)
        ai_raw = ai_df["text"].tolist()
        ai_labels = [1 if l == "malicious" else 0 for l in ai_df["label"]]
        in_domain_results = evaluate_transformer_on_dataset(
            classifier=classifier,
            requests_raw=ai_raw,
            labels=ai_labels,
            dataset_name="AI WAF Validation (In-Domain)",
            threshold=0.50,
        )

    # 3. Benchmark End-to-End Firewall Engine
    tfidf_path = ROOT / "models/saved/tfidf_logistic_baseline.joblib"
    ml_detector = MLDetector(
        tfidf_model_path=str(tfidf_path) if tfidf_path.exists() else None,
        transformer_model_dir=str(MODEL_DIR),
        fast_pass_threshold=0.05,
        transformer_block_threshold=0.20,
    )
    firewall_engine = CentralDecisionEngine(
        ml_detector=ml_detector,
        tau_block=0.20,
        tau_monitor=0.26,
    )

    firewall_profile = evaluate_end_to_end_firewall(
        engine=firewall_engine,
        requests_raw=held_out_raw,
        labels=held_out_labels,
        sample_size=2000,
    )

    # 4. Save Final Report
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    full_report = {
        "evaluation_name": "Transformer-Based WAF: Final Pipeline Benchmark",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_architecture": "all-MiniLM-L6-v2 (Fine-Tuned with Structural Tokens)",
        "hardware_device": str(classifier.device),
        "post_hoc_held_out_csic_partition": held_out_results,
        "in_domain_ai_waf_validation": in_domain_results,
        "end_to_end_firewall_benchmark": firewall_profile,
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print(f"\n[DONE] Final evaluation report successfully saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
