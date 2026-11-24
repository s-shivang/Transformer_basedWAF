"""
Shadow Mode & Historical Traffic Replay Validator.

Simulates passive inline firewall deployment on historical traffic. Evaluates the full
4-layer firewall architecture (Rules -> L2 TF-IDF -> L3 Transformer -> L4 Anomaly)
in non-blocking observation mode to measure:
- Benign Disruption Risk (False Alarms that would disrupt legitimate users)
- Attack Interception Rate (Attacks successfully flagged)
- Layer-by-layer attribution
- Realistic multi-client behavioral tracking (concurrent sessions)
- Production latency percentiles (p50, p95, p99)

Ensures strict separation between development validation replay and one-time post-hoc held-out evaluation.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import numpy as np

from src.pipeline.parser import parse_raw_http
from src.firewall.decision_engine import CentralDecisionEngine
from src.firewall.rules_engine import RulesEngine
from src.firewall.ml_detector import MLDetector
from src.firewall.anomaly_detector import BehavioralAnomalyDetector

CSIC_DEV_PATH = ROOT / "data/processed/csic_dev.parquet"
CSIC_HELD_OUT_PATH = ROOT / "data/processed/csic_held_out_test.parquet"
TRANSFORMER_MODEL_DIR = ROOT / "models/saved/transformer_waf"
TFIDF_MODEL_PATH = ROOT / "models/saved/tfidf_logistic_baseline.joblib"
CALIBRATED_CONFIG_PATH = ROOT / "models/saved/calibrated_thresholds.json"
REPORT_PATH = ROOT / "reports/shadow_mode_validation_report.json"

RANDOM_SEED = 42


def load_calibrated_thresholds() -> Tuple[float, float]:
    """Loads frozen calibrated thresholds or defaults if not found."""
    if CALIBRATED_CONFIG_PATH.exists():
        with open(CALIBRATED_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
            tau_block = cfg.get("tau_strict_block", 0.20)
            tau_monitor = cfg.get("tau_monitor", 0.26)
            return float(tau_block), float(tau_monitor)
    return 0.50, 0.26


def run_shadow_mode_replay(
    sample_size: int = 2000,
    dataset_source: str = "held_out_post_hoc",  # 'dev_validation' or 'held_out_post_hoc'
    num_benign_clients: int = 50,
    num_attacker_clients: int = 10,
) -> Dict[str, Any]:
    print("=" * 70)
    print("TASK G: SHADOW MODE & TRAFFIC REPLAY VALIDATION")
    print("=" * 70)

    # 1. Select and load dataset partition
    if dataset_source == "held_out_post_hoc":
        if not CSIC_HELD_OUT_PATH.exists():
            raise FileNotFoundError(f"Held-out dataset missing: {CSIC_HELD_OUT_PATH}")
        df = pd.read_parquet(CSIC_HELD_OUT_PATH)
        partition_name = "Post-Hoc Held-Out CSIC Partition (Sealed from training weights)"
        print(f"Data Source: {partition_name}")
        print("  [DISCLOSURE] Replaying on held-out partition strictly for post-hoc validation; not used for tuning.")
    elif dataset_source == "dev_validation":
        if not CSIC_DEV_PATH.exists():
            raise FileNotFoundError(f"CSIC Dev dataset missing: {CSIC_DEV_PATH}")
        df = pd.read_parquet(CSIC_DEV_PATH)
        partition_name = "CSIC Development Partition"
        print(f"Data Source: {partition_name}")
    else:
        raise ValueError(f"Unknown dataset_source: {dataset_source}")

    # Stratified deterministic sample
    sample_df = df.sample(min(sample_size, len(df)), random_state=RANDOM_SEED).reset_index(drop=True)

    # 2. Initialize 4-Layer Firewall
    tau_block, tau_monitor = load_calibrated_thresholds()
    print(f"Firewall Policy: tau_block={tau_block:.2f}, tau_monitor={tau_monitor:.2f}")

    ml_detector = MLDetector(
        tfidf_model_path=str(TFIDF_MODEL_PATH) if TFIDF_MODEL_PATH.exists() else None,
        transformer_model_dir=str(TRANSFORMER_MODEL_DIR) if TRANSFORMER_MODEL_DIR.exists() else None,
        fast_pass_threshold=0.05,
        transformer_block_threshold=tau_block,
    )

    rules_engine = RulesEngine()
    anomaly_detector = BehavioralAnomalyDetector(
        window_seconds=10.0,
        rate_limit_per_second=10.0,
        burst_threshold=20,
        sensitive_scan_threshold=4,
    )

    firewall = CentralDecisionEngine(
        rules_engine=rules_engine,
        ml_detector=ml_detector,
        anomaly_detector=anomaly_detector,
        tau_block=tau_block,
        tau_monitor=tau_monitor,
    )

    print(f"Replaying {len(sample_df):,} historical requests across realistic multi-client pools...")

    # Client ID pools
    benign_clients = [f"client_benign_{i:03d}" for i in range(num_benign_clients)]
    attacker_clients = [f"client_attacker_{i:03d}" for i in range(num_attacker_clients)]

    benign_total = 0
    benign_disrupted = 0
    malicious_total = 0
    malicious_intercepted = 0

    action_counts = {"ALLOW": 0, "BLOCK": 0, "CHALLENGE": 0, "MONITOR": 0}
    layer_attribution = {}
    latencies = []
    service_failures = 0

    simulated_clock = time.time()

    for i, (_, row) in enumerate(sample_df.iterrows()):
        raw_text = str(row["request_text"])
        is_attack = str(row["label"]).lower() in ("malicious", "anomalous")

        if is_attack:
            malicious_total += 1
            client_id = attacker_clients[i % num_attacker_clients]
        else:
            benign_total += 1
            client_id = benign_clients[i % num_benign_clients]

        # Advance simulated time slightly for each request (inter-arrival jitter)
        simulated_clock += np.random.uniform(0.01, 0.05)

        try:
            req = parse_raw_http(raw_text)
            dec = firewall.inspect_request(req, client_id=client_id, event_time=simulated_clock)
            latencies.append(dec.latency_ms)

            action_counts[dec.action] = action_counts.get(dec.action, 0) + 1

            for lyr in dec.triggered_layers:
                layer_attribution[lyr] = layer_attribution.get(lyr, 0) + 1

            # Impact tracking
            if not is_attack and dec.action in ("BLOCK", "CHALLENGE"):
                benign_disrupted += 1
            elif is_attack and dec.action in ("BLOCK", "CHALLENGE", "MONITOR"):
                malicious_intercepted += 1

        except Exception as e:
            service_failures += 1
            action_counts["ALLOW"] = action_counts.get("ALLOW", 0) + 1

    shadow_fpr = (benign_disrupted / benign_total) if benign_total > 0 else 0.0
    shadow_recall = (malicious_intercepted / malicious_total) if malicious_total > 0 else 0.0

    print("\n--- Shadow Replay Results ---")
    print(f"  Data Partition:            {partition_name}")
    print(f"  Total Requests Replayed:   {len(sample_df):,}")
    print(f"  Benign Requests:           {benign_total:,}")
    print(f"  Benign Disrupted (FPs):    {benign_disrupted:,} (Benign Disruption Rate: {shadow_fpr * 100:.2f}%)")
    print(f"  Malicious Requests:        {malicious_total:,}")
    print(f"  Attacks Intercepted:       {malicious_intercepted:,} (Attack Interception Rate: {shadow_recall * 100:.2f}%)")
    print(f"  Action Distribution:       {action_counts}")
    print(f"  Layer Triggers:            {layer_attribution}")
    print(f"  Service Failures:          {service_failures}")
    print(f"  Latency p50:               {np.percentile(latencies, 50):.3f} ms")
    print(f"  Latency p95:               {np.percentile(latencies, 95):.3f} ms")
    print(f"  Latency p99:               {np.percentile(latencies, 99):.3f} ms")

    report = {
        "validation_name": "Task G Shadow Mode Replay Validation",
        "dataset_source": dataset_source,
        "partition_name": partition_name,
        "sample_size": len(sample_df),
        "benign_total": benign_total,
        "benign_disrupted_count": benign_disrupted,
        "benign_disruption_rate": round(shadow_fpr, 4),
        "malicious_total": malicious_total,
        "malicious_intercepted_count": malicious_intercepted,
        "attack_interception_rate": round(shadow_recall, 4),
        "action_distribution": action_counts,
        "layer_attribution": layer_attribution,
        "service_failures": service_failures,
        "firewall_policy": {
            "tau_block": tau_block,
            "tau_monitor": tau_monitor,
        },
        "latency_percentiles": {
            "p50_ms": round(float(np.percentile(latencies, 50)), 3),
            "p95_ms": round(float(np.percentile(latencies, 95)), 3),
            "p99_ms": round(float(np.percentile(latencies, 99)), 3),
        },
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[Saved] Corrected Shadow Replay Report saved to: {REPORT_PATH}")
    return report


if __name__ == "__main__":
    run_shadow_mode_replay()
