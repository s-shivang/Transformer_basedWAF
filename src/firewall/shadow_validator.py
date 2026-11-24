from pathlib import Path
import json
import time
from typing import Dict, Any, List
import pandas as pd
import numpy as np

from src.pipeline.parser import parse_raw_http
from src.firewall.decision_engine import CentralDecisionEngine
from src.firewall.rules_engine import RulesEngine
from src.firewall.ml_detector import MLDetector
from src.firewall.anomaly_detector import BehavioralAnomalyDetector

ROOT = Path(__file__).resolve().parents[2]
CSIC_DEV_PATH = ROOT / "data/processed/csic_dev.parquet"
MODEL_DIR = ROOT / "models/saved/transformer_waf"
REPORT_PATH = ROOT / "reports/shadow_mode_validation_report.json"


def run_shadow_mode_replay(
    sample_size: int = 2000,
    model_dir: str = str(MODEL_DIR),
) -> Dict[str, Any]:
    """
    Executes Phase 4.5: Shadow Mode & Replay Validation.
    Replays historical traffic through the complete 4-layer architecture
    in non-blocking observation mode to measure disruption risk and efficacy.
    """
    print("=" * 70)
    print("PHASE 4.5: SHADOW MODE & TRAFFIC REPLAY VALIDATION")
    print("=" * 70)

    if not CSIC_DEV_PATH.exists():
        raise FileNotFoundError(f"CSIC dev dataset not found: {CSIC_DEV_PATH}")

    df = pd.read_parquet(CSIC_DEV_PATH)
    sample_df = df.sample(min(sample_size, len(df)), random_state=42)

    # Initialize 4-Layer Firewall in Shadow Mode
    ml_detector = MLDetector(
        transformer_model_dir=model_dir if Path(model_dir).exists() else None,
        transformer_block_threshold=0.75,
    )
    firewall = CentralDecisionEngine(
        rules_engine=RulesEngine(),
        ml_detector=ml_detector,
        anomaly_detector=BehavioralAnomalyDetector(),
        tau_block=0.75,
        tau_monitor=0.40,
    )

    print(f"Replaying {len(sample_df):,} historical requests in Shadow Mode...")

    benign_total = 0
    benign_disrupted = 0  # False alarms that WOULD have blocked normal users
    malicious_total = 0
    malicious_intercepted = 0  # Attacks successfully flagged

    action_counts = {"ALLOW": 0, "BLOCK": 0, "CHALLENGE": 0, "MONITOR": 0}
    layer_attribution = {}
    latencies = []

    for i, (_, row) in enumerate(sample_df.iterrows()):
        raw_text = str(row["request_text"])
        is_attack = str(row["label"]).lower() in ("malicious", "anomalous")

        if is_attack:
            malicious_total += 1
        else:
            benign_total += 1

        req = parse_raw_http(raw_text)
        client_id = f"client_{i % 100}"
        dec = firewall.inspect_request(req, client_id=client_id)
        latencies.append(dec.latency_ms)

        action_counts[dec.action] = action_counts.get(dec.action, 0) + 1

        for lyr in dec.triggered_layers:
            layer_attribution[lyr] = layer_attribution.get(lyr, 0) + 1

        # Check impact
        if not is_attack and dec.action in ("BLOCK", "CHALLENGE"):
            benign_disrupted += 1
        elif is_attack and dec.action in ("BLOCK", "CHALLENGE", "MONITOR"):
            malicious_intercepted += 1

    shadow_fpr = (benign_disrupted / benign_total) if benign_total > 0 else 0.0
    shadow_recall = (malicious_intercepted / malicious_total) if malicious_total > 0 else 0.0

    print("\n--- Shadow Mode Impact Analysis ---")
    print(f"  Total Benign Replayed:     {benign_total:,}")
    print(f"  Benign Disrupted (FPs):    {benign_disrupted:,} (Shadow Disruption Rate: {shadow_fpr * 100:.2f}%)")
    print(f"  Total Attacks Replayed:    {malicious_total:,}")
    print(f"  Attacks Intercepted:       {malicious_intercepted:,} (Shadow Interception Rate: {shadow_recall * 100:.2f}%)")
    print(f"  Action Breakdown:          {action_counts}")
    print(f"  Layer Triggers:            {layer_attribution}")
    print(f"  p50 Latency:               {np.percentile(latencies, 50):.3f} ms")
    print(f"  p95 Latency:               {np.percentile(latencies, 95):.3f} ms")

    report = {
        "validation_name": "Phase 4.5 Shadow Mode & Replay Validation",
        "sample_size": len(sample_df),
        "benign_total": benign_total,
        "benign_disrupted_count": benign_disrupted,
        "shadow_disruption_rate": round(shadow_fpr, 4),
        "malicious_total": malicious_total,
        "malicious_intercepted_count": malicious_intercepted,
        "shadow_interception_rate": round(shadow_recall, 4),
        "action_distribution": action_counts,
        "layer_attribution": layer_attribution,
        "latency_percentiles": {
            "p50_ms": round(float(np.percentile(latencies, 50)), 3),
            "p95_ms": round(float(np.percentile(latencies, 95)), 3),
            "p99_ms": round(float(np.percentile(latencies, 99)), 3),
        },
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Saved Shadow Mode Report to: {REPORT_PATH}")
    return report


if __name__ == "__main__":
    run_shadow_mode_replay()
