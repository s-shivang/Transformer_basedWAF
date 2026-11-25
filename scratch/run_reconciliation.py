"""
Reconciliation benchmark runner for Phase 7.3 Deliverable A.
Runs v1_0, v2_1, and v2_2 through the canonical evaluator on the exact 2,865-sample validation split.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import numpy as np
from src.evaluation.canonical_evaluator import CanonicalEvaluator
from src.evaluation.evaluate_v1_vs_v2_1_vs_v2_2 import load_fixed_dev_val_split

print("Loading 2,865 dev validation split...")
raw_requests, y_val = load_fixed_dev_val_split()
print(f"Loaded {len(raw_requests)} samples (Benign: {int((y_val == 0).sum())}, Malicious: {int((y_val == 1).sum())})")

models = {
    "v1_0": ROOT / "models/frozen/v1_0",
    "v2_1": ROOT / "models/frozen/v2_1",
    "v2_2": ROOT / "models/frozen/v2_2",
}

results = {}

for name, path in models.items():
    print(f"\nEvaluating {name} ({path})...")
    evaluator = CanonicalEvaluator(path)
    probs = evaluator.predict_batch(raw_requests, batch_size=128)
    
    m_50 = evaluator.compute_metrics(y_val, probs, threshold=0.50)
    m_85 = evaluator.compute_metrics(y_val, probs, threshold=0.85)
    
    results[name] = {
        "tau_0_50": m_50,
        "tau_0_85": m_85,
    }
    
    print(f"[{name}] @ tau=0.50: Recall={m_50['recall']*100:.2f}%, Precision={m_50['precision']*100:.2f}%, FPR={m_50['fpr']*100:.2f}%, F1={m_50['f1']*100:.2f}%, ROC-AUC={m_50['roc_auc']:.4f}")
    print(f"[{name}] @ tau=0.85: Recall={m_85['recall']*100:.2f}%, Precision={m_85['precision']*100:.2f}%, FPR={m_85['fpr']*100:.2f}%, F1={m_85['f1']*100:.2f}%, ROC-AUC={m_85['roc_auc']:.4f}")
    print(f"[{name}] Confusion Matrix (0.50): {m_50['confusion_matrix']}")
    print(f"[{name}] Confusion Matrix (0.85): {m_85['confusion_matrix']}")

with open(ROOT / "scratch/reconciliation_benchmark_results.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("\nBenchmark completed and saved to scratch/reconciliation_benchmark_results.json")
