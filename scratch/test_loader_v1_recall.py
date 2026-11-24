"""
Verification of Benchmark 1 loader for Model v1.0.
Verifies that on syntax-preserving representations, Model v1.0 reproduces its true ~97.57% recall at tau=0.50.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import numpy as np
import torch
from sklearn.metrics import recall_score, confusion_matrix, precision_score, f1_score, roc_auc_score

from src.models.train_transformer import load_training_data
from src.ml_service.model_loader import ModelContainer

V1_DIR = ROOT / "models/frozen/v1_0"

container = ModelContainer(model_dir=V1_DIR)
container.initialize()

print("\n1. Loading original 2,865 split from train_transformer...")
X_train, y_train, X_val, y_val = load_training_data()
y_val = np.array(y_val)
print(f"Loaded {len(X_val)} validation samples. Benign: {(y_val==0).sum()}, Malicious: {(y_val==1).sum()}")

# Evaluate Model v1.0 directly on the 2,865 feature strings (as in Phase 3/4)
print("\nScoring directly on original feature strings...")
batch_size = 128
probs_feat = []

for i in range(0, len(X_val), batch_size):
    batch = X_val[i : i + batch_size]
    enc = container.transformer_tokenizer(
        batch,
        max_length=container.max_length,
        truncation=True,
        padding=True,
        return_tensors="pt"
    ).to(container.device)
    with torch.no_grad():
        logits = container.transformer_model(**enc).logits
        if container.device.startswith("cuda") and logits.dtype != torch.float32:
            logits = logits.float()
        # Platt scaling for v1.0
        w = float(container.platt_params.get("w", 0.7724))
        b = float(container.platt_params.get("b", 0.4965))
        # Logit difference z = z1 - z0
        z = (logits[:, 1] - logits[:, 0]).cpu().numpy()
        calibrated_p = 1.0 / (1.0 + np.exp(-(w * z + b)))
        probs_feat.extend(calibrated_p)

probs_feat = np.array(probs_feat)

# Recall at 0.50 and 0.85
rec_50 = recall_score(y_val, (probs_feat >= 0.50).astype(int))
rec_85 = recall_score(y_val, (probs_feat >= 0.85).astype(int))
tn, fp, fn, tp = confusion_matrix(y_val, (probs_feat >= 0.50).astype(int), labels=[0, 1]).ravel()
fpr_50 = fp / (fp + tn)

print(f"Model v1.0 on raw feature strings:")
print(f"  @ tau=0.50: Recall={rec_50*100:.2f}% (TP={tp}/{tp+fn}), FPR={fpr_50*100:.2f}% (FP={fp})")
print(f"  @ tau=0.85: Recall={rec_85*100:.2f}%")
