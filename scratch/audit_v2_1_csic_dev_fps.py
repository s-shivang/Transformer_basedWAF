"""
Forensic False-Positive Audit on CSIC Dev Validation Split for Model v2.1.
Identifies the top 25 highest-scoring false positives made on the CSIC Dev validation partition.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import pandas as pd
import numpy as np
import torch
from sklearn.model_selection import StratifiedGroupKFold

from src.ml_service.model_loader import ModelContainer

V2_1_DIR = ROOT / "models/frozen/v2_1"
DEV_AUGMENTED_PATH = ROOT / "data/processed/dev_v2_1_augmented.parquet"

container = ModelContainer(model_dir=V2_1_DIR)
container.initialize()

df = pd.read_parquet(DEV_AUGMENTED_PATH)

# Re-create the exact group split used in v2.1 training (6 splits, fold 0, random_state=42)
sgkf = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=42)
_, val_idx = next(sgkf.split(df, df["label"], df["group_id"]))
val_df = df.iloc[val_idx].copy().reset_index(drop=True)

# Filter strictly to CSIC Dev benign samples in validation fold!
csic_dev_benign = val_df[(val_df["source"] == "csic_dev") & (val_df["label"] == 0)].copy().reset_index(drop=True)
print(f"CSIC Dev Benign samples in validation fold: {len(csic_dev_benign)}")

# Score all with Model v2.1
features = csic_dev_benign["feat_structured_v2_norm"].tolist()
batch_size = 64
probs = []

for i in range(0, len(features), batch_size):
    batch = features[i : i + batch_size]
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
        w = float(container.platt_params.get("w", 0.9409))
        b = float(container.platt_params.get("b", 0.2075))
        z = (logits[:, 1] - logits[:, 0]).cpu().numpy()
        calibrated_p = 1.0 / (1.0 + np.exp(-(w * z + b)))
        probs.extend(calibrated_p)

csic_dev_benign["v2_1_score"] = probs
top_fps = csic_dev_benign.sort_values(by="v2_1_score", ascending=False).head(25)

print("\n" + "=" * 80)
print("TOP 25 HIGHEST-SCORING FALSE POSITIVES ON CSIC DEV VALIDATION FOLD (MODEL V2.1)")
print("=" * 80)

audit_records = []
for idx, (_, row) in enumerate(top_fps.iterrows(), 1):
    raw = row["raw_text"]
    first_line = raw.strip().split("\n")[0]
    score = row["v2_1_score"]
    feat = row["feat_structured_v2_norm"]
    
    print(f"\n--- FP #{idx} | Score: {score:.4f} ---")
    print(f"Request Line: {first_line}")
    print(f"Feature: {feat[:120]}...")
    
    # Analyze root cause
    reasons = []
    if "anadir.jsp" in raw or "jsp" in raw.lower():
        reasons.append("legacy_jsp_form")
    if "pago" in raw.lower() or "tarjeta" in raw.lower():
        reasons.append("payment_checkout_param")
    if "id=" in raw.lower() or "codigo" in raw.lower():
        reasons.append("numeric_id_param")
    if "B1=" in raw or "B2=" in raw or "submit" in raw.lower():
        reasons.append("form_button_key")
    if "%" in raw:
        reasons.append("url_encoding")
    if not reasons:
        reasons.append("unfamiliar_param_key")
        
    print(f"Identified Cause: {', '.join(reasons)}")
    audit_records.append({
        "rank": idx,
        "score": round(float(score), 4),
        "request_line": first_line,
        "feature_snippet": feat[:150],
        "causes": reasons
    })

with open(ROOT / "reports/v2_1_csic_dev_fp_audit.json", "w", encoding="utf-8") as f:
    json.dump(audit_records, f, indent=2)

print(f"\nSaved FP audit -> reports/v2_1_csic_dev_fp_audit.json")
