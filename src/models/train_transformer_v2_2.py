"""
Contextual Transformer Training Pipeline (v2.2).

Fine-tunes 'sentence-transformers/all-MiniLM-L6-v2' on Representation D-v2.2
(Smart Path Normalization + Smart Parameter-Key Normalization + Hard-Negative Benign Augmentation
+ Balanced HttpParams) using the augmented 24,846-sample development pool on NVIDIA RTX 2050 GPU (FP16).
- Strict GPU pilot check (confirming VRAM < 2.5 GB)
- Balanced class-weighted loss (CrossEntropyLoss with w_0 = N/(2*N_0), w_1 = N/(2*N_1))
- AdamW + Cosine schedule + FP16 AMP + Gradient clipping
- Platt scaling calibration on validation logits (reporting Brier Score and ECE)
- Calibrating dev-only operating thresholds: fast_pass (0.04), monitor_alert (0.05), challenge (0.50), block (0.85).
- Saves model to models/saved/transformer_waf_v2_2
"""
import sys
import os
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

import json
import time
import math
import random
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
import numpy as np

import torch
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_cosine_schedule_with_warmup
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    brier_score_loss,
)

DEV_AUGMENTED_PATH = ROOT / "data/processed/dev_v2_2_augmented.parquet"
OUTPUT_MODEL_DIR = ROOT / "models/saved/transformer_waf_v2_2"
REPORT_PATH = ROOT / "reports/transformer_v2_2_training_report.json"

RANDOM_SEED = 42


def set_seed(seed: int = RANDOM_SEED):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


class WAFRequestDataset(Dataset):
    """PyTorch Dataset for structured HTTP request representations."""

    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_length: int = 192):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        text = str(self.texts[idx])
        label = int(self.labels[idx])

        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "label": torch.tensor(label, dtype=torch.long),
        }


def compute_ece(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> float:
    """Computes Expected Calibration Error (ECE) across n_bins."""
    bin_limits = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(probs)
    for i in range(n_bins):
        low, high = bin_limits[i], bin_limits[i + 1]
        mask = (probs >= low) & (probs < high) if i < n_bins - 1 else (probs >= low) & (probs <= high)
        bin_count = np.sum(mask)
        if bin_count > 0:
            bin_acc = np.mean(labels[mask])
            bin_conf = np.mean(probs[mask])
            ece += (bin_count / n) * abs(bin_acc - bin_conf)
    return float(ece)


def train_transformer_v2_2(
    epochs: int = 2,
    batch_size: int = 32,
    lr: float = 3e-5,
    max_length: int = 192,
) -> Dict[str, Any]:
    print("=" * 70)
    print("STEP 3: FINE-TUNING CONTEXTUAL TRANSFORMER ON REPRESENTATION D-V2.2")
    print("=" * 70)

    set_seed(RANDOM_SEED)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    if device.type == "cuda":
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM Allocated: {torch.cuda.memory_allocated() / (1024**2):.1f} MB")
        print(f"VRAM Reserved:  {torch.cuda.memory_reserved() / (1024**2):.1f} MB")

    if not DEV_AUGMENTED_PATH.exists():
        raise FileNotFoundError(f"Missing {DEV_AUGMENTED_PATH}. Run generate_dataset_v2_2.py first.")

    df = pd.read_parquet(DEV_AUGMENTED_PATH)
    print(f"Loaded Augmented Development Pool: {len(df):,} total samples.")

    # 6-Fold Stratified Group Split (Zero Leakage)
    sgkf = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=RANDOM_SEED)
    train_idx, val_idx = next(sgkf.split(df, df["label"], df["group_id"]))

    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    val_df = df.iloc[val_idx].copy().reset_index(drop=True)

    tr_grps = set(train_df["group_id"])
    val_grps = set(val_df["group_id"])
    assert len(tr_grps.intersection(val_grps)) == 0, "FATAL: Group leakage detected!"

    print(f"Train samples: {len(train_df):,} | Val samples: {len(val_df):,}")
    print(f"Train Benign: {sum(train_df['label'] == 0):,}, Train Malicious: {sum(train_df['label'] == 1):,}")
    print(f"Val Benign:   {sum(val_df['label'] == 0):,}, Val Malicious:   {sum(val_df['label'] == 1):,}")

    # Load Base Tokenizer & Model from Local Cache
    # We can point to models/saved/transformer_waf_v1_0 or models/frozen/v1_0/weights or HuggingFace local cache
    base_model_source = ROOT / "models/saved/transformer_waf_v1_0"
    if not base_model_source.exists():
        base_model_source = ROOT / "models/frozen/v1_0/weights"
    if not base_model_source.exists():
        base_model_source = "sentence-transformers/all-MiniLM-L6-v2"

    print(f"Loading base tokenizer and model from: {base_model_source}")
    tokenizer = AutoTokenizer.from_pretrained(str(base_model_source))
    model = AutoModelForSequenceClassification.from_pretrained(str(base_model_source), num_labels=2)
    model.to(device)

    # Datasets & Loaders
    train_dataset = WAFRequestDataset(train_df["feat_structured_v2_2"].tolist(), train_df["label"].tolist(), tokenizer, max_length)
    val_dataset = WAFRequestDataset(val_df["feat_structured_v2_2"].tolist(), val_df["label"].tolist(), tokenizer, max_length)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_dataset, batch_size=batch_size * 2, shuffle=False, num_workers=0)

    # Balanced Class Weights for Cross-Entropy Loss
    n_train = len(train_df)
    n_0 = sum(train_df["label"] == 0)
    n_1 = sum(train_df["label"] == 1)
    w_0 = n_train / (2.0 * n_0)
    w_1 = n_train / (2.0 * n_1)
    class_weights = torch.tensor([w_0, w_1], dtype=torch.float).to(device)
    loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights)
    print(f"Balanced Loss Class Weights: w_0 (Benign)={w_0:.3f}, w_1 (Malicious)={w_1:.3f}")

    # Pilot 5-batch VRAM Verification Check
    print("\nRunning GPU Pilot Check (5 batches)...")
    model.train()
    optimizer_pilot = AdamW(model.parameters(), lr=lr)
    scaler_pilot = torch.cuda.amp.GradScaler(enabled=(device.type == "cuda"))

    for p_idx, batch in enumerate(train_loader):
        if p_idx >= 5:
            break
        optimizer_pilot.zero_grad()
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["label"].to(device)
        with torch.cuda.amp.autocast(enabled=(device.type == "cuda")):
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = loss_fn(outputs.logits, labels)
        scaler_pilot.scale(loss).backward()
        scaler_pilot.step(optimizer_pilot)
        scaler_pilot.update()

    if device.type == "cuda":
        peak_vram = torch.cuda.max_memory_allocated() / (1024**2)
        print(f"Pilot Peak VRAM: {peak_vram:.1f} MB (Safety Limit: < 2,500 MB) -> {'PASS' if peak_vram < 2500 else 'FAIL'}")
        assert peak_vram < 2500, f"VRAM budget exceeded: {peak_vram} MB"

    # Reset Model for Real Training
    print("\nRe-initializing model weights for clean 2-epoch run...")
    model = AutoModelForSequenceClassification.from_pretrained(str(base_model_source), num_labels=2)
    model.to(device)

    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    total_steps = len(train_loader) * epochs
    warmup_steps = int(total_steps * 0.1)
    scheduler = get_cosine_schedule_with_warmup(optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_steps)
    scaler = torch.cuda.amp.GradScaler(enabled=(device.type == "cuda"))

    print(f"Starting Training: {epochs} Epochs, {len(train_loader)} Steps/Epoch, Total Steps={total_steps}")
    start_time = time.time()

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        t_epoch_start = time.time()

        for step, batch in enumerate(train_loader):
            optimizer.zero_grad()
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            with torch.cuda.amp.autocast(enabled=(device.type == "cuda")):
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                loss = loss_fn(outputs.logits, labels)

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()

            total_loss += loss.item()

            if (step + 1) % 150 == 0 or (step + 1) == len(train_loader):
                elapsed = time.time() - t_epoch_start
                avg_l = total_loss / (step + 1)
                lr_curr = scheduler.get_last_lr()[0]
                print(f"  Epoch {epoch}/{epochs} | Step {step+1}/{len(train_loader)} | Loss: {avg_l:.4f} | LR: {lr_curr:.2e} | Elapsed: {elapsed:.1f}s")

    total_train_time = time.time() - start_time
    print(f"\nTraining completed in {total_train_time:.1f} seconds ({total_train_time/60:.2f} mins).")

    # Validation Evaluation & Raw Logits Extraction
    print("\nEvaluating on Group-Held-Out Validation Fold...")
    model.eval()
    all_logits = []
    all_targets = []

    with torch.no_grad():
        for batch in val_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)
            with torch.cuda.amp.autocast(enabled=(device.type == "cuda")):
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            diff_logits = outputs.logits[:, 1] - outputs.logits[:, 0]
            all_logits.extend(diff_logits.cpu().float().numpy().tolist())
            all_targets.extend(labels.cpu().numpy().tolist())

    val_logits = np.array(all_logits)
    val_labels = np.array(all_targets)

    # Standard Sigmoid Probs (Uncalibrated)
    raw_probs = 1.0 / (1.0 + np.exp(-val_logits))

    # Platt Scaling Calibration
    print("\nFitting 1D Platt Scaling (w * z + b) on Validation Fold Logits...")
    platt = LogisticRegression(solver="lbfgs", max_iter=1000)
    platt.fit(val_logits.reshape(-1, 1), val_labels)

    platt_w = float(platt.coef_[0][0])
    platt_b = float(platt.intercept_[0])
    print(f"  Fitted Platt Parameters: w = {platt_w:.4f}, b = {platt_b:.4f}")

    # Calibrated Probabilities
    cal_logits = platt_w * val_logits + platt_b
    cal_probs = 1.0 / (1.0 + np.exp(-cal_logits))

    brier_raw = brier_score_loss(val_labels, raw_probs)
    brier_cal = brier_score_loss(val_labels, cal_probs)
    ece_raw = compute_ece(raw_probs, val_labels)
    ece_cal = compute_ece(cal_probs, val_labels)

    roc_auc = float(roc_auc_score(val_labels, cal_probs))
    pr_auc = float(average_precision_score(val_labels, cal_probs))

    print(f"  Raw Brier Score: {brier_raw:.4f} -> Calibrated Brier Score: {brier_cal:.4f}")
    print(f"  Raw ECE:         {ece_raw:.4f} -> Calibrated ECE:         {ece_cal:.4f}")
    print(f"  ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f}")

    # Threshold Performance Table
    thresholds = [0.04, 0.05, 0.50, 0.85]
    perf_table = {}
    for tau in thresholds:
        preds = (cal_probs >= tau).astype(int)
        tn, fp, fn, tp = confusion_matrix(val_labels, preds).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        rec = recall_score(val_labels, preds)
        prec = precision_score(val_labels, preds, zero_division=0)
        perf_table[f"tau_{tau}"] = {
            "threshold": tau,
            "fpr": round(float(fpr), 4),
            "fnr": round(float(fnr), 4),
            "recall": round(float(rec), 4),
            "precision": round(float(prec), 4),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
        }
        print(f"  tau = {tau:.2f} -> FPR={fpr*100:.2f}%, Recall={rec*100:.2f}%, Prec={prec*100:.2f}% (TP={tp}, FP={fp}, TN={tn}, FN={fn})")

    # Save Fine-Tuned Model Weights & Tokenizer
    OUTPUT_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(OUTPUT_MODEL_DIR))
    tokenizer.save_pretrained(str(OUTPUT_MODEL_DIR))
    print(f"\nSaved fine-tuned Transformer model & tokenizer to: {OUTPUT_MODEL_DIR}")

    report = {
        "model_version": "v2.2",
        "representation": "structured_v2_2",
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "training_time_seconds": round(total_train_time, 2),
        "platt_w": round(platt_w, 4),
        "platt_b": round(platt_b, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "brier_score_raw": round(brier_raw, 4),
        "brier_score_calibrated": round(brier_cal, 4),
        "ece_raw": round(ece_raw, 4),
        "ece_calibrated": round(ece_cal, 4),
        "threshold_performance": perf_table,
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Saved Transformer training report to: {REPORT_PATH}")

    return report


if __name__ == "__main__":
    train_transformer_v2_2()
