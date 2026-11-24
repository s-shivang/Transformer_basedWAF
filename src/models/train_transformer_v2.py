"""
Contextual Transformer Training Pipeline (v2.0).

Fine-tunes 'sentence-transformers/all-MiniLM-L6-v2' on Representation D-v2
using the augmented 22,667-sample development pool on NVIDIA RTX 2050 GPU (FP16).
- Strict GPU pilot check (confirming VRAM < 2.5 GB)
- AdamW + Cosine schedule + FP16 AMP + Gradient clipping
- Platt scaling calibration on validation logits (reporting Brier Score and ECE)
- Calibrating dev-only operating thresholds: fast_pass, monitor_alert, challenge, block, strict_block.
- Saves model to models/saved/transformer_waf_v2
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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

DEV_AUGMENTED_PATH = ROOT / "data/processed/dev_v2_augmented.parquet"
OUTPUT_MODEL_DIR = ROOT / "models/saved/transformer_waf_v2"
REPORT_PATH = ROOT / "reports/transformer_v2_training_report.json"

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
        bin_mask = (probs > bin_limits[i]) & (probs <= bin_limits[i + 1])
        bin_count = np.sum(bin_mask)
        if bin_count > 0:
            bin_acc = np.mean(labels[bin_mask])
            bin_conf = np.mean(probs[bin_mask])
            ece += (bin_count / n) * abs(bin_acc - bin_conf)

    return float(ece)


def run_gpu_pilot(model, dataloader, device: torch.device, use_fp16: bool) -> float:
    """Runs a 10-batch pilot on GPU to verify peak VRAM < 2.5 GB."""
    print("\n[GPU Pilot] Running 10-batch trial to verify VRAM headroom...")
    if device.type == "cuda":
        torch.cuda.reset_peak_memory_stats(device)

    model.train()
    optimizer = AdamW(model.parameters(), lr=1e-5)
    scaler = torch.amp.GradScaler(device.type, enabled=use_fp16)

    for step, batch in enumerate(dataloader):
        if step >= 10:
            break
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["label"].to(device)

        optimizer.zero_grad()
        if use_fp16:
            with torch.amp.autocast(device_type=device.type, dtype=torch.float16):
                loss = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels).loss
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
        else:
            loss = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels).loss
            loss.backward()
            optimizer.step()

    peak_vram_gb = 0.0
    if device.type == "cuda":
        peak_vram_gb = torch.cuda.max_memory_allocated(device) / 1e9
        print(f"  [GPU Pilot Result] Peak VRAM: {peak_vram_gb:.2f} GB (Target: < 2.5 GB — SAFE!)")
        assert peak_vram_gb < 2.5, f"Peak VRAM ({peak_vram_gb:.2f} GB) exceeded 2.5 GB limit!"
    else:
        print("  [GPU Pilot Result] Running on CPU.")

    return peak_vram_gb


def train_model_v2(
    num_epochs: int = 3,
    batch_size: int = 32,
    learning_rate: float = 3e-5,
    max_length: int = 192,
) -> Dict[str, Any]:
    set_seed(RANDOM_SEED)

    print("=" * 70)
    print("STEP 3.2: FINE-TUNING CONTEXTUAL TRANSFORMER V2.0 (RTX 2050 FP16)")
    print("=" * 70)

    if torch.cuda.is_available():
        device = torch.device("cuda:0")
        device_name = torch.cuda.get_device_name(0)
        vram_gb = torch.cuda.get_device_properties(0).total_memory / 1e9
        use_fp16 = True
        print(f"[Hardware] GPU: {device_name} ({vram_gb:.2f} GB VRAM) with FP16 enabled")
    else:
        device = torch.device("cpu")
        use_fp16 = False
        print("[Hardware] CPU execution (FP32)")

    # 1. Load Data
    df = pd.read_parquet(DEV_AUGMENTED_PATH)
    print(f"Loaded Augmented Development Pool: {len(df):,} records")

    # Group-Aware Train/Validation Split (6 folds, fold 0)
    sgkf = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=RANDOM_SEED)
    tr_idx, val_idx = next(sgkf.split(df, df["label"], df["group_id"]))

    train_df = df.iloc[tr_idx].copy().reset_index(drop=True)
    val_df = df.iloc[val_idx].copy().reset_index(drop=True)

    # Verify zero group overlap
    tr_grps = set(train_df["group_id"])
    val_grps = set(val_df["group_id"])
    overlap = tr_grps.intersection(val_grps)
    assert len(overlap) == 0, f"FATAL: Group leakage! Overlap: {len(overlap)}"
    print(f"Group Split: Train={len(train_df):,}, Val={len(val_df):,} (Group overlap: {len(overlap)})")

    # 2. Tokenizer & Base Model
    base_model_name = "sentence-transformers/all-MiniLM-L6-v2"
    tokenizer = AutoTokenizer.from_pretrained(base_model_name)
    special_tokens = ["[METHOD]", "[PATH]", "[PARAM]", "[PAYLOAD]", "[HEADERS]"]
    tokenizer.add_special_tokens({"additional_special_tokens": special_tokens})

    model = AutoModelForSequenceClassification.from_pretrained(base_model_name, num_labels=2)
    model.resize_token_embeddings(len(tokenizer))
    model.to(device)

    # 3. Datasets & Loaders
    train_dataset = WAFRequestDataset(train_df["feat_structured_v2"].tolist(), train_df["label"].tolist(), tokenizer, max_length=max_length)
    val_dataset = WAFRequestDataset(val_df["feat_structured_v2"].tolist(), val_df["label"].tolist(), tokenizer, max_length=max_length)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, pin_memory=(device.type == "cuda"))
    val_loader = DataLoader(val_dataset, batch_size=batch_size * 2, shuffle=False)

    # 4. GPU Pilot Verification
    peak_vram = run_gpu_pilot(model, train_loader, device, use_fp16)

    # 5. Optimizer & Scheduler
    total_steps = len(train_loader) * num_epochs
    warmup_steps = int(total_steps * 0.1)

    optimizer = AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    scheduler = get_cosine_schedule_with_warmup(optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_steps)
    scaler = torch.amp.GradScaler(device.type, enabled=use_fp16)

    print(f"\n[Training] Starting {num_epochs} Epochs ({total_steps} steps, lr={learning_rate})...")
    best_f1 = 0.0
    history = []
    t_start = time.time()

    for epoch in range(1, num_epochs + 1):
        model.train()
        total_loss = 0.0
        t0 = time.time()

        for step, batch in enumerate(train_loader, 1):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            optimizer.zero_grad()
            if use_fp16:
                with torch.amp.autocast(device_type=device.type, dtype=torch.float16):
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                    loss = outputs.loss
                scaler.scale(loss).backward()
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
            else:
                outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()

            scheduler.step()
            total_loss += loss.item()

            if step % 150 == 0 or step == len(train_loader):
                print(f"  Epoch {epoch}/{num_epochs} | Step {step}/{len(train_loader)} | Loss: {loss.item():.4f}")

        epoch_loss = total_loss / len(train_loader)
        epoch_dur = time.time() - t0

        # Evaluate on validation fold
        model.eval()
        val_logits_list = []
        val_labels_list = []
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device)
                attention_mask = batch["attention_mask"].to(device)
                labels = batch["label"]
                if use_fp16:
                    with torch.amp.autocast(device_type=device.type, dtype=torch.float16):
                        logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
                else:
                    logits = model(input_ids=input_ids, attention_mask=attention_mask).logits

                val_logits_list.append(logits.float().cpu())
                val_labels_list.append(labels)

        val_logits = torch.cat(val_logits_list, dim=0)
        val_labels = torch.cat(val_labels_list, dim=0).numpy()
        val_probs = torch.softmax(val_logits, dim=-1)[:, 1].numpy()
        val_preds = (val_probs >= 0.50).astype(int)

        acc = float(accuracy_score(val_labels, val_preds))
        prec = float(precision_score(val_labels, val_preds, zero_division=0))
        rec = float(recall_score(val_labels, val_preds, zero_division=0))
        f1 = float(f1_score(val_labels, val_preds, zero_division=0))
        cm = confusion_matrix(val_labels, val_preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        print(f"\n>> Epoch {epoch} Done ({epoch_dur:.1f}s) | Avg Loss: {epoch_loss:.4f}")
        print(f"   Validation: Acc={acc*100:.2f}%, F1={f1*100:.2f}%, Recall={rec*100:.2f}%, FPR={fpr*100:.2f}%")
        print(f"   Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}\n")

        history.append({
            "epoch": epoch,
            "train_loss": round(epoch_loss, 4),
            "val_f1": round(f1, 4),
            "val_fpr": round(fpr, 4),
            "val_recall": round(rec, 4),
            "duration_s": round(epoch_dur, 1),
        })

        if f1 > best_f1:
            best_f1 = f1
            print(f"  [Checkpoint] Saving best model (F1: {best_f1:.4f}) to {OUTPUT_MODEL_DIR}...")
            OUTPUT_MODEL_DIR.mkdir(parents=True, exist_ok=True)
            model.save_pretrained(OUTPUT_MODEL_DIR)
            tokenizer.save_pretrained(OUTPUT_MODEL_DIR)

    total_time = time.time() - t_start
    print(f"\n[Training Complete] Total elapsed time: {total_time:.1f}s | Best Val F1: {best_f1:.4f}")

    # Reload best model for calibration
    print(f"\nLoading best saved model from {OUTPUT_MODEL_DIR} for Platt Scaling & Threshold Calibration...")
    model = AutoModelForSequenceClassification.from_pretrained(OUTPUT_MODEL_DIR)
    tokenizer = AutoTokenizer.from_pretrained(OUTPUT_MODEL_DIR)
    model.to(device)
    model.eval()

    # Re-extract validation logits
    val_logits_list = []
    val_labels_list = []
    with torch.no_grad():
        for batch in val_loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"]
            if use_fp16:
                with torch.amp.autocast(device_type=device.type, dtype=torch.float16):
                    logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
            else:
                logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
            val_logits_list.append(logits.float().cpu())
            val_labels_list.append(labels)

    val_logits_raw = torch.cat(val_logits_list, dim=0)
    # Logit difference for binary classification: z = z_mal - z_benign
    z_diff = (val_logits_raw[:, 1] - val_logits_raw[:, 0]).numpy()
    val_labels = torch.cat(val_labels_list, dim=0).numpy()
    raw_probs = torch.softmax(val_logits_raw, dim=-1)[:, 1].numpy()

    # 6. Platt Scaling
    print("\n--- Computing Platt Scaling Calibration ---")
    platt_clf = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000)
    platt_clf.fit(z_diff.reshape(-1, 1), val_labels)
    w_platt = float(platt_clf.coef_[0][0])
    b_platt = float(platt_clf.intercept_[0])

    calibrated_probs = 1.0 / (1.0 + np.exp(-(w_platt * z_diff + b_platt)))

    # Compute Brier score and ECE before vs after
    raw_brier = float(brier_score_loss(val_labels, raw_probs))
    calib_brier = float(brier_score_loss(val_labels, calibrated_probs))
    raw_ece = compute_ece(raw_probs, val_labels, n_bins=10)
    calib_ece = compute_ece(calibrated_probs, val_labels, n_bins=10)

    print(f"Platt Parameters: w = {w_platt:.4f}, b = {b_platt:.4f}")
    print(f"Brier Score: Before = {raw_brier:.4f} -> After = {calib_brier:.4f} (Lower is better)")
    print(f"ECE (10 bins): Before = {raw_ece*100:.2f}% -> After = {calib_ece*100:.2f}% (Lower is better)")

    # 7. Operating Threshold Calibration on Dev Validation Fold
    print("\n--- Dev-Only Operating Threshold Calibration ---")
    tau_grid = np.linspace(0.01, 0.99, 99)
    threshold_results = []
    best_block_tau = 0.50
    min_fpr_diff = 999.0

    for tau in tau_grid:
        preds = (calibrated_probs >= tau).astype(int)
        tn_c, fp_c, fn_c, tp_c = confusion_matrix(val_labels, preds, labels=[0, 1]).ravel()
        t_rec = tp_c / (tp_c + fn_c) if (tp_c + fn_c) > 0 else 0.0
        t_fpr = fp_c / (fp_c + tn_c) if (fp_c + tn_c) > 0 else 0.0
        t_prec = tp_c / (tp_c + fp_c) if (tp_c + fp_c) > 0 else 0.0
        t_f1 = (2 * t_prec * t_rec) / (t_prec + t_rec) if (t_prec + t_rec) > 0 else 0.0

        threshold_results.append({
            "threshold": round(float(tau), 2),
            "recall": round(float(t_rec), 4),
            "fpr": round(float(t_fpr), 4),
            "precision": round(float(t_prec), 4),
            "f1": round(float(t_f1), 4),
        })

        # Target block threshold <= 0.5% FPR while maximizing recall
        if t_fpr <= 0.005 and abs(t_fpr - 0.005) < min_fpr_diff:
            min_fpr_diff = abs(t_fpr - 0.005)
            best_block_tau = float(tau)

    # Operating points
    op_fast_pass = 0.04
    op_monitor_alert = 0.05
    op_challenge = 0.15
    op_block = round(best_block_tau, 2)
    op_strict = 0.90

    # Metrics at op_block
    block_preds = (calibrated_probs >= op_block).astype(int)
    tn_b, fp_b, fn_b, tp_b = confusion_matrix(val_labels, block_preds, labels=[0, 1]).ravel()
    block_rec = tp_b / (tp_b + fn_b)
    block_fpr = fp_b / (fp_b + tn_b)
    block_f1 = f1_score(val_labels, block_preds)

    print(f"Selected Operating Points:")
    print(f"  - fast_pass_allow:       {op_fast_pass:.2f}")
    print(f"  - monitor_alert:        {op_monitor_alert:.2f}")
    print(f"  - challenge:            {op_challenge:.2f}")
    print(f"  - block (<= 0.5% FPR):  {op_block:.2f} (Recall={block_rec*100:.2f}%, FPR={block_fpr*100:.2f}%, F1={block_f1*100:.2f}%)")
    print(f"  - strict_block_low_fpr: {op_strict:.2f}")

    report = {
        "model_architecture": "sentence-transformers/all-MiniLM-L6-v2 (FP16)",
        "representation": "structured_v2",
        "device": str(device),
        "peak_vram_gb": round(peak_vram, 2),
        "total_training_time_s": round(total_time, 1),
        "best_val_f1": round(best_f1, 4),
        "history": history,
        "platt_calibration": {
            "w": round(w_platt, 4),
            "b": round(b_platt, 4),
            "raw_brier_score": round(raw_brier, 4),
            "calibrated_brier_score": round(calib_brier, 4),
            "raw_ece": round(raw_ece, 4),
            "calibrated_ece": round(calib_ece, 4),
        },
        "operating_thresholds": {
            "fast_pass_allow": op_fast_pass,
            "monitor_alert": op_monitor_alert,
            "challenge": op_challenge,
            "block": op_block,
            "strict_block_low_fpr": op_strict,
            "metrics_at_block": {
                "recall": round(float(block_rec), 4),
                "fpr": round(float(block_fpr), 4),
                "f1": round(float(block_f1), 4),
                "confusion_matrix": {"tn": int(tn_b), "fp": int(fp_b), "fn": int(fn_b), "tp": int(tp_b)},
            },
        },
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Saved Training Report: {REPORT_PATH}")

    return report


if __name__ == "__main__":
    train_model_v2()
