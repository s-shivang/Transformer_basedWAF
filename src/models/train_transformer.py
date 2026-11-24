import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
import math
import random
from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np

import torch
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import get_cosine_schedule_with_warmup
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
)

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features
from src.models.transformer_waf import initialize_transformer_model, SPECIAL_STRUCTURAL_TOKENS

ROOT = Path(__file__).resolve().parents[2]
AI_WAF_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
CSIC_DEV_PATH = ROOT / "data/processed/csic_dev.parquet"
HTTP_PARAMS_PATH = ROOT / "data/raw/http_params/payload_train.csv"
OUTPUT_MODEL_DIR = ROOT / "models/saved/transformer_waf"
REPORT_DIR = ROOT / "reports"
OUTPUT_REPORT_PATH = REPORT_DIR / "transformer_training_report.json"

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


def load_training_data() -> Tuple[List[str], List[int], List[str], List[int]]:
    """
    Constructs a balanced cross-domain training and validation set:
    - AI WAF requests
    - CSIC Development Partition (strictly keeping held-out partition sealed!)
    - Representation D: Structured sequence serialization.
    """
    print("\n[DataPrep] Loading datasets for cross-domain training...")

    records = []

    # 1. Load AI WAF
    if AI_WAF_PATH.exists():
        ai_df = pd.read_parquet(AI_WAF_PATH)[["text", "label"]].dropna().copy()
        ai_df["text"] = ai_df["text"].astype(str).str.strip()
        ai_df["label"] = ai_df["label"].astype(str).str.strip().str.lower()
        ai_df = ai_df[ai_df["text"].ne("")].copy()
        ai_df["norm"] = ai_df["text"].str.split().str.join(" ").str.lower()
        ai_df = ai_df.drop_duplicates("norm").reset_index(drop=True)
        print(f"  AI WAF deduplicated samples: {len(ai_df):,}")

        # Subsample if necessary to balance dataset
        ai_benign = ai_df[ai_df["label"] == "benign"]
        ai_mal = ai_df[ai_df["label"] == "malicious"]
        sample_ai_benign = ai_benign.sample(min(len(ai_benign), 6000), random_state=RANDOM_SEED)
        sample_ai_mal = ai_mal.sample(min(len(ai_mal), 3000), random_state=RANDOM_SEED)

        for text in sample_ai_benign["text"]:
            p = parse_raw_http(text, label=0, source="ai_waf")
            records.append((build_features(p, "structured"), 0))
        for text in sample_ai_mal["text"]:
            p = parse_raw_http(text, label=1, source="ai_waf")
            records.append((build_features(p, "structured"), 1))

    # 2. Load CSIC Development Partition (Dev only - Held-Out partition remains sealed!)
    if CSIC_DEV_PATH.exists():
        csic_dev = pd.read_parquet(CSIC_DEV_PATH)
        print(f"  CSIC Development Partition available: {len(csic_dev):,}")
        csic_benign = csic_dev[csic_dev["label"].str.lower() == "benign"]
        csic_mal = csic_dev[csic_dev["label"].str.lower().isin(["malicious", "anomalous"])]

        # Sample from CSIC dev to give model exposure to Spanish e-commerce vocabulary
        sample_csic_benign = csic_benign.sample(min(len(csic_benign), 4000), random_state=RANDOM_SEED)
        sample_csic_mal = csic_mal.sample(min(len(csic_mal), 3000), random_state=RANDOM_SEED)

        for text in sample_csic_benign["request_text"]:
            p = parse_raw_http(text, label=0, source="csic_dev")
            records.append((build_features(p, "structured"), 0))
        for text in sample_csic_mal["request_text"]:
            p = parse_raw_http(text, label=1, source="csic_dev")
            records.append((build_features(p, "structured"), 1))

    # 3. Load HTTP Params Payloads (Fixed: correctly parse string 'anom' labels)
    if HTTP_PARAMS_PATH.exists():
        hp_df = pd.read_csv(HTTP_PARAMS_PATH).dropna().copy()
        if "payload" in hp_df.columns and "label" in hp_df.columns:
            is_mal = hp_df["label"].astype(str).str.strip().str.lower().isin(["anom", "1", "malicious"])
            hp_mal = hp_df[is_mal]
            sample_hp_mal = hp_mal.sample(min(len(hp_mal), 2000), random_state=RANDOM_SEED)
            for pl in sample_hp_mal["payload"]:
                feat = f"[METHOD] GET [PATH] /search [PARAM] q={pl} [PAYLOAD] {pl}"
                records.append((feat, 1))

    # Shuffle
    random.shuffle(records)
    texts, labels = zip(*records)
    print(f"[DataPrep] Total combined training records: {len(texts):,} (Benign: {labels.count(0):,}, Malicious: {labels.count(1):,})")

    # Train / Val Split (85% train, 15% validation)
    X_train, X_val, y_train, y_val = train_test_split(
        list(texts),
        list(labels),
        test_size=0.15,
        random_state=RANDOM_SEED,
        stratify=list(labels),
    )

    print(f"  Train set: {len(X_train):,}, Validation set: {len(X_val):,}")
    return X_train, y_train, X_val, y_val


def evaluate_dataset(
    model, dataloader, device: torch.device, use_fp16: bool = False
) -> Dict[str, Any]:
    """Evaluates model performance and computes metrics."""
    model.eval()
    all_preds = []
    all_probs = []
    all_labels = []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            if use_fp16:
                with torch.amp.autocast(device_type=device.type, dtype=torch.float16):
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            else:
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)

            logits = outputs.logits
            probs = torch.softmax(logits, dim=-1)
            preds = torch.argmax(logits, dim=-1)

            all_probs.extend(probs[:, 1].cpu().tolist())
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels.cpu().tolist())

    acc = float(accuracy_score(all_labels, all_preds))
    prec = float(precision_score(all_labels, all_preds, pos_label=1, zero_division=0))
    rec = float(recall_score(all_labels, all_preds, pos_label=1, zero_division=0))
    f1 = float(f1_score(all_labels, all_preds, pos_label=1, zero_division=0))
    auc = float(roc_auc_score(all_labels, all_probs)) if len(set(all_labels)) > 1 else 1.0

    cm = confusion_matrix(all_labels, all_preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "roc_auc": round(auc, 4),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def train_model(
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    num_epochs: int = 3,
    batch_size: int = 16,
    learning_rate: float = 2e-5,
    max_length: int = 192,
):
    set_seed(RANDOM_SEED)

    if torch.cuda.is_available():
        device = torch.device("cuda:0")
        device_name = torch.cuda.get_device_name(0)
        vram_gb = torch.cuda.get_device_properties(0).total_memory / 1e9
        use_fp16 = True
        print(f"[Training] Hardware: {device_name} ({vram_gb:.2f} GB VRAM) with FP16 enabled")
    else:
        device = torch.device("cpu")
        use_fp16 = False
        print("[Training] Hardware: CPU (FP32)")

    # 1. Load data
    X_train, y_train, X_val, y_val = load_training_data()

    # 2. Initialize Model & Tokenizer
    model, tokenizer = initialize_transformer_model(
        model_name_or_path=model_name,
        num_labels=2,
        device=device,
    )

    # 3. Create Datasets & DataLoaders
    train_dataset = WAFRequestDataset(X_train, y_train, tokenizer, max_length=max_length)
    val_dataset = WAFRequestDataset(X_val, y_val, tokenizer, max_length=max_length)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, pin_memory=(device.type == "cuda"))
    val_loader = DataLoader(val_dataset, batch_size=batch_size * 2, shuffle=False)

    # 4. Optimizer & Scheduler
    total_steps = len(train_loader) * num_epochs
    warmup_steps = int(total_steps * 0.1)

    optimizer = AdamW(model.parameters(), lr=learning_rate, weight_decay=0.01)
    scheduler = get_cosine_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=total_steps,
    )
    scaler = torch.amp.GradScaler(device.type, enabled=use_fp16)

    print(f"\n[Training] Starting fine-tuning: {num_epochs} epochs, {total_steps} steps, lr={learning_rate}")
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

            if step % 100 == 0 or step == len(train_loader):
                print(f"  Epoch {epoch}/{num_epochs} | Step {step}/{len(train_loader)} | Loss: {loss.item():.4f}")

        avg_loss = total_loss / len(train_loader)
        epoch_dur = time.time() - t0

        # Evaluate on validation partition
        val_metrics = evaluate_dataset(model, val_loader, device, use_fp16=use_fp16)
        print(f"\n>> Epoch {epoch} Complete ({epoch_dur:.1f}s) | Avg Train Loss: {avg_loss:.4f}")
        print(f"   Val Metrics: Acc: {val_metrics['accuracy']} | F1: {val_metrics['f1']} | Recall: {val_metrics['recall']} | FPR: {val_metrics['fpr']}")
        print(f"   Confusion Matrix: {val_metrics['confusion_matrix']}\n")

        history.append({
            "epoch": epoch,
            "train_loss": round(avg_loss, 4),
            "val_metrics": val_metrics,
            "duration_s": round(epoch_dur, 1),
        })

        if val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            print(f"  [Checkpoint] Saving new best model to {OUTPUT_MODEL_DIR} (F1: {best_f1:.4f})...")
            OUTPUT_MODEL_DIR.mkdir(parents=True, exist_ok=True)
            model.save_pretrained(OUTPUT_MODEL_DIR)
            tokenizer.save_pretrained(OUTPUT_MODEL_DIR)

    total_time = time.time() - t_start
    print(f"\n[Training Complete] Total elapsed time: {total_time:.1f}s | Best Val F1: {best_f1:.4f}")

    # Save training report
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_data = {
        "model_name": model_name,
        "device": str(device),
        "num_epochs": num_epochs,
        "batch_size": batch_size,
        "learning_rate": learning_rate,
        "total_training_time_seconds": round(total_time, 1),
        "best_val_f1": best_f1,
        "history": history,
    }
    with open(OUTPUT_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"Saved training report to: {OUTPUT_REPORT_PATH}")


if __name__ == "__main__":
    train_model()
