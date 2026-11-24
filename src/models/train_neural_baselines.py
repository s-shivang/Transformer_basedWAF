"""
Neural Baselines Training Module:
- Candidate B: FastText-Equivalent Lightweight EmbeddingBag Classifier
- Candidate C: 1D-CNN Multi-Scale Convolutional Text Classifier

Trains both lightweight neural candidates on the identical group-held-out split
(15,135 train, 2,865 validation) using the shared subword vocabulary and local RTX 2050 GPU.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, average_precision_score

from src.models.train_tfidf_layer import load_balanced_development_pool

MODEL_DIR = ROOT / "models/saved/transformer_waf"
REPORT_PATH = ROOT / "reports/neural_baselines_report.json"
FASTTEXT_MODEL_PATH = ROOT / "models/saved/fasttext_waf_baseline.pt"
CNN_MODEL_PATH = ROOT / "models/saved/cnn_waf_baseline.pt"

RANDOM_SEED = 42


# =====================================================================
# Candidate B: FastText-Equivalent Supervised EmbeddingBag Architecture
# =====================================================================
class FastTextWAFClassifier(nn.Module):
    """
    Lightweight supervised text classifier mathematically equivalent to FastText:
    computes mean token embedding bag followed by linear projection layers.
    """
    def __init__(self, vocab_size: int, embed_dim: int = 64, num_classes: int = 2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.fc = nn.Sequential(
            nn.Linear(embed_dim, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, num_classes),
        )

    def forward(self, input_ids, attention_mask=None):
        # input_ids: (B, L)
        emb = self.embedding(input_ids)  # (B, L, D)
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(-1).float()  # (B, L, 1)
            sum_emb = torch.sum(emb * mask, dim=1)
            len_mask = torch.clamp(mask.sum(dim=1), min=1.0)
            pooled = sum_emb / len_mask
        else:
            pooled = torch.mean(emb, dim=1)
        return self.fc(pooled)


# =====================================================================
# Candidate C: 1D-CNN Multi-Scale Convolutional Architecture
# =====================================================================
class CNN1DWAFClassifier(nn.Module):
    """
    Lightweight multi-scale 1D Convolutional text classifier:
    Parallel convolutions with kernel sizes 3, 5, 7 + Global Max Pooling + Dropout + Linear Head.
    """
    def __init__(self, vocab_size: int, embed_dim: int = 64, num_filters: int = 64, num_classes: int = 2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv3 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=3, padding=1)
        self.conv5 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=5, padding=2)
        self.conv7 = nn.Conv1d(in_channels=embed_dim, out_channels=num_filters, kernel_size=7, padding=3)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)
        self.fc = nn.Sequential(
            nn.Linear(num_filters * 3, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_classes),
        )

    def forward(self, input_ids, attention_mask=None):
        # (B, L) -> (B, L, D) -> (B, D, L) for Conv1d
        emb = self.embedding(input_ids).transpose(1, 2)
        c3 = self.relu(self.conv3(emb))
        c5 = self.relu(self.conv5(emb))
        c7 = self.relu(self.conv7(emb))

        # Global Max Pooling over time dimension L
        p3 = torch.max(c3, dim=2)[0]
        p5 = torch.max(c5, dim=2)[0]
        p7 = torch.max(c7, dim=2)[0]

        feat = torch.cat([p3, p5, p7], dim=1)  # (B, num_filters * 3)
        feat = self.dropout(feat)
        return self.fc(feat)


class TokenizedDataset(Dataset):
    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_length: int = 192):
        self.labels = labels
        enc = tokenizer(
            texts,
            max_length=max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )
        self.input_ids = enc["input_ids"]
        self.attention_mask = enc["attention_mask"]

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return {
            "input_ids": self.input_ids[idx],
            "attention_mask": self.attention_mask[idx],
            "label": torch.tensor(self.labels[idx], dtype=torch.long),
        }


def evaluate_neural_model(model, dataloader, device) -> Dict[str, Any]:
    model.eval()
    all_preds, all_probs, all_labels = [], [], []
    with torch.no_grad():
        for b in dataloader:
            ids = b["input_ids"].to(device)
            mask = b["attention_mask"].to(device)
            lbl = b["label"].to(device)

            logits = model(ids, mask)
            probs = torch.softmax(logits, dim=-1)[:, 1]
            preds = torch.argmax(logits, dim=-1)

            all_probs.extend(probs.cpu().tolist())
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(lbl.cpu().tolist())

    acc = float(accuracy_score(all_labels, all_preds))
    prec = float(precision_score(all_labels, all_preds, pos_label=1, zero_division=0))
    rec = float(recall_score(all_labels, all_preds, pos_label=1, zero_division=0))
    f1 = float(f1_score(all_labels, all_preds, pos_label=1, zero_division=0))
    auc = float(roc_auc_score(all_labels, all_probs)) if len(set(all_labels)) > 1 else 1.0
    pr_auc = float(average_precision_score(all_labels, all_probs))

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
        "pr_auc": round(pr_auc, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def train_neural_candidate(name: str, model: nn.Module, train_loader, val_loader, device, epochs: int = 5) -> Tuple[Dict[str, Any], float]:
    print(f"\n--- Training {name} on {device} ({epochs} epochs) ---")
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    criterion = nn.CrossEntropyLoss()

    best_f1 = 0.0
    best_metrics = {}
    t0 = time.perf_counter()

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for b in train_loader:
            ids = b["input_ids"].to(device)
            mask = b["attention_mask"].to(device)
            lbl = b["label"].to(device)

            optimizer.zero_grad()
            logits = model(ids, mask)
            loss = criterion(logits, lbl)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        val_res = evaluate_neural_model(model, val_loader, device)
        avg_loss = total_loss / len(train_loader)
        print(f"  Epoch {epoch}/{epochs} | Loss: {avg_loss:.4f} | Val Acc: {val_res['accuracy'] * 100:.2f}% | Val Rec: {val_res['recall'] * 100:.2f}% | Val FPR: {val_res['fpr'] * 100:.2f}% | F1: {val_res['f1']:.4f}")

        if val_res["f1"] > best_f1:
            best_f1 = val_res["f1"]
            best_metrics = val_res

    duration = time.perf_counter() - t0
    print(f"  Completed in {duration:.1f}s | Best Val F1: {best_f1:.4f}")
    return best_metrics, duration


def run_neural_baselines():
    print("=" * 70)
    print("PHASE 2B: CANDIDATES B (FASTTEXT-EQUIVALENT) & C (1D-CNN) TRAINING")
    print("=" * 70)

    # 1. Load balanced dataset and deterministic group split
    df = load_balanced_development_pool()
    from sklearn.model_selection import StratifiedGroupKFold
    groups = []
    for f in df["feat_structured"]:
        grp = f.split("[PARAM]")[0].strip() if "[PARAM]" in f else f[:32]
        groups.append(grp)

    sgkf = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=RANDOM_SEED)
    tr_idx, val_idx = next(sgkf.split(df, df["label"], groups))

    train_df = df.iloc[tr_idx].reset_index(drop=True)
    val_df = df.iloc[val_idx].reset_index(drop=True)

    print(f"Data: Train={len(train_df):,}, Val={len(val_df):,} (Group-Isolated)")

    # 2. Tokenize with shared tokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR), local_files_only=True)
    vocab_size = len(tokenizer)

    train_ds = TokenizedDataset(train_df["feat_structured"].tolist(), train_df["label"].tolist(), tokenizer, max_length=192)
    val_ds = TokenizedDataset(val_df["feat_structured"].tolist(), val_df["label"].tolist(), tokenizer, max_length=192)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    train_loader = DataLoader(train_ds, batch_size=64, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=128, shuffle=False)

    # 3. Train Candidate B: FastText-Equivalent EmbeddingBag
    fasttext_model = FastTextWAFClassifier(vocab_size=vocab_size, embed_dim=64).to(device)
    ft_metrics, ft_dur = train_neural_candidate("Candidate B: FastText-Equivalent EmbeddingBag", fasttext_model, train_loader, val_loader, device, epochs=5)
    torch.save(fasttext_model.state_dict(), FASTTEXT_MODEL_PATH)

    # Measure latency
    sample_ids = val_ds.input_ids[:1].to(device)
    sample_mask = val_ds.attention_mask[:1].to(device)
    t0_lat = time.perf_counter()
    for _ in range(500):
        _ = fasttext_model(sample_ids, sample_mask)
    ft_lat_us = ((time.perf_counter() - t0_lat) / 500) * 1_000_000.0

    # 4. Train Candidate C: 1D-CNN Multi-Scale Convolutional
    cnn_model = CNN1DWAFClassifier(vocab_size=vocab_size, embed_dim=64, num_filters=64).to(device)
    cnn_metrics, cnn_dur = train_neural_candidate("Candidate C: 1D-CNN Multi-Scale Convolutional", cnn_model, train_loader, val_loader, device, epochs=5)
    torch.save(cnn_model.state_dict(), CNN_MODEL_PATH)

    t0_lat = time.perf_counter()
    for _ in range(500):
        _ = cnn_model(sample_ids, sample_mask)
    cnn_lat_us = ((time.perf_counter() - t0_lat) / 500) * 1_000_000.0

    # Compile report
    report = {
        "candidate_b_fasttext": {
            "model_type": "FastText-Equivalent Supervised EmbeddingBag",
            "vocab_size": vocab_size,
            "embed_dim": 64,
            "validation_metrics": ft_metrics,
            "training_time_seconds": round(ft_dur, 2),
            "step_latency_us": round(ft_lat_us, 1),
            "model_size_mb": round(Path(FASTTEXT_MODEL_PATH).stat().st_size / (1024 * 1024), 2),
        },
        "candidate_c_1d_cnn": {
            "model_type": "1D-CNN Multi-Scale Convolutional (Kernels: 3, 5, 7)",
            "vocab_size": vocab_size,
            "embed_dim": 64,
            "num_filters": 64,
            "validation_metrics": cnn_metrics,
            "training_time_seconds": round(cnn_dur, 2),
            "step_latency_us": round(cnn_lat_us, 1),
            "model_size_mb": round(Path(CNN_MODEL_PATH).stat().st_size / (1024 * 1024), 2),
        },
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n[Saved] Neural Baselines Report saved to: {REPORT_PATH}")
    return report


if __name__ == "__main__":
    run_neural_baselines()
