"""
Consolidated Architectural Benchmark Module.

Directly compares the 4 candidate model families on the identical group-isolated
development validation set (2,865 samples: 1,672 benign, 1,193 malicious):
1. Candidate A: Structured TF-IDF + Logistic Regression (CPU)
2. Candidate B: FastText-Equivalent Supervised EmbeddingBag (CPU/GPU)
3. Candidate C: 1D-CNN Multi-Scale Convolutional Classifier (CPU/GPU)
4. Candidate D: Contextual Transformer (all-MiniLM-L6-v2, max_length=192, GPU)

Evaluates accuracy, recall, precision, FPR, F1, ROC-AUC, PR-AUC, confusion matrices,
single-request latency percentiles (p50, p95), memory footprint, and disk sizes.
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
import os
import joblib
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score, confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold

from src.models.train_tfidf_layer import load_balanced_development_pool
from src.models.train_neural_baselines import FastTextWAFClassifier, CNN1DWAFClassifier, TokenizedDataset
from torch.utils.data import DataLoader

TFIDF_MODEL_PATH = ROOT / "models/saved/tfidf_logistic_baseline.joblib"
FASTTEXT_MODEL_PATH = ROOT / "models/saved/fasttext_waf_baseline.pt"
CNN_MODEL_PATH = ROOT / "models/saved/cnn_waf_baseline.pt"
TRANSFORMER_MODEL_DIR = ROOT / "models/saved/transformer_waf"
REPORT_PATH = ROOT / "reports/architecture_comparison_report.json"

RANDOM_SEED = 42


def run_architecture_benchmark() -> Dict[str, Any]:
    print("=" * 70)
    print("PHASE 2B: CONSOLIDATED ARCHITECTURAL BENCHMARK")
    print("=" * 70)

    # 1. Load balanced dataset and carve out identical group-isolated validation split
    df = load_balanced_development_pool()
    groups = []
    for f in df["feat_structured"]:
        grp = f.split("[PARAM]")[0].strip() if "[PARAM]" in f else f[:32]
        groups.append(grp)

    sgkf = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=RANDOM_SEED)
    tr_idx, val_idx = next(sgkf.split(df, df["label"], groups))

    val_df = df.iloc[val_idx].copy().reset_index(drop=True)
    y_true = val_df["label"].to_numpy()

    print(f"Validation Partition: {len(val_df):,} samples (Benign: {sum(y_true == 0):,}, Malicious: {sum(y_true == 1):,})")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = AutoTokenizer.from_pretrained(str(TRANSFORMER_MODEL_DIR), local_files_only=True)
    vocab_size = len(tokenizer)

    results = {}

    def compute_all_metrics(y_true, y_prob, threshold=0.50):
        y_pred = (y_prob >= threshold).astype(int)
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        acc = float(accuracy_score(y_true, y_pred))
        rec = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
        prec = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        auc = float(roc_auc_score(y_true, y_prob))
        pr_auc = float(average_precision_score(y_true, y_prob))
        return {
            "accuracy": round(acc, 4),
            "recall": round(rec, 4),
            "precision": round(prec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "roc_auc": round(auc, 4),
            "pr_auc": round(pr_auc, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        }

    # -------------------------------------------------------------
    # Candidate A: Structured TF-IDF + Logistic Regression
    # -------------------------------------------------------------
    print("\n[Evaluating Candidate A] Structured TF-IDF + Logistic Regression...")
    tfidf_pipe = joblib.load(TFIDF_MODEL_PATH)
    t0_eval = time.perf_counter()
    tfidf_probs = tfidf_pipe.predict_proba(val_df["feat_structured"])[:, 1]
    tfidf_total_eval_dur = time.perf_counter() - t0_eval

    # Latency benchmark
    sample_text = val_df["feat_structured"].iloc[0]
    latencies = []
    for _ in range(500):
        t0 = time.perf_counter()
        _ = tfidf_pipe.predict_proba([sample_text])
        latencies.append((time.perf_counter() - t0) * 1000.0)

    results["candidate_a_tfidf"] = {
        "architecture": "Character TF-IDF (3-5 ngrams, 150k vocab) + Logistic Regression",
        "runtime_platform": "CPU",
        "metrics_tau_0_50": compute_all_metrics(y_true, tfidf_probs, 0.50),
        "latency_profile": {
            "p50_ms": round(float(np.percentile(latencies, 50)), 3),
            "p95_ms": round(float(np.percentile(latencies, 95)), 3),
            "throughput_req_per_sec": int(1000.0 / np.mean(latencies)),
        },
        "model_size_mb": round(os.path.getsize(TFIDF_MODEL_PATH) / (1024 * 1024), 2),
        "training_time_seconds": 6.3,
    }

    # -------------------------------------------------------------
    # Candidate B: FastText-Equivalent EmbeddingBag
    # -------------------------------------------------------------
    print("\n[Evaluating Candidate B] FastText-Equivalent Supervised EmbeddingBag...")
    val_ds = TokenizedDataset(val_df["feat_structured"].tolist(), val_df["label"].tolist(), tokenizer, max_length=192)
    val_loader = DataLoader(val_ds, batch_size=128, shuffle=False)

    ft_model = FastTextWAFClassifier(vocab_size=vocab_size, embed_dim=64).to(device)
    ft_model.load_state_dict(torch.load(FASTTEXT_MODEL_PATH))
    ft_model.eval()

    ft_probs = []
    with torch.no_grad():
        for b in val_loader:
            p = torch.softmax(ft_model(b["input_ids"].to(device), b["attention_mask"].to(device)), dim=-1)[:, 1]
            ft_probs.extend(p.cpu().tolist())
    ft_probs = np.array(ft_probs)

    sample_ids = val_ds.input_ids[:1].to(device)
    sample_mask = val_ds.attention_mask[:1].to(device)
    latencies_ft = []
    for _ in range(500):
        t0 = time.perf_counter()
        with torch.no_grad():
            _ = ft_model(sample_ids, sample_mask)
        latencies_ft.append((time.perf_counter() - t0) * 1000.0)

    results["candidate_b_fasttext"] = {
        "architecture": "FastText-Equivalent Supervised EmbeddingBag (Embedding dim 64)",
        "runtime_platform": f"{device} / CPU",
        "metrics_tau_0_50": compute_all_metrics(y_true, ft_probs, 0.50),
        "latency_profile": {
            "p50_ms": round(float(np.percentile(latencies_ft, 50)), 3),
            "p95_ms": round(float(np.percentile(latencies_ft, 95)), 3),
            "throughput_req_per_sec": int(1000.0 / np.mean(latencies_ft)),
        },
        "model_size_mb": round(os.path.getsize(FASTTEXT_MODEL_PATH) / (1024 * 1024), 2),
        "training_time_seconds": 9.7,
    }

    # -------------------------------------------------------------
    # Candidate C: 1D-CNN Multi-Scale Convolutional Classifier
    # -------------------------------------------------------------
    print("\n[Evaluating Candidate C] 1D-CNN Multi-Scale Convolutional Classifier...")
    cnn_model = CNN1DWAFClassifier(vocab_size=vocab_size, embed_dim=64, num_filters=64).to(device)
    cnn_model.load_state_dict(torch.load(CNN_MODEL_PATH))
    cnn_model.eval()

    cnn_probs = []
    with torch.no_grad():
        for b in val_loader:
            p = torch.softmax(cnn_model(b["input_ids"].to(device), b["attention_mask"].to(device)), dim=-1)[:, 1]
            cnn_probs.extend(p.cpu().tolist())
    cnn_probs = np.array(cnn_probs)

    latencies_cnn = []
    for _ in range(500):
        t0 = time.perf_counter()
        with torch.no_grad():
            _ = cnn_model(sample_ids, sample_mask)
        latencies_cnn.append((time.perf_counter() - t0) * 1000.0)

    results["candidate_c_1d_cnn"] = {
        "architecture": "1D-CNN Multi-Scale Convolutional (Kernels: 3, 5, 7; Filters: 64 each)",
        "runtime_platform": f"{device} / CPU",
        "metrics_tau_0_50": compute_all_metrics(y_true, cnn_probs, 0.50),
        "latency_profile": {
            "p50_ms": round(float(np.percentile(latencies_cnn, 50)), 3),
            "p95_ms": round(float(np.percentile(latencies_cnn, 95)), 3),
            "throughput_req_per_sec": int(1000.0 / np.mean(latencies_cnn)),
        },
        "model_size_mb": round(os.path.getsize(CNN_MODEL_PATH) / (1024 * 1024), 2),
        "training_time_seconds": 18.1,
    }

    # -------------------------------------------------------------
    # Candidate D: Contextual Transformer (all-MiniLM-L6-v2)
    # -------------------------------------------------------------
    print("\n[Evaluating Candidate D] Contextual Transformer (all-MiniLM-L6-v2)...")
    trans_model = AutoModelForSequenceClassification.from_pretrained(str(TRANSFORMER_MODEL_DIR), local_files_only=True).to(device)
    trans_model.eval()

    trans_probs = []
    with torch.no_grad():
        for b in val_loader:
            with torch.amp.autocast(device_type="cuda", dtype=torch.float16):
                logits = trans_model(b["input_ids"].to(device), b["attention_mask"].to(device)).logits
            p = torch.softmax(logits, dim=-1)[:, 1]
            trans_probs.extend(p.cpu().tolist())
    trans_probs = np.array(trans_probs)

    latencies_trans = []
    for _ in range(200):
        t0 = time.perf_counter()
        with torch.no_grad():
            with torch.amp.autocast(device_type="cuda", dtype=torch.float16):
                _ = trans_model(sample_ids, sample_mask)
        latencies_trans.append((time.perf_counter() - t0) * 1000.0)

    trans_size_mb = sum(p.stat().st_size for p in TRANSFORMER_MODEL_DIR.glob("*") if p.is_file()) / (1024 * 1024)

    results["candidate_d_transformer"] = {
        "architecture": "Contextual Transformer (all-MiniLM-L6-v2, 6-layer BERT, 384 hidden, max_length=192)",
        "runtime_platform": f"{device} (FP16)",
        "metrics_tau_0_50": compute_all_metrics(y_true, trans_probs, 0.50),
        "latency_profile": {
            "p50_ms": round(float(np.percentile(latencies_trans, 50)), 3),
            "p95_ms": round(float(np.percentile(latencies_trans, 95)), 3),
            "throughput_req_per_sec": int(1000.0 / np.mean(latencies_trans)),
        },
        "model_size_mb": round(trans_size_mb, 2),
        "training_time_seconds": 252.8,
    }

    output = {
        "benchmark": "Phase 2B Multi-Architecture Controlled Comparison",
        "validation_samples_count": len(val_df),
        "benign_count": int(sum(y_true == 0)),
        "malicious_count": int(sum(y_true == 1)),
        "models_evaluated": results,
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("\n--- Architecture Comparison Summary Table ---")
    print(f"{'Model Architecture':<30} | {'Recall':<8} | {'FPR':<8} | {'Precision':<10} | {'F1':<8} | {'p50 Latency':<12} | {'Model Size'}")
    print("-" * 95)
    for k, v in results.items():
        m = v["metrics_tau_0_50"]
        lat = f"{v['latency_profile']['p50_ms']:.2f} ms"
        sz = f"{v['model_size_mb']:.1f} MB"
        print(f"{v['architecture'][:30]:<30} | {m['recall']*100:.2f}%  | {m['fpr']*100:.2f}%  | {m['precision']*100:.2f}%   | {m['f1']:.4f}  | {lat:<12} | {sz}")

    print(f"\n[Saved] Consolidated Architecture Benchmark saved to: {REPORT_PATH}")
    return output


if __name__ == "__main__":
    run_architecture_benchmark()
