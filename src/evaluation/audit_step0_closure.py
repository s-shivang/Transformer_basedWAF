"""
Step 0 Audit Closure Script:
1. Apples-to-Apples Legacy Check (Legacy TF-IDF on Rep A vs Rep D)
2. Fast-Pass Verification (Exact split, sample counts, score definition, and confusion matrix behind tau=0.04)
3. Truncation Content Audit (Inspect sample of truncated requests at max_length=192)
4. ~27% FPR Root-Cause Audit (Domain shift, source breakdown, score distribution)
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from transformers import AutoTokenizer

from src.models.train_tfidf_layer import load_balanced_development_pool
from sklearn.model_selection import StratifiedGroupKFold
from src.pipeline.feature_builder import build_features
from src.pipeline.parser import parse_raw_http

def run_step0_audit():
    print("=" * 80)
    print("STEP 0: CLOSING REMAINING PHASE 2A AUDIT GAPS")
    print("=" * 80)

    # 1. Load Dataset & Verified Group Split
    df = load_balanced_development_pool()
    print(f"Total dataset loaded: {len(df):,} samples")
    print("Label distribution:\n", df["label"].value_counts().to_dict())
    print("Source distribution:\n", df["source"].value_counts().to_dict())

    sgkf = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    train_idx, val_idx = next(sgkf.split(df, df["label"], df["group_id"]))
    train_df = df.iloc[train_idx].reset_index(drop=True)
    val_df = df.iloc[val_idx].reset_index(drop=True)

    print(f"\nGroup-Aware Split: Train={len(train_df):,} | Val={len(val_df):,}")
    print("Val Label distribution:\n", val_df["label"].value_counts().to_dict())
    print("Val Source distribution:\n", val_df["source"].value_counts().to_dict())

    # Build representations
    print("\nBuilding representations for validation set...")
    val_rep_a = val_df["raw_text"].tolist()
    val_rep_d = val_df["feat_structured"].tolist()
    val_labels = val_df["label"].tolist()

    # -------------------------------------------------------------
    # 2. Apples-to-Apples Legacy Check
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("2. APPLES-TO-APPLES LEGACY CHECK")
    print("-" * 60)
    legacy_model_path = ROOT / "models/saved/legacy_tfidf_raw_baseline.joblib"
    active_model_path = ROOT / "models/saved/tfidf_logistic_baseline.joblib"

    results_legacy = {}
    if legacy_model_path.exists():
        legacy_clf = joblib.load(legacy_model_path)
        classes = list(legacy_clf.classes_)
        mal_idx = classes.index("malicious") if "malicious" in classes else 1

        for rep_name, texts in [("Rep A (Native Raw Flat)", val_rep_a), ("Rep D (Structured)", val_rep_d)]:
            probs = legacy_clf.predict_proba(texts)[:, mal_idx]
            preds = (probs >= 0.5).astype(int)
            acc = accuracy_score(val_labels, preds)
            rec = recall_score(val_labels, preds, zero_division=0)
            prec = precision_score(val_labels, preds, zero_division=0)
            f1 = f1_score(val_labels, preds, zero_division=0)
            cm = confusion_matrix(val_labels, preds, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            results_legacy[f"Legacy Model on {rep_name}"] = {
                "accuracy": round(float(acc), 4),
                "recall": round(float(rec), 4),
                "precision": round(float(prec), 4),
                "f1": round(float(f1), 4),
                "fpr": round(float(fpr), 4),
                "cm": [[int(tn), int(fp)], [int(fn), int(tp)]],
            }
            print(f"  Legacy TF-IDF on {rep_name}:")
            print(f"    Acc: {acc:.4f} | Rec: {rec:.4f} | Prec: {prec:.4f} | F1: {f1:.4f} | FPR: {fpr:.4f}")
            print(f"    Confusion Matrix: [[TN: {tn}, FP: {fp}], [FN: {fn}, TP: {tp}]]")

    if active_model_path.exists():
        active_clf = joblib.load(active_model_path)
        classes = list(active_clf.classes_)
        mal_idx = classes.index("malicious") if "malicious" in classes else 1
        probs = active_clf.predict_proba(val_rep_d)[:, mal_idx]
        preds = (probs >= 0.5).astype(int)
        acc = accuracy_score(val_labels, preds)
        rec = recall_score(val_labels, preds, zero_division=0)
        prec = precision_score(val_labels, preds, zero_division=0)
        f1 = f1_score(val_labels, preds, zero_division=0)
        cm = confusion_matrix(val_labels, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        results_legacy["Retrained Layer 2 on Rep D"] = {
            "accuracy": round(float(acc), 4),
            "recall": round(float(rec), 4),
            "precision": round(float(prec), 4),
            "f1": round(float(f1), 4),
            "fpr": round(float(fpr), 4),
            "cm": [[int(tn), int(fp)], [int(fn), int(tp)]],
        }
        print(f"  Retrained Layer 2 TF-IDF on Rep D:")
        print(f"    Acc: {acc:.4f} | Rec: {rec:.4f} | Prec: {prec:.4f} | F1: {f1:.4f} | FPR: {fpr:.4f}")
        print(f"    Confusion Matrix: [[TN: {tn}, FP: {fp}], [FN: {fn}, TP: {tp}]]")

    # -------------------------------------------------------------
    # 3. Fast-Pass Verification (tau_fast_pass = 0.04)
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("3. FAST-PASS VERIFICATION (tau_fast_pass = 0.04)")
    print("-" * 60)
    # Test on full 18,000 dataset and val set
    for split_name, t_df, t_texts in [("Validation Set (2,865 samples)", val_df, val_rep_d), ("Full Development Pool (18,000 samples)", df, df["feat_structured"].tolist())]:
        t_labels = t_df["label"].tolist()
        probs = active_clf.predict_proba(t_texts)[:, mal_idx]
        
        benign_mask = np.array(t_labels) == 0
        mal_mask = np.array(t_labels) == 1
        
        benign_total = int(np.sum(benign_mask))
        mal_total = int(np.sum(mal_mask))
        
        # Fast pass occurs when risk_score < 0.04
        tau = 0.04
        fast_passed = probs < tau
        benign_fp = int(np.sum(fast_passed & benign_mask))
        mal_fp = int(np.sum(fast_passed & mal_mask))  # Leaked attacks!
        
        print(f"  {split_name}:")
        print(f"    Total Benign: {benign_total:,} | Fast-Passed Benign: {benign_fp:,} ({benign_fp/benign_total*100:.2f}%)")
        print(f"    Total Attacks: {mal_total:,} | Leaked Attacks: {mal_fp} ({mal_fp/mal_total*100:.4f}%)")
        if mal_fp == 0:
            print("    [VERIFIED ZERO FALSE NEGATIVES] Exactly 0 attacks leaked through fast-pass!")

    # -------------------------------------------------------------
    # 4. Truncation Content Audit (max_length = 192)
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("4. TRUNCATION CONTENT AUDIT (max_length = 192)")
    print("-" * 60)
    tok_dir = ROOT / "models/saved/transformer_waf"
    tokenizer = AutoTokenizer.from_pretrained(tok_dir, local_files_only=True)
    
    # Audit token lengths on the 18,000 pool
    all_texts = df["feat_structured"].tolist()
    token_lengths = [len(tokenizer.encode(t, truncation=False)) for t in all_texts]
    arr = np.array(token_lengths)
    
    num_truncated = int(np.sum(arr > 192))
    pct_truncated = num_truncated / len(arr) * 100.0
    print(f"  Total samples > 192 tokens: {num_truncated:,} / {len(arr):,} ({pct_truncated:.2f}%)")
    
    # Inspect 5 truncated samples
    truncated_indices = np.where(arr > 192)[0]
    print(f"\n  Inspecting sample of truncated requests:")
    for idx in truncated_indices[:5]:
        row = df.iloc[idx]
        text = all_texts[idx]
        tokens = tokenizer.tokenize(text)
        kept_tokens = tokens[:192]
        dropped_tokens = tokens[192:]
        kept_str = tokenizer.convert_tokens_to_string(kept_tokens)
        dropped_str = tokenizer.convert_tokens_to_string(dropped_tokens)
        print(f"\n  [Sample {idx}] Source={row['source']}, Label={row['label']}, Full Tokens={len(tokens)}:")
        print(f"    Kept tail (last 40 chars): ...{kept_str[-40:]!r}")
        print(f"    Dropped head (first 60 chars): {dropped_str[:60]!r}...")
        has_payload_in_kept = "[PAYLOAD]" in kept_str
        has_payload_in_dropped = "[PAYLOAD]" in dropped_str
        print(f"    [PAYLOAD] token in kept sequence: {has_payload_in_kept} | In dropped: {has_payload_in_dropped}")

    # -------------------------------------------------------------
    # 5. ~27% FPR Root-Cause Audit
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("5. ~27% FPR ROOT-CAUSE AUDIT ON LINEAR MODELS")
    print("-" * 60)
    # Analyze false positives from active_clf on val_rep_d
    probs_val = active_clf.predict_proba(val_rep_d)[:, mal_idx]
    preds_val = (probs_val >= 0.5).astype(int)
    fps = np.where((np.array(val_labels) == 0) & (preds_val == 1))[0]
    
    fp_sources = val_df.iloc[fps]["source"].value_counts().to_dict()
    print(f"  Total False Positives on Val Set at threshold 0.50: {len(fps)} / {np.sum(np.array(val_labels)==0)}")
    print(f"  False Positive breakdown by source partition: {fp_sources}")
    print(f"  Distribution of probabilities on Benign Val:")
    benign_probs = probs_val[np.array(val_labels) == 0]
    print(f"    p25: {np.percentile(benign_probs, 25):.4f} | p50: {np.percentile(benign_probs, 50):.4f} | p75: {np.percentile(benign_probs, 75):.4f} | p95: {np.percentile(benign_probs, 95):.4f}")
    
    # Check top n-grams contributing to positive weights in TF-IDF
    vec = active_clf.named_steps["tfidf"]
    clf = active_clf.named_steps["classifier"]
    feature_names = np.array(vec.get_feature_names_out())
    coefs = clf.coef_[0]
    top_pos_idx = np.argsort(coefs)[-15:][::-1]
    print("\n  Top 15 Malicious-associated n-grams in Linear Classifier:")
    for i in top_pos_idx:
        print(f"    {feature_names[i]!r}: weight = {coefs[i]:.4f}")

    print("\n" + "=" * 80)
    print("STEP 0 AUDIT COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    run_step0_audit()
