"""
Phase 3 Step 0 Benchmarks:
1. Complete LOAFO Audit for all 4 candidate architectures (SQLi, XSS, Path Traversal, CMDI)
2. Expanded Adversarial/Evasion Challenge Suite (26 test cases)
3. Transformer Representation Ablation (structured vs structured_masked)
4. Comprehensive CPU vs GPU Latency & Throughput Benchmark
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import time
import joblib
import torch
import numpy as np
import pandas as pd
from sklearn.metrics import (
    recall_score, precision_score, f1_score, roc_auc_score,
    average_precision_score, confusion_matrix
)
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from src.models.train_tfidf_layer import load_balanced_development_pool
from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features
from src.models.train_neural_baselines import FastTextWAFClassifier, CNN1DWAFClassifier

HTTP_PARAMS_PATH = ROOT / "data/raw/http_params/payload_train.csv"
AI_WAF_PATH = ROOT / "data/raw/ai_waf/train-00000-of-00001.parquet"
CSIC_DEV_PATH = ROOT / "data/processed/csic_dev.parquet"

def run_benchmarks():
    print("=" * 80)
    print("PHASE 3 STEP 0: COMPREHENSIVE BENCHMARKS")
    print("=" * 80)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"CUDA Device: {device}")

    # Load Tokenizer & Models
    tok_dir = ROOT / "models/saved/transformer_waf"
    tokenizer = AutoTokenizer.from_pretrained(tok_dir, local_files_only=True)
    vocab_size = len(tokenizer)

    print("Loading models...")
    # Candidate A: TF-IDF
    tfidf_clf = joblib.load(ROOT / "models/saved/tfidf_logistic_baseline.joblib")
    classes = list(tfidf_clf.classes_)
    mal_idx = classes.index("malicious") if "malicious" in classes else 1

    # Candidate B: FastText
    fasttext_model = FastTextWAFClassifier(vocab_size=vocab_size, embed_dim=64, num_classes=2).to(device)
    fasttext_model.load_state_dict(torch.load(ROOT / "models/saved/fasttext_waf_baseline.pt", map_location=device))
    fasttext_model.eval()

    # Candidate C: 1D-CNN
    cnn_model = CNN1DWAFClassifier(vocab_size=vocab_size, embed_dim=64, num_classes=2).to(device)
    cnn_model.load_state_dict(torch.load(ROOT / "models/saved/cnn_waf_baseline.pt", map_location=device))
    cnn_model.eval()

    # Candidate D: Transformer (GPU FP16)
    transformer_model = AutoModelForSequenceClassification.from_pretrained(tok_dir, local_files_only=True).to(device)
    transformer_model.eval()
    if device.type == "cuda":
        transformer_model = transformer_model.half()

    # -------------------------------------------------------------
    # 1. Complete LOAFO Audit Across All 4 Architectures
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("1. COMPLETE LOAFO BENCHMARK (ALL 4 ARCHITECTURES)")
    print("-" * 60)
    from src.evaluation.loafo_benchmark import load_http_params_data
    from sklearn.model_selection import StratifiedGroupKFold

    df_hp = load_http_params_data()
    norm_df = df_hp[df_hp["attack_type"] == "norm"].copy().reset_index(drop=True)
    sgkf = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    _, te_idx = next(sgkf.split(norm_df, norm_df["label"], norm_df["group_id"]))
    benign_test = norm_df.iloc[te_idx].copy().reset_index(drop=True)
    benign_payloads = benign_test["payload"].astype(str).tolist()

    benign_texts = [f"[METHOD] GET [PATH] /search [PARAM] q={p} [PAYLOAD] {p}" for p in benign_payloads]
    y_benign = [0] * len(benign_texts)

    loafo_results = {}
    attack_families = ["sqli", "xss", "path-traversal", "cmdi"]

    for fam in attack_families:
        fam_df = df_hp[df_hp["attack_type"] == fam]
        is_statistically_small = len(fam_df) < 200
        print(f"\nEvaluating LOAFO Family: {fam.upper()} ({len(fam_df):,} samples) | Statistically small: {is_statistically_small}")

        fam_payloads = fam_df["payload"].dropna().astype(str).tolist()
        fam_texts = [f"[METHOD] GET [PATH] /search [PARAM] q={p} [PAYLOAD] {p}" for p in fam_payloads]
        y_attacks = [1] * len(fam_texts)

        eval_texts = benign_texts + fam_texts
        eval_labels = y_benign + y_attacks

        # Candidate A: TF-IDF
        probs_a = tfidf_clf.predict_proba(eval_texts)[:, mal_idx]
        preds_a = (probs_a >= 0.5).astype(int)

        # Batch inference for B, C, D
        probs_b, probs_c, probs_d = [], [], []
        batch_size = 128
        with torch.no_grad():
            for i in range(0, len(eval_texts), batch_size):
                b_texts = eval_texts[i:i+batch_size]
                enc = tokenizer(b_texts, max_length=192, padding=True, truncation=True, return_tensors="pt").to(device)

                # FastText
                out_b = fasttext_model(enc["input_ids"])
                probs_b.extend(torch.softmax(out_b, dim=-1)[:, 1].cpu().numpy())

                # 1D-CNN
                out_c = cnn_model(enc["input_ids"])
                probs_c.extend(torch.softmax(out_c, dim=-1)[:, 1].cpu().numpy())

                # Transformer
                out_d = transformer_model(**enc).logits
                if device.type == "cuda":
                    out_d = out_d.float()
                probs_d.extend(torch.softmax(out_d, dim=-1)[:, 1].cpu().numpy())

        probs_b = np.array(probs_b)
        probs_c = np.array(probs_c)
        probs_d = np.array(probs_d)

        preds_b = (probs_b >= 0.5).astype(int)
        preds_c = (probs_c >= 0.5).astype(int)
        preds_d = (probs_d >= 0.5).astype(int)

        def get_family_metrics(preds, probs, y_true):
            rec = float(recall_score(y_true, preds, zero_division=0))
            prec = float(precision_score(y_true, preds, zero_division=0))
            f1 = float(f1_score(y_true, preds, zero_division=0))
            roc = float(roc_auc_score(y_true, probs))
            pr_auc = float(average_precision_score(y_true, probs))
            cm = confusion_matrix(y_true, preds, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel()
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            return {
                "recall": round(rec, 4),
                "precision": round(prec, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4),
                "roc_auc": round(roc, 4),
                "pr_auc": round(pr_auc, 4),
                "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]
            }

        m_a = get_family_metrics(preds_a, probs_a, eval_labels)
        m_b = get_family_metrics(preds_b, probs_b, eval_labels)
        m_c = get_family_metrics(preds_c, probs_c, eval_labels)
        m_d = get_family_metrics(preds_d, probs_d, eval_labels)

        print(f"  Candidate A (TF-IDF):      Recall={m_a['recall']*100:6.2f}% | Prec={m_a['precision']*100:6.2f}% | ROC-AUC={m_a['roc_auc']:.4f} | FPR={m_a['fpr']*100:5.2f}%")
        print(f"  Candidate B (FastText):    Recall={m_b['recall']*100:6.2f}% | Prec={m_b['precision']*100:6.2f}% | ROC-AUC={m_b['roc_auc']:.4f} | FPR={m_b['fpr']*100:5.2f}%")
        print(f"  Candidate C (1D-CNN):      Recall={m_c['recall']*100:6.2f}% | Prec={m_c['precision']*100:6.2f}% | ROC-AUC={m_c['roc_auc']:.4f} | FPR={m_c['fpr']*100:5.2f}%")
        print(f"  Candidate D (Transformer): Recall={m_d['recall']*100:6.2f}% | Prec={m_d['precision']*100:6.2f}% | ROC-AUC={m_d['roc_auc']:.4f} | FPR={m_d['fpr']*100:5.2f}%")

        loafo_results[fam] = {
            "attack_samples": len(fam_df),
            "benign_samples": len(benign_texts),
            "statistically_small": is_statistically_small,
            "candidate_a_tfidf": m_a,
            "candidate_b_fasttext": m_b,
            "candidate_c_1d_cnn": m_c,
            "candidate_d_transformer": m_d
        }

    # -------------------------------------------------------------
    # 2. Expanded 26-Case Adversarial / Evasion Challenge Suite
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("2. EXPANDED 26-CASE ADVERSARIAL CHALLENGE SUITE")
    print("-" * 60)
    challenge_cases = [
        # Benign Healthchecks & Monitoring
        {"desc": "Clean healthcheck endpoint", "raw": "GET /healthz HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 0, "cat": "benign_healthcheck"},
        {"desc": "Metrics endpoint with prometheus params", "raw": "GET /metrics?format=prometheus HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 0, "cat": "benign_healthcheck"},
        {"desc": "Kubernetes ready probe", "raw": "GET /api/v1/ready HTTP/1.1\r\nHost: internal.cluster\r\n\r\n", "expected": 0, "cat": "benign_healthcheck"},
        # Benign API with SQL/JS keywords in legitimate context
        {"desc": "Search for book title containing 'Select'", "raw": "GET /books?query=Select+Your+Destiny HTTP/1.1\r\nHost: bookstore.com\r\n\r\n", "expected": 0, "cat": "benign_keyword"},
        {"desc": "Search for 'Union' in trade union article", "raw": "GET /news?topic=Labor+Union+Meeting HTTP/1.1\r\nHost: news.com\r\n\r\n", "expected": 0, "cat": "benign_keyword"},
        {"desc": "Filter products by order='asc'", "raw": "GET /products?sort=price&order=asc HTTP/1.1\r\nHost: store.com\r\n\r\n", "expected": 0, "cat": "benign_keyword"},
        {"desc": "Blog post discussing javascript <script>", "raw": "POST /articles HTTP/1.1\r\nHost: blog.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 42\r\n\r\ntitle=Learning+Web+Dev&body=HTML+script+tag", "expected": 0, "cat": "benign_keyword"},
        {"desc": "User bio containing quote and dashes", "raw": "POST /profile HTTP/1.1\r\nHost: app.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 35\r\n\r\nbio=It's+my+life+--+always+learning", "expected": 0, "cat": "benign_keyword"},
        # Same endpoint with benign vs attack
        {"desc": "Benign payment submission", "raw": "GET /tienda1/publico/pagar.jsp?precio=49.99&card=valid HTTP/1.1\r\nHost: store.com\r\n\r\n", "expected": 0, "cat": "endpoint_discrimination"},
        {"desc": "Malicious payment injection", "raw": "GET /tienda1/publico/pagar.jsp?precio=1%20UNION%20SELECT%20cc%20FROM%20users-- HTTP/1.1\r\nHost: store.com\r\n\r\n", "expected": 1, "cat": "endpoint_discrimination"},
        {"desc": "Benign profile view", "raw": "GET /users/view?id=1024 HTTP/1.1\r\nHost: app.com\r\n\r\n", "expected": 0, "cat": "endpoint_discrimination"},
        {"desc": "SQLi in profile view", "raw": "GET /users/view?id=1024%20OR%201=1 HTTP/1.1\r\nHost: app.com\r\n\r\n", "expected": 1, "cat": "endpoint_discrimination"},
        # URL Encoding & Double Encoding Evasions
        {"desc": "Single URL encoded SQLi", "raw": "GET /search?q=%27%20UNION%20SELECT%201%2C2%2C3-- HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "encoding_evasion"},
        {"desc": "Double percent-encoded SQLi", "raw": "GET /item?id=%2527%2520OR%25201=1-- HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "encoding_evasion"},
        {"desc": "Triple URL-encoded null byte", "raw": "GET /file?name=test%252500.pdf HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "encoding_evasion"},
        {"desc": "URL-encoded XSS alert", "raw": "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "encoding_evasion"},
        # Mixed Case Evasions
        {"desc": "Mixed case script tag", "raw": "POST /comment HTTP/1.1\r\nHost: blog.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 35\r\n\r\ntext=<sCrIpt>aLeRt(1)</ScRiPt>", "expected": 1, "cat": "mixed_case_evasion"},
        {"desc": "Mixed case SQL keywords", "raw": "GET /data?q=1%20uNiOn%20SeLeCt%201,2,3 HTTP/1.1\r\nHost: app.com\r\n\r\n", "expected": 1, "cat": "mixed_case_evasion"},
        {"desc": "Mixed case XSS svg onload", "raw": "GET /img?src=x%20oNlOaD=aLeRt(document.cookie) HTTP/1.1\r\nHost: app.com\r\n\r\n", "expected": 1, "cat": "mixed_case_evasion"},
        # Whitespace & Delimiter Obfuscation
        {"desc": "Tab and newline separated SQLi", "raw": "GET /data?q=1\t\r\nUNION\t\tSELECT\t1,2,3 HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "whitespace_evasion"},
        {"desc": "SQL comment inline whitespace bypass", "raw": "GET /data?q=1/**/UNION/**/SELECT/**/1,2 HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "whitespace_evasion"},
        {"desc": "Excessive space padding in XSS", "raw": "GET /q?val=<img    src=x    onerror=alert(1)> HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "whitespace_evasion"},
        # Unicode Fullwidth Evasion
        {"desc": "Unicode fullwidth SQLi", "raw": "GET /search?q=%EF%BC%87%20%EF%BC%AF%EF%BC%B2%20%EF%BC%91%EF%BC%9D%EF%BC%91 HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "unicode_evasion"},
        {"desc": "Unicode fullwidth script tag", "raw": "GET /search?q=%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C/script%EF%BC%9E HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "unicode_evasion"},
        # Path Traversal Variants
        {"desc": "Standard dot-dot-slash traversal", "raw": "GET /static/../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "path_traversal"},
        {"desc": "URL-encoded dot-dot-slash (%2e%2e%2f)", "raw": "GET /files?f=%2e%2e%2f%2e%2e%2fwindows%2fwin.ini HTTP/1.1\r\nHost: example.com\r\n\r\n", "expected": 1, "cat": "path_traversal"}
    ]

    ch_texts_d = []
    ch_texts_masked = []
    ch_y = []
    for c in challenge_cases:
        p = parse_raw_http(c["raw"])
        ch_texts_d.append(build_features(p, "structured"))
        ch_texts_masked.append(build_features(p, "structured_masked"))
        ch_y.append(c["expected"])
    ch_y = np.array(ch_y)

    # Evaluate Candidate A (TF-IDF)
    ch_p_a = tfidf_clf.predict_proba(ch_texts_d)[:, mal_idx]
    ch_pred_a = (ch_p_a >= 0.5).astype(int)

    # Evaluate Candidate D on Representation D vs Representation D-Masked
    enc_d = tokenizer(ch_texts_d, max_length=192, padding=True, truncation=True, return_tensors="pt").to(device)
    enc_m = tokenizer(ch_texts_masked, max_length=192, padding=True, truncation=True, return_tensors="pt").to(device)

    with torch.no_grad():
        out_d = transformer_model(**enc_d).logits
        out_m = transformer_model(**enc_m).logits
        if device.type == "cuda":
            out_d = out_d.float()
            out_m = out_m.float()
        ch_p_d = torch.softmax(out_d, dim=-1)[:, 1].cpu().numpy()
        ch_p_m = torch.softmax(out_m, dim=-1)[:, 1].cpu().numpy()

    ch_pred_d = (ch_p_d >= 0.5).astype(int)
    ch_pred_m = (ch_p_m >= 0.5).astype(int)

    acc_a = np.mean(ch_pred_a == ch_y)
    acc_d = np.mean(ch_pred_d == ch_y)
    acc_m = np.mean(ch_pred_m == ch_y)

    print(f"Candidate A (TF-IDF) Challenge Accuracy:               {acc_a*100:.1f}% ({np.sum(ch_pred_a==ch_y)}/{len(ch_y)})")
    print(f"Candidate D (Transformer Rep D) Challenge Accuracy:     {acc_d*100:.1f}% ({np.sum(ch_pred_d==ch_y)}/{len(ch_y)})")
    print(f"Candidate D (Transformer Masked) Challenge Accuracy:    {acc_m*100:.1f}% ({np.sum(ch_pred_m==ch_y)}/{len(ch_y)})")

    # -------------------------------------------------------------
    # 3. Transformer Representation Ablation on 2,865 Val Split
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("3. TRANSFORMER REPRESENTATION ABLATION (2,865 VALIDATION SPLIT)")
    print("-" * 60)
    df_pool = load_balanced_development_pool()
    groups_6 = [f.split("[PARAM]")[0].strip() if "[PARAM]" in f else f[:32] for f in df_pool["feat_structured"]]
    from sklearn.model_selection import StratifiedGroupKFold
    sgkf_6 = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=42)
    _, val_idx_6 = next(sgkf_6.split(df_pool, df_pool["label"], groups_6))
    val_df_6 = df_pool.iloc[val_idx_6].reset_index(drop=True)

    val_texts_rep_d = val_df_6["feat_structured"].tolist()
    val_parsed = [parse_raw_http(t) for t in val_df_6["raw_text"]]
    val_texts_rep_m = [build_features(p, "structured_masked") for p in val_parsed]
    y_val_6 = val_df_6["label"].to_numpy()

    def eval_transformer_texts(texts):
        probs = []
        batch_size = 32
        for i in range(0, len(texts), batch_size):
            b_texts = texts[i:i+batch_size]
            enc = tokenizer(b_texts, max_length=192, padding=True, truncation=True, return_tensors="pt").to(device)
            with torch.no_grad():
                logits = transformer_model(**enc).logits
                if device.type == "cuda":
                    logits = logits.float()
                p = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
                probs.extend(p)
        probs = np.array(probs)
        preds = (probs >= 0.5).astype(int)
        rec = float(recall_score(y_val_6, preds))
        prec = float(precision_score(y_val_6, preds))
        f1 = float(f1_score(y_val_6, preds))
        roc = float(roc_auc_score(y_val_6, probs))
        pr_auc = float(average_precision_score(y_val_6, probs))
        cm = confusion_matrix(y_val_6, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn))
        return {
            "accuracy": round(float((tp + tn) / len(y_val_6)), 4),
            "recall": round(rec, 4),
            "precision": round(prec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "roc_auc": round(roc, 4),
            "pr_auc": round(pr_auc, 4),
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]
        }

    print("Evaluating Transformer on Representation D...")
    res_d = eval_transformer_texts(val_texts_rep_d)
    print("Evaluating Transformer on Representation D-Masked (Path Masked)...")
    res_m = eval_transformer_texts(val_texts_rep_m)

    print(f"  Rep D (Structured):        Acc={res_d['accuracy']*100:.2f}%, Rec={res_d['recall']*100:.2f}%, FPR={res_d['fpr']*100:.2f}%, F1={res_d['f1']:.4f}")
    print(f"  Rep D-Masked (Path Mask):  Acc={res_m['accuracy']*100:.2f}%, Rec={res_m['recall']*100:.2f}%, FPR={res_m['fpr']*100:.2f}%, F1={res_m['f1']:.4f}")

    # -------------------------------------------------------------
    # 4. Comprehensive Latency & Throughput Benchmark (CPU vs GPU)
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("4. COMPREHENSIVE LATENCY & THROUGHPUT BENCHMARK (CPU VS GPU)")
    print("-" * 60)
    sample_texts = val_texts_rep_d[:500]

    # CPU Transformer
    cpu_device = torch.device("cpu")
    cpu_transformer = AutoModelForSequenceClassification.from_pretrained(tok_dir, local_files_only=True).to(cpu_device)
    cpu_transformer.eval()

    def benchmark_latency(infer_fn, samples, n_runs=200):
        latencies = []
        # Warmup
        for s in samples[:10]:
            infer_fn(s)
        for s in samples[:n_runs]:
            t0 = time.perf_counter()
            infer_fn(s)
            latencies.append((time.perf_counter() - t0) * 1000.0)
        arr = np.array(latencies)
        return {
            "p50_ms": round(float(np.percentile(arr, 50)), 3),
            "p95_ms": round(float(np.percentile(arr, 95)), 3),
            "p99_ms": round(float(np.percentile(arr, 99)), 3),
            "mean_ms": round(float(np.mean(arr)), 3),
            "throughput_req_per_sec": round(1000.0 / float(np.mean(arr)), 1)
        }

    # TF-IDF CPU single request
    lat_tfidf_cpu = benchmark_latency(lambda t: tfidf_clf.predict_proba([t]), sample_texts)
    print(f"Candidate A (TF-IDF CPU single req):       p50={lat_tfidf_cpu['p50_ms']} ms, p95={lat_tfidf_cpu['p95_ms']} ms, throughput={lat_tfidf_cpu['throughput_req_per_sec']} req/s")

    # Transformer CPU single request
    def infer_cpu_single(text):
        enc = tokenizer(text, max_length=192, truncation=True, return_tensors="pt").to(cpu_device)
        with torch.no_grad():
            cpu_transformer(**enc)
    lat_trans_cpu = benchmark_latency(infer_cpu_single, sample_texts, n_runs=100)
    print(f"Candidate D (Transformer CPU single req):  p50={lat_trans_cpu['p50_ms']} ms, p95={lat_trans_cpu['p95_ms']} ms, throughput={lat_trans_cpu['throughput_req_per_sec']} req/s")

    # Transformer GPU single request
    def infer_gpu_single(text):
        enc = tokenizer(text, max_length=192, truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            transformer_model(**enc)
    lat_trans_gpu = benchmark_latency(infer_gpu_single, sample_texts, n_runs=200)
    print(f"Candidate D (Transformer GPU single req):  p50={lat_trans_gpu['p50_ms']} ms, p95={lat_trans_gpu['p95_ms']} ms, throughput={lat_trans_gpu['throughput_req_per_sec']} req/s")

    # Transformer GPU batch=32
    def infer_gpu_batch32():
        batch = sample_texts[:32]
        enc = tokenizer(batch, max_length=192, padding=True, truncation=True, return_tensors="pt").to(device)
        with torch.no_grad():
            transformer_model(**enc)

    b_times = []
    for _ in range(50):
        t0 = time.perf_counter()
        infer_gpu_batch32()
        b_times.append(((time.perf_counter() - t0) * 1000.0) / 32.0)
    arr_b = np.array(b_times)
    lat_trans_gpu_batch = {
        "p50_per_req_ms": round(float(np.percentile(arr_b, 50)), 3),
        "p95_per_req_ms": round(float(np.percentile(arr_b, 95)), 3),
        "throughput_req_per_sec": round(1000.0 / float(np.mean(arr_b)), 1)
    }
    print(f"Candidate D (Transformer GPU batched 32): p50={lat_trans_gpu_batch['p50_per_req_ms']} ms/req, throughput={lat_trans_gpu_batch['throughput_req_per_sec']} req/s")

    # -------------------------------------------------------------
    # 5. Save Benchmark Data
    # -------------------------------------------------------------
    out_data = {
        "loafo_audit_all_candidates": loafo_results,
        "challenge_suite_26cases": {
            "total_cases": len(challenge_cases),
            "tfidf_accuracy": round(float(acc_a), 4),
            "transformer_rep_d_accuracy": round(float(acc_d), 4),
            "transformer_masked_accuracy": round(float(acc_m), 4)
        },
        "transformer_representation_ablation": {
            "rep_d_structured": res_d,
            "rep_d_masked": res_m
        },
        "latency_profiles": {
            "tfidf_cpu": lat_tfidf_cpu,
            "transformer_cpu_single": lat_trans_cpu,
            "transformer_gpu_single": lat_trans_gpu,
            "transformer_gpu_batch32": lat_trans_gpu_batch,
            "training_durations": {
                "candidate_a_tfidf_s": 6.3,
                "candidate_b_fasttext_s": 9.7,
                "candidate_c_1d_cnn_s": 18.1,
                "candidate_d_transformer_s": 252.8
            }
        }
    }

    out_file = ROOT / "reports/phase3_step0_benchmarks.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)
    print(f"\nAll benchmark results saved to: {out_file}")

if __name__ == "__main__":
    run_benchmarks()
