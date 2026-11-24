"""
Challenge Suite Evaluation across all 4 Candidate Architectures:
- Candidate A: Structured TF-IDF + Logistic Regression
- Candidate B: FastText EmbeddingBag Classifier
- Candidate C: 1D-CNN Multi-Scale Classifier
- Candidate D: Contextual Transformer (all-MiniLM-L6-v2)
"""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import json
import joblib
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from src.pipeline.parser import parse_raw_http
from src.pipeline.feature_builder import build_features
from src.models.train_neural_baselines import FastTextWAFClassifier, CNN1DWAFClassifier
from src.evaluation.benchmark_representations_deep import CHALLENGE_TEST_CASES

def evaluate_all():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Load Tokenizer
    tok_dir = ROOT / "models/saved/transformer_waf"
    tokenizer = AutoTokenizer.from_pretrained(tok_dir, local_files_only=True)
    vocab_size = len(tokenizer)

    # Load Models
    print("Loading models...")
    # Candidate A
    tfidf_clf = joblib.load(ROOT / "models/saved/tfidf_logistic_baseline.joblib")
    classes = list(tfidf_clf.classes_)
    mal_idx = classes.index("malicious") if "malicious" in classes else 1

    # Candidate B
    fasttext_model = FastTextWAFClassifier(vocab_size=vocab_size, embed_dim=64, num_classes=2).to(device)
    fasttext_model.load_state_dict(torch.load(ROOT / "models/saved/fasttext_waf_baseline.pt", map_location=device))
    fasttext_model.eval()

    # Candidate C
    cnn_model = CNN1DWAFClassifier(vocab_size=vocab_size, embed_dim=64, num_classes=2).to(device)
    cnn_model.load_state_dict(torch.load(ROOT / "models/saved/cnn_waf_baseline.pt", map_location=device))
    cnn_model.eval()

    # Candidate D
    transformer_model = AutoModelForSequenceClassification.from_pretrained(tok_dir, local_files_only=True).to(device)
    transformer_model.eval()
    if device.type == "cuda":
        transformer_model = transformer_model.half()

    # Parse and structure challenge test cases
    structured_texts = []
    y_true = []
    descriptions = []

    for tc in CHALLENGE_TEST_CASES:
        p = parse_raw_http(tc["raw"])
        feat = build_features(p, "structured")
        structured_texts.append(feat)
        y_true.append(tc["expected_label"])
        descriptions.append(tc["description"])

    # Predict Candidate A
    probs_a = tfidf_clf.predict_proba(structured_texts)[:, mal_idx]
    preds_a = (probs_a >= 0.5).astype(int)

    # Predict Candidate B, C, D
    enc = tokenizer(structured_texts, max_length=192, padding=True, truncation=True, return_tensors="pt")
    input_ids = enc["input_ids"].to(device)
    attention_mask = enc["attention_mask"].to(device)

    with torch.no_grad():
        # FastText
        logits_b = fasttext_model(input_ids)
        probs_b = torch.softmax(logits_b, dim=-1)[:, 1].cpu().numpy()
        preds_b = (probs_b >= 0.5).astype(int)

        # 1D-CNN
        logits_c = cnn_model(input_ids)
        probs_c = torch.softmax(logits_c, dim=-1)[:, 1].cpu().numpy()
        preds_c = (probs_c >= 0.5).astype(int)

        # Contextual Transformer
        logits_d = transformer_model(input_ids, attention_mask=attention_mask).logits
        if device.type == "cuda":
            logits_d = logits_d.float()
        probs_d = torch.softmax(logits_d, dim=-1)[:, 1].cpu().numpy()
        preds_d = (probs_d >= 0.5).astype(int)

    # Evaluate
    y_true = np.array(y_true)
    acc_a = float(np.mean(preds_a == y_true))
    acc_b = float(np.mean(preds_b == y_true))
    acc_c = float(np.mean(preds_c == y_true))
    acc_d = float(np.mean(preds_d == y_true))

    print("\n" + "=" * 80)
    print("CHALLENGE SUITE EVALUATION RESULTS (10 Adversarial/Evasion/Invariance Cases)")
    print("=" * 80)
    print(f"Candidate A (Structured TF-IDF):       Accuracy = {acc_a * 100:.1f}% ({np.sum(preds_a == y_true)}/10)")
    print(f"Candidate B (FastText EmbeddingBag):   Accuracy = {acc_b * 100:.1f}% ({np.sum(preds_b == y_true)}/10)")
    print(f"Candidate C (1D-CNN Multi-Scale):      Accuracy = {acc_c * 100:.1f}% ({np.sum(preds_c == y_true)}/10)")
    print(f"Candidate D (Contextual Transformer):  Accuracy = {acc_d * 100:.1f}% ({np.sum(preds_d == y_true)}/10)")

    print("\nDetailed Per-Case Results:")
    for i, desc in enumerate(descriptions):
        print(f"Case {i+1}: {desc}")
        print(f"  Truth: {y_true[i]} | Preds -> A: {preds_a[i]} (p={probs_a[i]:.3f}) | B: {preds_b[i]} (p={probs_b[i]:.3f}) | C: {preds_c[i]} (p={probs_c[i]:.3f}) | D: {preds_d[i]} (p={probs_d[i]:.3f})")

    results = {
        "candidate_a_tfidf": {"accuracy": acc_a, "correct": int(np.sum(preds_a == y_true)), "total": len(y_true)},
        "candidate_b_fasttext": {"accuracy": acc_b, "correct": int(np.sum(preds_b == y_true)), "total": len(y_true)},
        "candidate_c_1d_cnn": {"accuracy": acc_c, "correct": int(np.sum(preds_c == y_true)), "total": len(y_true)},
        "candidate_d_transformer": {"accuracy": acc_d, "correct": int(np.sum(preds_d == y_true)), "total": len(y_true)},
    }

    out_file = ROOT / "reports/challenge_suite_all_candidates.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved challenge results to: {out_file}")

if __name__ == "__main__":
    evaluate_all()
