# Model Weights & Runtime Checkpoints (`models/`)

> **Note:** This folder contains **binary model artifacts, weights, and calibration configurations**.  
> If you are looking for the Python training scripts and PyTorch neural network architecture source code, see [`src/models/`](file:///c:/Users/ptssh/Desktop/transformer-waf/src/models).

---

## Directory Overview

This directory acts as the central model repository used at runtime by the Transformer-WAF Data Plane (`src/ml_service/inference_engine.py`) and decision engine (`src/firewall/decision_engine.py`).

```text
models/
├── frozen/            <-- Immutable, production-ready frozen model checkpoints
│   ├── v1_0/          <-- Active production checkpoint (manifest, TF-IDF, Transformer weights)
│   ├── v2_0/          <-- Archived experimental v2.0 checkpoint
│   ├── v2_1/          <-- Archived experimental v2.1 checkpoint
│   └── v2_2/          <-- Archived experimental v2.2 checkpoint
└── saved/             <-- Development checkpoints, baseline weights, and training runs
    ├── transformer_waf/
    ├── tfidf_logistic_baseline.joblib
    ├── calibrated_thresholds.json
    └── ...
```

---

## Subdirectories

### 1. `models/frozen/` (Production Releases)
Each subfolder (`v1_0/`, `v2_0/`, etc.) represents a frozen release with cryptographic integrity verification:
- `model_manifest.json`: Cryptographic SHA-256 hashes of all artifacts. The inference service validates these on boot.
- `model.safetensors` & `config.json`: The fine-tuned Hugging Face / PyTorch Transformer weights (`all-MiniLM-L6-v2`).
- `tokenizer.json` & `tokenizer_config.json`: Vocabulary and tokenizer rules matching the trained model.
- `tfidf/tfidf_logistic_baseline.joblib`: Serialized Scikit-Learn TF-IDF Layer 1 classifier.
- `preprocessing_config.json`: Exact normalization and string canonicalization parameters.
- `threshold.json`: Calibrated operational risk decision bands (Monitor, Challenge, Block).

### 2. `models/saved/` (Development & Baseline Checkpoints)
- Intermediate checkpoints generated during training runs by scripts in `src/models/`.
- Neural baseline models (1D-CNN in `cnn_waf_baseline.pt`, FastText in `fasttext_waf_baseline.pt`).
- Saved threshold calibration files (`calibrated_thresholds.json`).

---

## MLOps Integrity Rule
- **Do not manually edit or rename files in `models/frozen/v1_0/`**. The inference engine validates SHA-256 checksums on startup and will reject tampered or corrupted weights.
