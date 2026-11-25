# Model Architectures & Training Source Code (`src/models/`)

> **Note:** This folder contains **Python source code** for model architectures and training pipelines.  
> If you are looking for the compiled binary weights, checkpoints, and production tokenizers, see [`models/`](file:///c:/Users/ptssh/Desktop/transformer-waf/models).

---

## Directory Overview

This directory contains the Python engineering codebase used to define, train, calibrate, and audit machine learning models for the Transformer-WAF platform.

```text
src/models/
├── transformer_waf.py             <-- PyTorch nn.Module architecture definition
├── train_transformer.py           <-- Transformer v1.0 training pipeline
├── train_transformer_v2.py        <-- Transformer v2.0 training pipeline
├── train_transformer_v2_1.py      <-- Transformer v2.1 training pipeline
├── train_transformer_v2_2.py      <-- Transformer v2.2 training pipeline
├── train_tfidf_layer.py           <-- Fast Layer 1 TF-IDF logistic classifier training
├── train_tfidf_layer_v2.py
├── train_tfidf_layer_v2_1.py
├── train_tfidf_layer_v2_2.py
├── train_neural_baselines.py      <-- 1D-CNN and FastText baseline training
└── audit_token_length.py          <-- Tokenization and sequence truncation audit script
```

---

## Key Components

### 1. Model Architectures (`transformer_waf.py`)
- Defines the `TransformerWAFClassifier` PyTorch module based on `sentence-transformers/all-MiniLM-L6-v2`.
- Implements custom classification heads, structural token embeddings, and dropout regularization.

### 2. Training Pipelines (`train_transformer_*.py`)
- Loads balanced development data from `data/processed/`.
- Executes AdamW optimization with linear learning rate warmup and gradient clipping.
- Exports trained checkpoints into `models/saved/` for subsequent evaluation and freezing.

### 3. Layer 1 TF-IDF Classifiers (`train_tfidf_layer_*.py`)
- Fits microsecond-latency n-gram character/word TF-IDF representations.
- Serializes trained pipelines using `joblib` into `models/saved/` and `models/frozen/`.

---

## Typical Workflow
1. Modify architecture in `transformer_waf.py`.
2. Run training script: `.venv/Scripts/python -m src.models.train_transformer`.
3. Model weights are output to `models/saved/`.
4. Artifacts are evaluated via `src/evaluation/` and frozen into `models/frozen/`.
