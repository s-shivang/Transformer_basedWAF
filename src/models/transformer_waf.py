from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
import os
import torch
import torch.nn as nn
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    PreTrainedTokenizerBase,
    PreTrainedModel,
)


SPECIAL_STRUCTURAL_TOKENS = ["[METHOD]", "[PATH]", "[PARAM]", "[PAYLOAD]", "[HEADERS]"]


def get_optimal_device() -> torch.device:
    """Detect and return CUDA device if available, otherwise CPU."""
    if torch.cuda.is_available():
        device = torch.device("cuda:0")
        print(f"[Device] Using GPU: {torch.cuda.get_device_name(0)} (VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB)")
    else:
        device = torch.device("cpu")
        print("[Device] Using CPU")
    return device


def initialize_transformer_model(
    model_name_or_path: str = "sentence-transformers/all-MiniLM-L6-v2",
    num_labels: int = 2,
    device: Optional[torch.device] = None,
) -> Tuple[PreTrainedModel, PreTrainedTokenizerBase]:
    """
    Initializes tokenizer and model with registered structural tokens:
    [METHOD], [PATH], [PARAM], [PAYLOAD], [HEADERS]
    and resizes embedding dimensions accordingly.
    """
    device = device or get_optimal_device()

    print(f"[ModelInit] Loading base model & tokenizer: {model_name_or_path}...")
    local_only = Path(model_name_or_path).exists()
    tokenizer = AutoTokenizer.from_pretrained(model_name_or_path, local_files_only=local_only)

    # Register special structural tokens
    num_added = tokenizer.add_special_tokens(
        {"additional_special_tokens": SPECIAL_STRUCTURAL_TOKENS}
    )
    if num_added > 0:
        print(f"[ModelInit] Added {num_added} special structural tokens: {SPECIAL_STRUCTURAL_TOKENS}")

    model = AutoModelForSequenceClassification.from_pretrained(
        model_name_or_path,
        num_labels=num_labels,
        local_files_only=local_only,
    )

    if num_added > 0:
        model.resize_token_embeddings(len(tokenizer))
        print(f"[ModelInit] Resized model token embeddings to {len(tokenizer)}")

    model.to(device)
    return model, tokenizer


class TransformerWAFClassifier:
    """
    Inference wrapper for the fine-tuned Transformer WAF classifier.
    Optimized for low-latency batch and single-request evaluation on laptop RTX 2050 / CPU.
    """

    def __init__(
        self,
        model_dir: str,
        device: Optional[torch.device] = None,
        max_length: int = 192,
        use_fp16: bool = True,
    ):
        self.device = device or get_optimal_device()
        self.max_length = max_length
        self.use_fp16 = use_fp16 and (self.device.type == "cuda")

        print(f"[TransformerWAF] Loading model from {model_dir}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        self.model.to(self.device)
        self.model.eval()

        if self.use_fp16:
            self.model = self.model.half()
            print("[TransformerWAF] Enabled FP16 inference for NVIDIA Tensor Cores.")

    @torch.inference_mode()
    def predict_proba(self, texts: List[str]) -> List[float]:
        """
        Returns list of probabilities of the request being malicious (class 1).
        """
        if not texts:
            return []

        inputs = self.tokenizer(
            texts,
            max_length=self.max_length,
            padding=True,
            truncation=True,
            return_tensors="pt",
        ).to(self.device)

        outputs = self.model(**inputs)
        logits = outputs.logits
        if self.use_fp16:
            logits = logits.float()

        probs = torch.softmax(logits, dim=-1)
        # Class 1 is malicious
        mal_probs = probs[:, 1].tolist()
        return mal_probs

    def predict_single(self, text: str) -> float:
        """Inference for a single structured request string."""
        return self.predict_proba([text])[0]
