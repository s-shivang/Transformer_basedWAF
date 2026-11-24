"""
Inference Engine for WAF ML Inference Service.

Handles request parsing, Representation D feature building, 2-stage cascaded
inference (Microsecond TF-IDF triage -> Deep Transformer contextual evaluation),
Platt scaling calibration, safe payload limits, and decision tier assignment.
"""
from typing import Optional, Dict, Any
import time
import uuid
import math
import json
import torch
from fastapi import HTTPException

from src.ml_service.schemas import PredictRequest, PredictResponse
from src.ml_service.model_loader import ModelContainer, container as global_container
from src.pipeline.schema import ParsedRequest
from src.pipeline.parser import parse_raw_http, parse_body_content, parse_query_string, REQUEST_LINE_PATTERN
from src.pipeline.canonicalizer import canonicalize_path, canonicalize_value
from src.pipeline.feature_builder import build_features

MAX_PAYLOAD_BYTES = 65536  # 64 KB limit


def parse_from_structured(
    request_id: str,
    method: Optional[str] = None,
    path: Optional[str] = None,
    query_params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
) -> ParsedRequest:
    """
    Constructs a canonicalized ParsedRequest from decomposed HTTP fields with exact
    pipeline parity.
    """
    m = (method or "GET").upper()
    raw_path = path or "/"
    canonical_p, path_flags = canonicalize_path(raw_path)

    q_params = dict(query_params or {})
    h_headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
    raw_body = body or ""

    content_type = h_headers.get("content-type", "")
    body_params, body_payload_values = parse_body_content(raw_body, content_type)

    canonical_payloads = []
    combined_flags = dict(path_flags)

    for qk, qv in q_params.items():
        vals = qv if isinstance(qv, list) else [qv]
        for val in vals:
            c_val, flags = canonicalize_value(str(val), decode_html=True)
            canonical_payloads.append(c_val)
            for fk, fv in flags.items():
                if fv:
                    combined_flags[fk] = True

    for val in body_payload_values:
        c_val, flags = canonicalize_value(str(val), decode_html=True)
        canonical_payloads.append(c_val)
        for fk, fv in flags.items():
            if fv:
                combined_flags[fk] = True

    # Reconstruct raw_text representation
    raw_lines = [f"{m} {raw_path} HTTP/1.1"]
    for hk, hv in h_headers.items():
        raw_lines.append(f"{hk}: {hv}")
    if raw_body:
        raw_lines.append("")
        raw_lines.append(raw_body)
    raw_text = "\r\n".join(raw_lines)

    return ParsedRequest(
        id=request_id,
        raw_text=raw_text,
        method=m,
        path=canonical_p,
        query_params=q_params,
        body_params=body_params,
        headers=h_headers,
        canonical_payloads=canonical_payloads,
        encoding_flags=combined_flags,
    )


class InferenceEngine:
    """
    Core inference engine executing 2-Stage Cascade WAF detection:
    - Tier 1: Microsecond TF-IDF triage on CPU.
    - Tier 2: Deep Contextual Transformer on GPU (FP16) or CPU fallback.
    - Platt calibration: converts raw logits to calibrated probabilities.
    """

    def __init__(self, model_container: Optional[ModelContainer] = None):
        self.container = model_container or global_container

    def _validate_payload_size(self, req: PredictRequest):
        """Enforces 64 KB maximum payload limit."""
        total_bytes = 0
        if req.raw_http is not None:
            total_bytes = len(req.raw_http.encode("utf-8"))
        else:
            if req.method:
                total_bytes += len(req.method.encode("utf-8"))
            if req.path:
                total_bytes += len(req.path.encode("utf-8"))
            if req.query_params:
                total_bytes += len(json.dumps(req.query_params).encode("utf-8"))
            if req.headers:
                total_bytes += len(json.dumps(req.headers).encode("utf-8"))
            if req.body:
                total_bytes += len(req.body.encode("utf-8"))

        if total_bytes > MAX_PAYLOAD_BYTES:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Payload size ({total_bytes} bytes) exceeds maximum allowed "
                    f"limit of 64 KB ({MAX_PAYLOAD_BYTES} bytes)."
                ),
            )

    def _validate_non_empty(self, req: PredictRequest):
        """Rejects empty payloads with HTTP 400."""
        if req.raw_http is not None:
            if not req.raw_http.strip():
                raise HTTPException(
                    status_code=400,
                    detail="Empty payload: raw_http contains only whitespace or is empty.",
                )
            return

        has_content = (
            bool(req.path and req.path.strip())
            or bool(req.query_params)
            or bool(req.body and req.body.strip())
        )
        if not has_content:
            raise HTTPException(
                status_code=400,
                detail="Empty payload: request contains no actionable HTTP content.",
            )

    def predict(self, req: PredictRequest) -> PredictResponse:
        t0 = time.perf_counter()

        if not self.container.is_ready:
            raise HTTPException(
                status_code=503,
                detail="ML models not ready or startup verification incomplete.",
            )

        # 1. Size & emptiness validation
        self._validate_payload_size(req)
        self._validate_non_empty(req)

        req_id = req.request_id or f"req_{uuid.uuid4().hex[:12]}"

        # 2. Request Parsing with canonicalization
        try:
            if req.raw_http is not None:
                first_line = req.raw_http.strip().split("\n")[0].strip()
                if not REQUEST_LINE_PATTERN.match(first_line):
                    raise HTTPException(
                        status_code=400,
                        detail="Malformed HTTP request: missing or invalid request line (expected 'METHOD /path HTTP/x.y').",
                    )
                parsed_req = parse_raw_http(req.raw_http, request_id=req_id)
            else:
                parsed_req = parse_from_structured(
                    request_id=req_id,
                    method=req.method,
                    path=req.path,
                    query_params=req.query_params,
                    headers=req.headers,
                    body=req.body,
                )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Malformed HTTP request: {str(e)}",
            )

        # 3. Representation feature assembly (dynamic according to model version)
        rep_mode = getattr(self.container, "representation_mode", "structured")
        feature_text = build_features(parsed_req, representation=rep_mode)
        if not feature_text.strip():
            feature_text = "[METHOD] GET [PATH] /"

        # 4. Token count & Truncation detection
        token_ids = self.container.transformer_tokenizer.encode(
            feature_text, add_special_tokens=True, truncation=False
        )
        token_count = len(token_ids)
        max_len = self.container.max_length
        use_head_tail = bool(getattr(self.container, "head_tail_chunking", False) and token_count > max_len)

        # Truncation indicates whether tokens fell outside the active model context window
        effective_limit = (max_len * 2) if getattr(self.container, "head_tail_chunking", False) else max_len
        is_truncated = bool(token_count > effective_limit)

        # 5. Stage 1: Fast-Pass TF-IDF Microsecond Triage
        classes = list(self.container.tfidf_pipeline.classes_)
        proba_tfidf = self.container.tfidf_pipeline.predict_proba([feature_text])[0]
        mal_idx = classes.index("malicious") if "malicious" in classes else 1
        tfidf_score = float(proba_tfidf[mal_idx])

        tau_fast_pass = float(self.container.thresholds.get("fast_pass_allow", 0.04))

        if tfidf_score <= tau_fast_pass and not use_head_tail:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return PredictResponse(
                request_id=req_id,
                prediction="benign",
                recommended_tier="fast_pass_allow",
                malicious_probability=round(tfidf_score, 5),
                raw_probability=round(tfidf_score, 5),
                stage_used="fast_pass_tfidf",
                threshold=round(tau_fast_pass, 4),
                model_version=self.container.model_version,
                truncated=is_truncated,
                latency_ms=round(latency_ms, 3),
                status="ok",
            )

        # 6. Stage 2: Deep Contextual Transformer Inference
        if use_head_tail:
            # 2-Chunk Head+Tail Scoring for Long Requests
            sep_id = self.container.transformer_tokenizer.sep_token_id
            cls_id = self.container.transformer_tokenizer.cls_token_id

            # Head chunk (first max_len tokens)
            head_ids = list(token_ids[:max_len])
            if sep_id is not None and head_ids[-1] != sep_id:
                head_ids[-1] = sep_id
            head_mask = [1] * len(head_ids)

            # Tail chunk (last max_len tokens with preserved CLS and SEP)
            tail_core = list(token_ids[-(max_len - 1):])
            tail_ids = ([cls_id] if cls_id is not None else [head_ids[0]]) + tail_core
            if len(tail_ids) > max_len:
                tail_ids = tail_ids[:max_len]
            if sep_id is not None and tail_ids[-1] != sep_id:
                tail_ids[-1] = sep_id
            tail_mask = [1] * len(tail_ids)

            input_ids_tensor = torch.tensor(
                [head_ids, tail_ids], dtype=torch.long, device=self.container.device
            )
            attn_mask_tensor = torch.tensor(
                [head_mask, tail_mask], dtype=torch.long, device=self.container.device
            )

            with torch.inference_mode():
                outputs = self.container.transformer_model(
                    input_ids=input_ids_tensor, attention_mask=attn_mask_tensor
                )
                logits = outputs.logits
                if self.container.device.startswith("cuda") and logits.dtype != torch.float32:
                    logits = logits.float()
                probs = torch.softmax(logits, dim=-1)[:, 1]
                raw_prob = float(torch.max(probs).item())
        else:
            enc = self.container.transformer_tokenizer(
                feature_text,
                max_length=self.container.max_length,
                truncation=True,
                return_tensors="pt",
            ).to(self.container.device)

            with torch.inference_mode():
                outputs = self.container.transformer_model(**enc)
                logits = outputs.logits
                if self.container.device.startswith("cuda") and logits.dtype != torch.float32:
                    logits = logits.float()
                probs = torch.softmax(logits, dim=-1).squeeze().tolist()
                raw_prob = (
                    float(probs[1])
                    if isinstance(probs, list) and len(probs) > 1
                    else float(probs)
                )

        # 7. Platt Scaling Calibration
        calib_cfg = self.container.thresholds.get("platt_calibration", {})
        if calib_cfg.get("enabled", True):
            w = float(self.container.platt_params.get("w", 0.7724))
            b = float(self.container.platt_params.get("b", 0.4965))
            eps = 1e-7
            p_clipped = min(max(raw_prob, eps), 1.0 - eps)
            logit = math.log(p_clipped / (1.0 - p_clipped))
            calibrated_prob = 1.0 / (1.0 + math.exp(-(w * logit + b)))
        else:
            calibrated_prob = raw_prob

        # 8. Decision Tier Assignment
        tau_block = (
            req.threshold_override
            if req.threshold_override is not None
            else float(self.container.thresholds.get("block", 0.50))
        )
        tau_monitor = float(self.container.thresholds.get("monitor_alert", 0.05))

        if calibrated_prob >= tau_block:
            tier = "block"
            pred = "malicious"
        elif calibrated_prob >= tau_monitor:
            tier = "monitor_alert"
            pred = "malicious"
        else:
            tier = "allow"
            pred = "benign"

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return PredictResponse(
            request_id=req_id,
            prediction=pred,
            recommended_tier=tier,
            malicious_probability=round(calibrated_prob, 5),
            raw_probability=round(raw_prob, 5),
            stage_used="transformer",
            threshold=round(tau_block, 4),
            model_version=self.container.model_version,
            truncated=is_truncated,
            latency_ms=round(latency_ms, 3),
            status="ok",
        )
