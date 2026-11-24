from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import time

from src.pipeline.schema import ParsedRequest
from src.firewall.rules_engine import RulesEngine, RuleValidationResult
from src.firewall.ml_detector import MLDetector, MLScoringResult
from src.firewall.anomaly_detector import BehavioralAnomalyDetector, AnomalyEvaluationResult

ROOT = Path(__file__).resolve().parents[2]
FROZEN_MANIFEST_PATH = ROOT / "models/frozen/v1_0/model_manifest.json"


@dataclass
class DecisionResult:
    action: str  # 'BLOCK', 'CHALLENGE', 'MONITOR', 'ALLOW'
    http_status: int  # 403, 429, 200
    client_id: str
    risk_score: float
    anomaly_score: float
    primary_reason: str
    triggered_layers: List[str]
    latency_ms: float
    latency_breakdown: Dict[str, float]
    audit_data: Dict[str, Any] = field(default_factory=dict)


class CentralDecisionEngine:
    """
    Central Decision Engine coordinating all 4 layers of the WAF:
    - Layer 1: Rules & Protocol Validator
    - Layer 2: Fast ML (TF-IDF)
    - Layer 3: Context-Aware Transformer
    - Layer 4: Behavioral Anomaly Detection
    """

    def __init__(
        self,
        rules_engine: Optional[RulesEngine] = None,
        ml_detector: Optional[MLDetector] = None,
        anomaly_detector: Optional[BehavioralAnomalyDetector] = None,
        tau_block: Optional[float] = None,
        tau_monitor: Optional[float] = None,
    ):
        manifest_cfg = {}
        if FROZEN_MANIFEST_PATH.exists():
            try:
                with open(FROZEN_MANIFEST_PATH, "r", encoding="utf-8") as f:
                    manifest_cfg = json.load(f).get("threshold_tiers", {})
            except Exception:
                pass

        self.rules_engine = rules_engine or RulesEngine()
        self.ml_detector = ml_detector or MLDetector()
        self.anomaly_detector = anomaly_detector or BehavioralAnomalyDetector()

        if tau_block is not None:
            self.tau_block = tau_block
        elif "tau_block" in manifest_cfg:
            self.tau_block = float(manifest_cfg["tau_block"])
        else:
            self.tau_block = 0.50

        if tau_monitor is not None:
            self.tau_monitor = tau_monitor
        elif "tau_alert" in manifest_cfg:
            self.tau_monitor = float(manifest_cfg["tau_alert"])
        else:
            self.tau_monitor = 0.05

    def inspect_request(
        self,
        req: ParsedRequest,
        client_id: str = "unknown_client",
        event_time: Optional[float] = None,
    ) -> DecisionResult:
        t_start = time.perf_counter()
        breakdown: Dict[str, float] = {}
        triggered_layers: List[str] = []

        # ==========================================================
        # Layer 1: Protocol & Deterministic Rules Validation
        # ==========================================================
        t0 = time.perf_counter()
        rule_res: RuleValidationResult = self.rules_engine.validate(req)
        breakdown["layer_1_rules_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)

        if not rule_res.is_valid:
            triggered_layers.append("Layer1_Rules")
            first_viol = rule_res.violations[0]
            reason = f"Layer 1 Rule Violation: [{first_viol.rule_id}] {first_viol.message}"

            # Record blocked event in anomaly detector for behavioral tracking
            self.anomaly_detector.record_event(
                client_id=client_id,
                path=req.path,
                status_code=403,
                is_blocked=True,
                event_time=event_time,
            )

            total_ms = (time.perf_counter() - t_start) * 1000.0
            return DecisionResult(
                action="BLOCK",
                http_status=403,
                client_id=client_id,
                risk_score=1.0,
                anomaly_score=0.0,
                primary_reason=reason,
                triggered_layers=triggered_layers,
                latency_ms=round(total_ms, 3),
                latency_breakdown=breakdown,
                audit_data={
                    "rule_violations": [
                        {"rule_id": v.rule_id, "category": v.category, "matched": v.matched_value}
                        for v in rule_res.violations
                    ]
                },
            )

        # ==========================================================
        # Layer 2 & 3: Hierarchical ML & Transformer Scoring
        # ==========================================================
        t1 = time.perf_counter()
        ml_res: MLScoringResult = self.ml_detector.evaluate_hierarchical(req)
        breakdown["layer_2_3_ml_ms"] = round((time.perf_counter() - t1) * 1000.0, 3)

        if ml_res.layer == "L2_FAST_PASS":
            triggered_layers.append("Layer2_TFIDF_FastPass")
        elif ml_res.layer.startswith("L3"):
            triggered_layers.append("Layer3_Transformer")
        else:
            triggered_layers.append(f"Layer_{ml_res.layer}")

        # ==========================================================
        # Layer 4: Behavioral Anomaly Detection
        # ==========================================================
        t2 = time.perf_counter()
        # First record current access event
        self.anomaly_detector.record_event(
            client_id=client_id,
            path=req.path,
            status_code=200,
            is_blocked=False,
            event_time=event_time,
        )
        anomaly_res: AnomalyEvaluationResult = self.anomaly_detector.evaluate(
            client_id=client_id,
            req=req,
            current_time=event_time,
        )
        breakdown["layer_4_anomaly_ms"] = round((time.perf_counter() - t2) * 1000.0, 3)

        if anomaly_res.action != "ALLOW":
            triggered_layers.append("Layer4_BehavioralAnomaly")

        # ==========================================================
        # Central Policy Evaluation
        # ==========================================================
        risk_score = ml_res.risk_score
        anomaly_score = anomaly_res.anomaly_score

        # Rule A: High ML Risk Score -> BLOCK (403)
        if risk_score >= self.tau_block:
            action = "BLOCK"
            http_status = 403
            reason = f"High malicious syntax probability ({risk_score:.4f} >= {self.tau_block:.2f})"

        # Rule B: Severe Behavioral Anomaly -> BLOCK (403)
        elif anomaly_res.action == "BLOCK":
            action = "BLOCK"
            http_status = 403
            reason = f"Severe behavioral anomaly score ({anomaly_score:.2f}): {'; '.join(anomaly_res.reasons)}"

        # Rule C: Moderate Behavioral Anomaly -> CHALLENGE (429)
        elif anomaly_res.action == "CHALLENGE":
            action = "CHALLENGE"
            http_status = 429
            reason = f"Behavioral rate/scan anomaly triggered: {'; '.join(anomaly_res.reasons)}"

        # Rule D: Ambiguous Risk Score -> MONITOR (200 with audit tag)
        elif risk_score >= self.tau_monitor:
            action = "MONITOR"
            http_status = 200
            reason = f"Elevated risk score ({risk_score:.4f}) monitored under threshold {self.tau_block:.2f}"

        # Rule E: Clean Request -> ALLOW (200)
        else:
            action = "ALLOW"
            http_status = 200
            reason = "All security layers verified clean"

        total_ms = (time.perf_counter() - t_start) * 1000.0
        return DecisionResult(
            action=action,
            http_status=http_status,
            client_id=client_id,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            primary_reason=reason,
            triggered_layers=triggered_layers,
            latency_ms=round(total_ms, 3),
            latency_breakdown=breakdown,
            audit_data={
                "ml_details": ml_res.details,
                "anomaly_details": {
                    "rate": anomaly_res.request_rate,
                    "distinct_paths": anomaly_res.distinct_paths_count,
                    "reasons": anomaly_res.reasons,
                },
            },
        )
