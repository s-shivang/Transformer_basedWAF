"""
Multi-Layer Central Decision Engine for WAF Core.

Coordinates:
- Layer 1: Protocol & Deterministic Rules Validation
- Layer 2/3: ML Inference (Fast-Pass TF-IDF & Deep Transformer)
- Layer 4: Behavioral Anomaly & Burst Detection
- Policy-driven enforcement: monitor, blocking, strict, disabled
- Explicit degraded mode / fail-open vs fail-closed handling
"""
from typing import Dict, Any, List, Optional, Union, Literal
from dataclasses import dataclass, field
import time
import uuid
from pydantic import BaseModel, Field

from src.pipeline.schema import ParsedRequest
from src.pipeline.parser import parse_raw_http
from src.firewall.policy import FirewallPolicy
from src.firewall.rules_engine import RulesEngine, RuleValidationResult
from src.firewall.ml_client import MLClient, MLClientResult
from src.firewall.anomaly_detector import BehavioralAnomalyDetector, AnomalyEvaluationResult


class WAFDecision(BaseModel):
    """
    Standardized, privacy-safe security event and enforcement action output.
    """
    request_id: str
    tenant_id: str
    site_id: str
    action: Literal["ALLOW", "BLOCK", "MONITOR", "CHALLENGE"]
    would_action: Literal["ALLOW", "BLOCK", "MONITOR", "CHALLENGE"]
    reason: str
    risk_score: float
    stage_used: str
    rule_matches: List[str] = Field(default_factory=list)
    anomaly_flags: List[str] = Field(default_factory=list)
    degraded_mode: bool = False
    model_version: str = "unknown"
    policy_version: str = "1.0.0"
    inspection_mode: Literal["monitor", "blocking", "strict", "disabled"]
    latency_ms: float
    details: Dict[str, Any] = Field(default_factory=dict)

    @property
    def http_status(self) -> int:
        if self.action == "BLOCK":
            return 403
        elif self.action == "CHALLENGE":
            return 429
        return 200

    @property
    def primary_reason(self) -> str:
        return self.reason


# Backward compatibility alias
DecisionResult = WAFDecision


class CentralDecisionEngine:
    """
    Central Decision Engine coordinating all inspection layers.
    Enforces tenant policies, multi-signal fusion, and explicit failure modes.
    """

    def __init__(
        self,
        policy: Optional[FirewallPolicy] = None,
        rules_engine: Optional[RulesEngine] = None,
        ml_client: Optional[MLClient] = None,
        ml_detector: Optional[Any] = None,
        anomaly_detector: Optional[BehavioralAnomalyDetector] = None,
        tau_block: Optional[float] = None,
        tau_monitor: Optional[float] = None,
    ):
        if policy is not None:
            self.policy = policy
        elif tau_block is not None:
            # Legacy constructor explicitly setting block threshold implies active blocking
            self.policy = FirewallPolicy(inspection_mode="blocking")
            self.policy.thresholds.block = tau_block
            if tau_monitor is not None:
                self.policy.thresholds.monitor = tau_monitor
        else:
            self.policy = FirewallPolicy(inspection_mode="monitor")

        self.rules_engine = rules_engine or RulesEngine(
            max_body_size=self.policy.max_request_size_bytes,
            allowed_methods=set(self.policy.allowed_methods),
        )

        if ml_client is not None:
            self.ml_client = ml_client
        elif ml_detector is not None:
            # Wrap MLDetector as a clean adapter
            class _DetectorAdapter:
                def __init__(self, detector):
                    self.detector = detector
                def predict(self, raw_http=None, request_id=None, **kwargs):
                    from src.pipeline.parser import parse_raw_http
                    p = parse_raw_http(raw_http, request_id=request_id or "req_adapt")
                    res = self.detector.evaluate_hierarchical(p)
                    stage = "fast_pass_tfidf" if res.layer == "L2_FAST_PASS" else "transformer"
                    return MLClientResult(
                        success=True,
                        risk_score=res.risk_score,
                        raw_probability=res.risk_score,
                        stage_used=stage,
                        model_version="v1.0.0",
                        latency_ms=res.latency_ms,
                    )
            self.ml_client = _DetectorAdapter(ml_detector)
        else:
            self.ml_client = MLClient()

        self.anomaly_detector = anomaly_detector or BehavioralAnomalyDetector()

    def inspect_request(
        self,
        req: Union[ParsedRequest, str],
        client_id: str = "unknown_client",
        event_time: Optional[float] = None,
    ) -> WAFDecision:
        """
        Executes multi-layer inspection according to policy.
        """
        t_start = time.perf_counter()
        req_id = f"req_{uuid.uuid4().hex[:12]}"

        # 1. Parsing normalization
        if isinstance(req, str):
            parsed_req = parse_raw_http(req, request_id=req_id)
        else:
            parsed_req = req
            if parsed_req.id:
                req_id = parsed_req.id

        now = event_time or time.time()

        # ==========================================================
        # 1. Inspection Disabled Check
        # ==========================================================
        if self.policy.inspection_mode == "disabled":
            latency = (time.perf_counter() - t_start) * 1000.0
            return WAFDecision(
                request_id=req_id,
                tenant_id=self.policy.tenant_id,
                site_id=self.policy.site_id,
                action="ALLOW",
                would_action="ALLOW",
                reason="INSPECTION_DISABLED",
                risk_score=0.0,
                stage_used="none",
                degraded_mode=False,
                model_version="none",
                policy_version=self.policy.policy_version,
                inspection_mode=self.policy.inspection_mode,
                latency_ms=round(latency, 3),
            )

        # ==========================================================
        # 2. Request Validation Constraints (Size & Methods)
        # ==========================================================
        req_bytes = len(parsed_req.raw_text.encode("utf-8")) if parsed_req.raw_text else 0
        if req_bytes > self.policy.max_request_size_bytes:
            would = "BLOCK"
            act = "MONITOR" if self.policy.inspection_mode == "monitor" else "BLOCK"
            latency = (time.perf_counter() - t_start) * 1000.0
            self.anomaly_detector.record_event(client_id, parsed_req.path, is_blocked=(act == "BLOCK"), event_time=now)
            return WAFDecision(
                request_id=req_id,
                tenant_id=self.policy.tenant_id,
                site_id=self.policy.site_id,
                action=act,
                would_action=would,
                reason="REQUEST_SIZE_LIMIT_EXCEEDED",
                risk_score=1.0,
                stage_used="protocol_validator",
                rule_matches=["RFC_PAYLOAD_TOO_LARGE"],
                policy_version=self.policy.policy_version,
                inspection_mode=self.policy.inspection_mode,
                latency_ms=round(latency, 3),
            )

        if not self.policy.is_method_allowed(parsed_req.method):
            would = "BLOCK"
            act = "MONITOR" if self.policy.inspection_mode == "monitor" else "BLOCK"
            latency = (time.perf_counter() - t_start) * 1000.0
            self.anomaly_detector.record_event(client_id, parsed_req.path, is_blocked=(act == "BLOCK"), event_time=now)
            return WAFDecision(
                request_id=req_id,
                tenant_id=self.policy.tenant_id,
                site_id=self.policy.site_id,
                action=act,
                would_action=would,
                reason=f"DISALLOWED_HTTP_METHOD_{parsed_req.method.upper()}",
                risk_score=1.0,
                stage_used="protocol_validator",
                rule_matches=["RFC_METHOD_DISALLOWED"],
                policy_version=self.policy.policy_version,
                inspection_mode=self.policy.inspection_mode,
                latency_ms=round(latency, 3),
            )

        # ==========================================================
        # 3. Layer 1: Deterministic Rules Engine
        # ==========================================================
        rule_matches: List[str] = []
        if self.policy.rules_enabled:
            rule_res: RuleValidationResult = self.rules_engine.validate(parsed_req)
            if rule_res.has_blocking_violation:
                rule_matches = [v.rule_id for v in rule_res.violations if v.severity == "BLOCK"]
                primary_rule = rule_matches[0]

                would = "BLOCK"
                act = "MONITOR" if self.policy.inspection_mode == "monitor" else "BLOCK"
                self.anomaly_detector.record_event(client_id, parsed_req.path, is_blocked=(act == "BLOCK"), event_time=now)

                latency = (time.perf_counter() - t_start) * 1000.0
                return WAFDecision(
                    request_id=req_id,
                    tenant_id=self.policy.tenant_id,
                    site_id=self.policy.site_id,
                    action=act,
                    would_action=would,
                    reason=f"LAYER1_RULE_{primary_rule}",
                    risk_score=1.0,
                    stage_used="rules_engine",
                    rule_matches=rule_matches,
                    policy_version=self.policy.policy_version,
                    inspection_mode=self.policy.inspection_mode,
                    latency_ms=round(latency, 3),
                    details={"violation_details": [v.message for v in rule_res.violations]},
                )

        # ==========================================================
        # 4. Path Exclusions (Bypass ML)
        # ==========================================================
        if self.policy.is_path_excluded(parsed_req.path):
            latency = (time.perf_counter() - t_start) * 1000.0
            self.anomaly_detector.record_event(client_id, parsed_req.path, is_blocked=False, event_time=now)
            return WAFDecision(
                request_id=req_id,
                tenant_id=self.policy.tenant_id,
                site_id=self.policy.site_id,
                action="ALLOW",
                would_action="ALLOW",
                reason="PATH_EXCLUDED_FROM_ML",
                risk_score=0.0,
                stage_used="path_exclusion",
                policy_version=self.policy.policy_version,
                inspection_mode=self.policy.inspection_mode,
                latency_ms=round(latency, 3),
            )

        # ==========================================================
        # 5. Layer 4: Behavioral Anomaly Detection
        # ==========================================================
        anomaly_flags: List[str] = []
        is_anomaly_active = False
        if self.policy.anomaly_enabled:
            anom_res: AnomalyEvaluationResult = self.anomaly_detector.evaluate(
                client_id, req=parsed_req, current_time=now
            )
            anomaly_flags = anom_res.reasons
            is_anomaly_active = (anom_res.action in ("CHALLENGE", "BLOCK") or anom_res.anomaly_score >= 0.50)

        # ==========================================================
        # 6. Layer 2/3: ML Inference Service Call
        # ==========================================================
        ml_score = 0.0
        stage_used = "none"
        model_ver = "unknown"
        degraded = False

        if self.policy.ml_enabled:
            ml_res: MLClientResult = self.ml_client.predict(
                raw_http=parsed_req.raw_text,
                request_id=req_id,
            )

            if not ml_res.success:
                # --------------------------------------------------
                # Explicit Degraded Mode Handling
                # --------------------------------------------------
                degraded = True
                fail_domain = ml_res.failure_domain or "unknown"

                if is_anomaly_active:
                    would = "CHALLENGE"
                    act = "MONITOR" if self.policy.inspection_mode == "monitor" else "CHALLENGE"
                    reason = "ML_DEGRADED_ANOMALY_ACTIVE"
                elif self.policy.ml_failure_mode == "fail_closed":
                    would = "BLOCK"
                    act = "MONITOR" if self.policy.inspection_mode == "monitor" else "BLOCK"
                    reason = "ML_UNAVAILABLE_FAIL_CLOSED"
                else:  # fail_open
                    would = "ALLOW"
                    act = "ALLOW"
                    reason = "ML_UNAVAILABLE_FAIL_OPEN"

                self.anomaly_detector.record_event(client_id, parsed_req.path, is_blocked=(act == "BLOCK"), event_time=now)
                latency = (time.perf_counter() - t_start) * 1000.0
                return WAFDecision(
                    request_id=req_id,
                    tenant_id=self.policy.tenant_id,
                    site_id=self.policy.site_id,
                    action=act,
                    would_action=would,
                    reason=reason,
                    risk_score=0.0,
                    stage_used="degraded_local_rules",
                    rule_matches=rule_matches,
                    anomaly_flags=anomaly_flags,
                    degraded_mode=True,
                    model_version="unavailable",
                    policy_version=self.policy.policy_version,
                    inspection_mode=self.policy.inspection_mode,
                    latency_ms=round(latency, 3),
                    details={"error": ml_res.error_message, "failure_domain": fail_domain},
                )

            # ML Success
            ml_score = ml_res.risk_score
            stage_used = ml_res.stage_used
            model_ver = ml_res.model_version

        # ==========================================================
        # 7. Multi-Signal Fusion & Decision Assignment
        # ==========================================================
        target_action = "ALLOW"
        target_reason = "CLEAN_REQUEST"

        # A. Microsecond Fast-Pass clean shortcut
        if stage_used == "fast_pass_tfidf" and not is_anomaly_active:
            target_action = "ALLOW"
            target_reason = "FAST_PASS_CLEAN"

        # B. Strict mode evaluation
        elif self.policy.inspection_mode == "strict":
            if ml_score >= self.policy.thresholds.strict_block:
                target_action = "BLOCK"
                target_reason = "STRICT_ML_BLOCK"
            elif ml_score >= self.policy.thresholds.monitor:
                target_action = "MONITOR"
                target_reason = "STRICT_ML_MONITOR"
            else:
                target_action = "ALLOW"
                target_reason = "STRICT_ML_ALLOW"

        # C. Standard Blocking & Monitor mode evaluation
        else:
            if ml_score >= self.policy.thresholds.block:
                target_action = "BLOCK"
                target_reason = "ML_THRESHOLD_EXCEEDED"
            elif self.policy.thresholds.challenge <= ml_score < self.policy.thresholds.block:
                if is_anomaly_active:
                    target_action = "BLOCK"
                    target_reason = "ML_AND_ANOMALY_ESCALATION"
                else:
                    target_action = "CHALLENGE"
                    target_reason = "ML_CHALLENGE_BAND"
            elif self.policy.thresholds.monitor <= ml_score < self.policy.thresholds.challenge:
                target_action = "MONITOR"
                target_reason = "ML_MONITOR_ALERT"
            else:
                if is_anomaly_active:
                    target_action = "CHALLENGE"
                    target_reason = "BEHAVIORAL_ANOMALY_TRIGGERED"
                else:
                    target_action = "ALLOW"
                    target_reason = "CLEAN_REQUEST"

        # Determine would_action and action based on inspection_mode
        would_action = target_action
        if self.policy.inspection_mode == "monitor":
            # In monitor mode: never return BLOCK or CHALLENGE to the client
            if would_action in ("BLOCK", "CHALLENGE", "MONITOR"):
                final_action = "MONITOR"
            else:
                final_action = "ALLOW"
        else:
            final_action = target_action

        # Record event in anomaly tracker
        self.anomaly_detector.record_event(
            client_id=client_id,
            path=parsed_req.path,
            is_blocked=(final_action == "BLOCK"),
            event_time=now,
        )

        latency = (time.perf_counter() - t_start) * 1000.0
        return WAFDecision(
            request_id=req_id,
            tenant_id=self.policy.tenant_id,
            site_id=self.policy.site_id,
            action=final_action,
            would_action=would_action,
            reason=target_reason,
            risk_score=round(ml_score, 4),
            stage_used=stage_used,
            rule_matches=rule_matches,
            anomaly_flags=anomaly_flags,
            degraded_mode=degraded,
            model_version=model_ver,
            policy_version=self.policy.policy_version,
            inspection_mode=self.policy.inspection_mode,
            latency_ms=round(latency, 3),
        )
