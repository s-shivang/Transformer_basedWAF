from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import time
from collections import deque
from src.pipeline.schema import ParsedRequest


SENSITIVE_PROBE_PATHS: Set[str] = {
    "/admin", "/administrator", "/wp-login.php", "/wp-admin",
    "/.env", "/.git", "/config.php", "/phpmyadmin", "/actuator",
    "/console", "/api/v1/debug", "/server-status", "/swagger-ui.html"
}


@dataclass
class ClientEvent:
    timestamp: float
    path: str
    status_code: int = 200
    is_blocked: bool = False
    is_sensitive: bool = False


@dataclass
class AnomalyEvaluationResult:
    client_id: str
    anomaly_score: float  # [0.0, 1.0]
    action: str  # 'ALLOW', 'CHALLENGE', 'BLOCK'
    reasons: List[str] = field(default_factory=list)
    request_rate: float = 0.0  # requests / second in current window
    distinct_paths_count: int = 0
    blocked_count: int = 0


class BehavioralAnomalyDetector:
    """
    Layer 4: Behavioral Anomaly Detection.
    Tracks client request behavior over a sliding time-window to detect:
    - High-frequency burst patterns / rate anomalies
    - Sensitive endpoint enumeration / directory brute-forcing
    - High ratio of security violations / client errors
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        rate_limit_per_second: float = 10.0,
        burst_threshold: int = 30,
        sensitive_scan_threshold: int = 4,
        violation_threshold: int = 5,
        anomaly_challenge_threshold: float = 0.50,
        anomaly_block_threshold: float = 0.85,
    ):
        self.window_seconds = window_seconds
        self.rate_limit_per_second = rate_limit_per_second
        self.burst_threshold = burst_threshold
        self.sensitive_scan_threshold = sensitive_scan_threshold
        self.violation_threshold = violation_threshold
        self.anomaly_challenge_threshold = anomaly_challenge_threshold
        self.anomaly_block_threshold = anomaly_block_threshold

        # Map client_id -> deque of ClientEvent
        self._client_history: Dict[str, deque] = {}

    def _evict_stale_events(self, client_id: str, now: float) -> None:
        if client_id not in self._client_history:
            return
        dq = self._client_history[client_id]
        cutoff = now - self.window_seconds
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()
        if not dq:
            del self._client_history[client_id]

    def record_event(
        self,
        client_id: str,
        path: str,
        status_code: int = 200,
        is_blocked: bool = False,
        event_time: Optional[float] = None,
    ) -> None:
        now = event_time or time.time()
        self._evict_stale_events(client_id, now)

        if client_id not in self._client_history:
            self._client_history[client_id] = deque()

        is_sensitive = any(path.lower().startswith(p) for p in SENSITIVE_PROBE_PATHS)
        self._client_history[client_id].append(
            ClientEvent(
                timestamp=now,
                path=path,
                status_code=status_code,
                is_blocked=is_blocked,
                is_sensitive=is_sensitive,
            )
        )

    def evaluate(
        self,
        client_id: str,
        req: ParsedRequest,
        current_time: Optional[float] = None,
    ) -> AnomalyEvaluationResult:
        now = current_time or time.time()
        self._evict_stale_events(client_id, now)

        events = self._client_history.get(client_id, deque())
        reasons: List[str] = []
        anomaly_score = 0.0

        if not events:
            return AnomalyEvaluationResult(
                client_id=client_id,
                anomaly_score=0.0,
                action="ALLOW",
                reasons=[],
                request_rate=0.0,
                distinct_paths_count=0,
                blocked_count=0,
            )

        # Calculate time span and rate
        oldest = events[0].timestamp
        duration = max(1.0, now - oldest)
        total_reqs = len(events)
        rate = total_reqs / duration

        # 1. Burst rate anomaly
        if total_reqs > self.burst_threshold:
            burst_factor = min(1.0, (total_reqs - self.burst_threshold) / self.burst_threshold)
            anomaly_score += 0.40 * burst_factor
            reasons.append(f"Excessive burst rate: {total_reqs} requests in {duration:.1f}s")
        elif rate > self.rate_limit_per_second:
            anomaly_score += 0.30
            reasons.append(f"Rate limit exceeded: {rate:.1f} req/s > {self.rate_limit_per_second} req/s")

        # 2. Scanning / directory enumeration
        distinct_paths = len({e.path for e in events})
        sensitive_count = sum(1 for e in events if e.is_sensitive)
        if sensitive_count >= self.sensitive_scan_threshold:
            probe_score = min(0.75, 0.45 + 0.10 * (sensitive_count - self.sensitive_scan_threshold + 1))
            anomaly_score += probe_score
            reasons.append(f"Sensitive probe scanning detected: {sensitive_count} sensitive endpoints hit")
        elif distinct_paths >= 15 and (distinct_paths / total_reqs) > 0.8:
            anomaly_score += 0.35
            reasons.append(f"Endpoint fuzzing/enumeration pattern: {distinct_paths} distinct paths")

        # 3. Repeated security violations / blocked requests
        blocked_count = sum(1 for e in events if e.is_blocked)
        if blocked_count >= self.violation_threshold:
            anomaly_score += 0.50
            reasons.append(f"Repeated blocked violations from client: {blocked_count} blocks in window")
        elif blocked_count > 0:
            anomaly_score += 0.15 * blocked_count

        anomaly_score = min(1.0, anomaly_score)

        if anomaly_score >= self.anomaly_block_threshold:
            action = "BLOCK"
        elif anomaly_score >= self.anomaly_challenge_threshold:
            action = "CHALLENGE"
        else:
            action = "ALLOW"

        return AnomalyEvaluationResult(
            client_id=client_id,
            anomaly_score=round(anomaly_score, 4),
            action=action,
            reasons=reasons,
            request_rate=round(rate, 2),
            distinct_paths_count=distinct_paths,
            blocked_count=blocked_count,
        )
