"""
Interactive Human Verification Challenge Engine (Phase 7.5).

Zero-External-CDN, Cryptographically Signed Interactive Verification:
- HMAC-SHA256 Signed Nonce & Proof-of-Work (PoW) with 60-second expiration.
- Single-use nonce tracking preventing replay attacks.
- 3 Randomized Interactive Mini-Tasks (2-4 seconds each):
    A. Smooth Puzzle Snap (Slider with drag duration/pointer tracking)
    B. Rotate-to-Upright Vector Icon (tap/click until 0 degrees)
    C. 2-Node Sequence Tap (ordered 1 -> 2 node click)
    + Accessible Keyboard Fallback option.
- Browser SHA-256 Proof-of-Work (lightweight 3-4 leading zeros, ~100-300ms).
- WAF Clearance Cookie (HttpOnly, SameSite=Lax) bound to hash(client_ip + User-Agent).
"""
import os
import time
import json
import hmac
import hashlib
import secrets
import random
from typing import Dict, Any, Tuple, Optional, Set
from dataclasses import dataclass

DEFAULT_CHALLENGE_SECRET = os.getenv("WAF_CHALLENGE_SECRET") or secrets.token_hex(32)
CHALLENGE_TTL_SECONDS = 60
CLEARANCE_TTL_SECONDS = int(os.getenv("WAF_CLEARANCE_TTL", "300"))
POW_DIFFICULTY_ZEROS = 3  # 3 leading hex zeros (e.g. '000') for ~100-300ms in modern browsers
MIN_INTERACTION_MS = 250   # Reject bot instant solves (< 250ms)


def get_challenge_secret() -> bytes:
    return (os.getenv("WAF_CHALLENGE_SECRET") or DEFAULT_CHALLENGE_SECRET).encode("utf-8")


def hash_client_binding(client_ip: str, user_agent: str) -> str:
    """Computes SHA-256 fingerprint binding client IP and User-Agent."""
    raw = f"{client_ip.strip()}::{user_agent.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def sanitize_redirect_url(url: Optional[str]) -> str:
    """Strictly validates redirect URL to prevent Open-Redirect vulnerabilities."""
    if not url or not isinstance(url, str):
        return "/"
    url = url.strip()
    # Must start with exactly one forward slash, not '//' (protocol-relative) or http:/https:
    if url.startswith("/") and not url.startswith("//") and not url.startswith("/\\"):
        # Prevent javascript:, data:, or CR/LF
        if any(c in url for c in ["\r", "\n", "\t", "<", ">", '"', "'"]):
            return "/"
        return url
    return "/"


class ChallengeTokenManager:
    """
    Issues and validates cryptographically signed single-use challenge tokens
    and clearance cookies.
    """

    def __init__(self, secret: Optional[bytes] = None):
        self.secret = secret or get_challenge_secret()
        self.used_nonces: Dict[str, float] = {}  # nonce -> expiry_timestamp

    def _cleanup_expired_nonces(self):
        now = time.time()
        expired = [n for n, exp in self.used_nonces.items() if exp < now]
        for n in expired:
            del self.used_nonces[n]

    def generate_challenge(self, client_ip: str, user_agent: str, redirect_url: str = "/") -> Dict[str, Any]:
        """
        Generates a signed challenge package with randomized task parameters.
        """
        self._cleanup_expired_nonces()
        nonce = secrets.token_hex(16)
        created_at = int(time.time())
        expires_at = created_at + CHALLENGE_TTL_SECONDS
        client_bind = hash_client_binding(client_ip, user_agent)
        safe_redirect = sanitize_redirect_url(redirect_url)

        # Proof-of-Work prefix
        pow_prefix = secrets.token_hex(8)

        # Select one of 3 mini-tasks randomly: 'slider', 'rotate', 'nodes'
        task_type = random.choice(["slider", "rotate", "nodes"])
        task_data: Dict[str, Any] = {"type": task_type}

        if task_type == "slider":
            # Target snap position between 80px and 220px (slider width 280px)
            target_x = random.randint(90, 210)
            task_data["target_x"] = target_x
            task_data["tolerance"] = 10
            expected_answer = str(target_x)
        elif task_type == "rotate":
            # Random initial angle: 90, 180, or 270 degrees
            initial_angle = random.choice([90, 180, 270])
            task_data["initial_angle"] = initial_angle
            # Goal is always upright (0 degrees)
            expected_answer = "0"
        else:  # 'nodes'
            # Two nodes in random relative order / position
            task_data["node1_label"] = "1"
            task_data["node2_label"] = "2"
            task_data["node1_pos"] = {"x": random.randint(20, 100), "y": random.randint(20, 80)}
            task_data["node2_pos"] = {"x": random.randint(140, 220), "y": random.randint(20, 80)}
            expected_answer = "1,2"

        # Sign token: nonce:created_at:expires_at:client_bind:pow_prefix:task_type:expected_answer
        payload = f"{nonce}:{created_at}:{expires_at}:{client_bind}:{pow_prefix}:{task_type}:{expected_answer}"
        sig = hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

        token = f"{payload}:{sig}"

        return {
            "token": token,
            "nonce": nonce,
            "pow_prefix": pow_prefix,
            "pow_difficulty": POW_DIFFICULTY_ZEROS,
            "task": task_data,
            "redirect_url": safe_redirect,
            "expires_in": CHALLENGE_TTL_SECONDS,
        }

    def verify_solution(
        self,
        token: str,
        answer: str,
        pow_nonce: str,
        duration_ms: int,
        client_ip: str,
        user_agent: str,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates token integrity, single-use, PoW, duration, and task answer.
        """
        self._cleanup_expired_nonces()
        parts = token.split(":")
        if len(parts) != 8:
            return False, "INVALID_TOKEN_FORMAT", {}

        nonce, created_s, expires_s, client_bind, pow_prefix, task_type, expected_ans, sig = parts

        # 1. Verify HMAC Signature
        payload = f"{nonce}:{created_s}:{expires_s}:{client_bind}:{pow_prefix}:{task_type}:{expected_ans}"
        expected_sig = hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return False, "SIGNATURE_MISMATCH", {}

        now = time.time()
        expires_at = float(expires_s)

        # 2. Check Expiration
        if now > expires_at:
            return False, "TOKEN_EXPIRED", {}

        # 3. Check Single-Use Nonce
        if nonce in self.used_nonces:
            return False, "NONCE_REPLAY_DETECTED", {}

        # 4. Check Client Fingerprint
        expected_client = hash_client_binding(client_ip, user_agent)
        if not hmac.compare_digest(client_bind, expected_client):
            return False, "CLIENT_BINDING_MISMATCH", {}

        # 5. Check Human Duration (reject instant bot solves)
        if duration_ms < MIN_INTERACTION_MS:
            return False, "BOT_SPEED_REJECTED", {}

        # 6. Check Proof-of-Work
        pow_str = f"{pow_prefix}{pow_nonce}"
        pow_hash = hashlib.sha256(pow_str.encode("utf-8")).hexdigest()
        required_prefix = "0" * POW_DIFFICULTY_ZEROS
        if not pow_hash.startswith(required_prefix):
            return False, "INVALID_PROOF_OF_WORK", {}

        # 7. Check Task Answer
        answer_str = str(answer).strip()
        if task_type == "slider":
            try:
                given_x = int(answer_str)
                target_x = int(expected_ans)
                if abs(given_x - target_x) > 12:  # Tolerance +-12px
                    return False, "TASK_ANSWER_INCORRECT", {}
            except ValueError:
                return False, "TASK_ANSWER_MALFORMED", {}
        elif task_type == "rotate":
            if answer_str != "0" and answer_str != "360":
                return False, "TASK_ANSWER_INCORRECT", {}
        elif task_type == "nodes":
            if answer_str != expected_ans:
                return False, "TASK_ANSWER_INCORRECT", {}
        elif task_type == "keyboard_fallback":
            # For accessibility fallback, answer must match expected_ans
            if answer_str != expected_ans:
                return False, "TASK_ANSWER_INCORRECT", {}
        else:
            if answer_str != expected_ans:
                return False, "TASK_ANSWER_INCORRECT", {}

        # Mark Nonce Consumed (store until its natural expiry + 10s)
        self.used_nonces[nonce] = expires_at + 10.0

        return True, "VERIFICATION_SUCCESS", {"task_type": task_type, "duration_ms": duration_ms}

    def issue_clearance_cookie(self, client_ip: str, user_agent: str) -> str:
        """
        Creates a tamper-proof HMAC signed clearance cookie bound to client_ip + User-Agent.
        Format: created_at:expires_at:client_binding:hmac_sig
        """
        created_at = int(time.time())
        expires_at = created_at + CLEARANCE_TTL_SECONDS
        client_bind = hash_client_binding(client_ip, user_agent)
        payload = f"{created_at}:{expires_at}:{client_bind}"
        sig = hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload}:{sig}"

    def validate_clearance_cookie(self, cookie_val: Optional[str], client_ip: str, user_agent: str) -> bool:
        """
        Validates the clearance cookie's signature, expiration, and client fingerprint.
        """
        if not cookie_val or not isinstance(cookie_val, str):
            return False
        parts = cookie_val.split(":")
        if len(parts) != 4:
            return False

        created_s, expires_s, client_bind, sig = parts
        payload = f"{created_s}:{expires_s}:{client_bind}"
        expected_sig = hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            return False

        # Expiry check
        try:
            if time.time() > float(expires_s):
                return False
        except ValueError:
            return False

        # Client binding check
        expected_client = hash_client_binding(client_ip, user_agent)
        if not hmac.compare_digest(client_bind, expected_client):
            return False

        return True


# Global token manager
challenge_manager = ChallengeTokenManager()


# ============================================================================
# Pure HTML/SVG/CSS/JS Self-Contained Verification Page Generator (Zero CDN)
# ============================================================================

def render_challenge_page(
    challenge_data: Dict[str, Any],
    request_id: str,
    target_path: str = "/",
) -> str:
    """
    Renders a stunning dark glassmorphic HTML page containing inline SVGs,
    Proof-of-Work web worker/script, and interactive client task.
    """
    token = challenge_data["token"]
    pow_prefix = challenge_data["pow_prefix"]
    difficulty = challenge_data["pow_difficulty"]
    task = challenge_data["task"]
    task_type = task["type"]
    safe_redirect = sanitize_redirect_url(challenge_data.get("redirect_url", target_path))

    task_json_str = json.dumps(task)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Verification | Protected by Transformer-WAF</title>
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.75);
      --card-border: rgba(255, 255, 255, 0.12);
      --primary: #38bdf8;
      --primary-glow: rgba(56, 189, 248, 0.4);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --success: #34d399;
      --danger: #f87171;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    body {{
      background-color: var(--bg);
      background-image: radial-gradient(circle at 50% 20%, rgba(56, 189, 248, 0.08) 0%, transparent 60%);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }}
    .waf-card {{
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 32px;
      max-width: 440px;
      width: 100%;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
      text-align: center;
    }}
    .shield-icon {{
      width: 56px;
      height: 56px;
      margin: 0 auto 16px auto;
      display: block;
      filter: drop-shadow(0 0 12px var(--primary-glow));
    }}
    h1 {{ font-size: 20px; font-weight: 700; margin-bottom: 8px; letter-spacing: -0.02em; }}
    p.desc {{ font-size: 13.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 24px; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      background: rgba(56, 189, 248, 0.1);
      border: 1px solid rgba(56, 189, 248, 0.2);
      border-radius: 9999px;
      font-size: 11px;
      color: var(--primary);
      margin-bottom: 20px;
    }}
    .task-container {{
      background: rgba(10, 15, 26, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 24px;
      min-height: 140px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      position: relative;
      user-select: none;
    }}

    /* Task A: Slider */
    .slider-track {{
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 24px;
      position: relative;
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }}
    .slider-target {{
      position: absolute;
      top: 6px;
      width: 36px;
      height: 36px;
      border: 2px dashed var(--primary);
      border-radius: 10px;
      background: rgba(56, 189, 248, 0.1);
      box-sizing: border-box;
    }}
    .slider-knob {{
      position: absolute;
      top: 4px;
      left: 4px;
      width: 40px;
      height: 40px;
      background: var(--primary);
      border-radius: 20px;
      cursor: grab;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 15px var(--primary-glow);
      transition: box-shadow 0.2s;
    }}
    .slider-knob:active {{ cursor: grabbing; box-shadow: 0 0 25px var(--primary); }}

    /* Task B: Rotate Icon */
    .rotate-box {{
      width: 90px;
      height: 90px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.1);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
    }}
    .rotate-box:hover {{ background: rgba(255, 255, 255, 0.08); }}

    /* Task C: Node Tap */
    .nodes-canvas {{
      width: 260px;
      height: 110px;
      position: relative;
      background: rgba(255, 255, 255, 0.02);
      border-radius: 10px;
    }}
    .tap-node {{
      position: absolute;
      width: 38px;
      height: 38px;
      border-radius: 50%;
      background: rgba(56, 189, 248, 0.2);
      border: 2px solid var(--primary);
      color: var(--primary);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 0 10px var(--primary-glow);
      transition: all 0.2s;
    }}
    .tap-node.active {{
      background: var(--success);
      border-color: var(--success);
      color: #000;
      box-shadow: 0 0 15px rgba(52, 211, 153, 0.5);
    }}

    .status-text {{
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 10px;
      min-height: 20px;
    }}
    .btn {{
      background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
      color: #fff;
      border: none;
      border-radius: 12px;
      padding: 12px 24px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      width: 100%;
      transition: opacity 0.2s, transform 0.1s;
    }}
    .btn:hover {{ opacity: 0.95; }}
    .btn:active {{ transform: scale(0.98); }}
    .btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
    .footer-meta {{
      margin-top: 20px;
      font-size: 11px;
      color: #64748b;
      display: flex;
      justify-content: space-between;
    }}
    .accessible-link {{
      color: var(--text-muted);
      font-size: 12px;
      text-decoration: underline;
      cursor: pointer;
      margin-top: 12px;
      display: inline-block;
    }}
  </style>
</head>
<body>
  <div class="waf-card">
    <!-- SVG Shield Header -->
    <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>

    <div class="badge">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
      Anomaly Inspection Check
    </div>

    <h1>Quick Security Check</h1>
    <p class="desc" id="task-prompt">Please complete the quick verification below so we know you are human.</p>

    <!-- Interactive Task Container -->
    <div class="task-container" id="task-container">
      <!-- Dynamic task elements injected by JS -->
    </div>

    <div class="status-text" id="status-text">Verifying security posture...</div>

    <button class="btn" id="confirm-btn" disabled onclick="submitChallenge()">Confirm Verification</button>

    <div class="accessible-link" id="acc-fallback-toggle" onclick="enableAccessibleFallback()">
      Keyboard / Accessible Alternative
    </div>

    <div class="footer-meta">
      <span>Ray ID: {request_id}</span>
      <span>Transformer-WAF Guard</span>
    </div>
  </div>

  <script>
    const challengeData = {task_json_str};
    const token = "{token}";
    const powPrefix = "{pow_prefix}";
    const powDiff = {difficulty};
    const redirectUrl = "{safe_redirect}";

    let startTime = Date.now();
    let solvedPowNonce = "";
    let taskAnswer = "";
    let isTaskSolved = false;

    // 1. Solve Proof of Work in background (SHA-256)
    async function sha256(str) {{
      const buf = new TextEncoder().encode(str);
      const digest = await crypto.subtle.digest('SHA-256', buf);
      return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    }}

    async function solvePoW() {{
      const targetPrefix = '0'.repeat(powDiff);
      let nonce = 0;
      while (true) {{
        const hash = await sha256(powPrefix + nonce.toString());
        if (hash.startsWith(targetPrefix)) {{
          solvedPowNonce = nonce.toString();
          document.getElementById('status-text').innerText = 'Security check ready. Complete the task above.';
          break;
        }}
        nonce++;
      }}
    }}
    solvePoW();

    // 2. Render Interactive Task
    const container = document.getElementById('task-container');
    const promptEl = document.getElementById('task-prompt');
    const confirmBtn = document.getElementById('confirm-btn');

    if (challengeData.type === 'slider') {{
      promptEl.innerText = 'Drag the glowing piece into the target slot.';
      container.innerHTML = `
        <div class="slider-track" id="slider-track">
          <div class="slider-target" style="left: ${{challengeData.target_x}}px;"></div>
          <div class="slider-knob" id="slider-knob">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>
          </div>
        </div>
      `;
      setupSlider();
    }} else if (challengeData.type === 'rotate') {{
      promptEl.innerText = 'Tap the icon to rotate it upright (pointing up).';
      let currentAngle = challengeData.initial_angle || 90;
      container.innerHTML = `
        <div class="rotate-box" id="rotate-icon" style="transform: rotate(${{currentAngle}}deg);">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2">
            <path d="M12 2L19 21L12 17L5 21L12 2Z"/>
          </svg>
        </div>
      `;
      const icon = document.getElementById('rotate-icon');
      icon.onclick = () => {{
        currentAngle = (currentAngle + 90) % 360;
        icon.style.transform = `rotate(${{currentAngle}}deg)`;
        if (currentAngle === 0) {{
          taskAnswer = "0";
          isTaskSolved = true;
          confirmBtn.disabled = false;
          document.getElementById('status-text').innerText = 'Upright position aligned! Click Confirm.';
        }} else {{
          isTaskSolved = false;
          confirmBtn.disabled = true;
        }}
      }};
    }} else if (challengeData.type === 'nodes') {{
      promptEl.innerText = 'Click node 1 then node 2 in sequential order.';
      container.innerHTML = `
        <div class="nodes-canvas">
          <div class="tap-node" id="node-1" style="left: ${{challengeData.node1_pos.x}}px; top: ${{challengeData.node1_pos.y}}px;">1</div>
          <div class="tap-node" id="node-2" style="left: ${{challengeData.node2_pos.x}}px; top: ${{challengeData.node2_pos.y}}px;">2</div>
        </div>
      `;
      let step = 0;
      const n1 = document.getElementById('node-1');
      const n2 = document.getElementById('node-2');
      n1.onclick = () => {{
        if (step === 0) {{
          step = 1;
          n1.classList.add('active');
          document.getElementById('status-text').innerText = 'Great! Now click node 2.';
        }}
      }};
      n2.onclick = () => {{
        if (step === 1) {{
          step = 2;
          n2.classList.add('active');
          taskAnswer = "1,2";
          isTaskSolved = true;
          confirmBtn.disabled = false;
          document.getElementById('status-text').innerText = 'Sequence complete! Click Confirm.';
        }}
      }};
    }}

    function setupSlider() {{
      const knob = document.getElementById('slider-knob');
      const track = document.getElementById('slider-track');
      let dragging = false;
      let startX = 0;
      let currentX = 0;
      let dragSteps = 0;

      const onStart = (e) => {{
        dragging = true;
        startX = (e.touches ? e.touches[0].clientX : e.clientX) - currentX;
      }};
      const onMove = (e) => {{
        if (!dragging) return;
        dragSteps++;
        const clientX = e.touches ? e.touches[0].clientX : e.clientX;
        const trackRect = track.getBoundingClientRect();
        let newX = clientX - trackRect.left - 20;
        newX = Math.max(4, Math.min(newX, trackRect.width - 44));
        currentX = newX;
        knob.style.left = currentX + 'px';

        // Check snap tolerance
        if (Math.abs(currentX - challengeData.target_x) <= (challengeData.tolerance || 10)) {{
          taskAnswer = Math.round(currentX).toString();
          isTaskSolved = true;
          confirmBtn.disabled = false;
          document.getElementById('status-text').innerText = 'Snap position matched! Click Confirm.';
        }} else {{
          isTaskSolved = false;
          confirmBtn.disabled = true;
        }}
      }};
      const onEnd = () => {{ dragging = false; }};

      knob.addEventListener('mousedown', onStart);
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onEnd);
      knob.addEventListener('touchstart', onStart);
      window.addEventListener('touchmove', onMove);
      window.addEventListener('touchend', onEnd);
    }}

    function enableAccessibleFallback() {{
      promptEl.innerText = 'Accessible Mode: Click button below to complete.';
      container.innerHTML = `
        <div style="padding: 10px;">
          <label style="font-size: 13px; color: var(--text-muted); display: block; margin-bottom: 8px;">Single-Step Verification Pass:</label>
          <button class="btn" style="background: rgba(56, 189, 248, 0.2); border: 1px solid var(--primary);" onclick="accSolve()">Confirm Human Presence</button>
        </div>
      `;
      window.accSolve = () => {{
        taskAnswer = challengeData.type === 'slider' ? challengeData.target_x.toString() : (challengeData.type === 'rotate' ? '0' : '1,2');
        isTaskSolved = true;
        confirmBtn.disabled = false;
        document.getElementById('status-text').innerText = 'Accessible check ready. Click Confirm.';
      }};
    }}

    async function submitChallenge() {{
      if (!isTaskSolved || !solvedPowNonce) return;
      confirmBtn.disabled = true;
      document.getElementById('status-text').innerText = 'Validating cryptographic proof...';

      const durationMs = Date.now() - startTime;
      try {{
        const resp = await fetch('/_waf/challenge/verify', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            token: token,
            answer: taskAnswer,
            pow_nonce: solvedPowNonce,
            duration_ms: durationMs,
            redirect_url: redirectUrl
          }})
        }});
        const data = await resp.json();
        if (resp.ok && data.verified) {{
          document.getElementById('status-text').style.color = '#34d399';
          document.getElementById('status-text').innerText = 'Verified! Redirecting...';
          setTimeout(() => {{ window.location.href = data.redirect_url || '/'; }}, 500);
        }} else {{
          document.getElementById('status-text').style.color = '#f87171';
          document.getElementById('status-text').innerText = 'Verification failed: ' + (data.detail || 'Please reload');
        }}
      }} catch (err) {{
        document.getElementById('status-text').innerText = 'Error connecting to verification server.';
      }}
    }}
  </script>
</body>
</html>
"""
    return html
