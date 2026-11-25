"""
Self-contained Modern WAF Benchmark runner.
Spawns the test upstream app (127.0.0.1:8002), the ML inference service (127.0.0.1:8000),
and the WAF Gateway (127.0.0.1:8001), executes the 105-request modern test corpus,
records exact metrics, and shuts down the test processes cleanly.
"""
import sys
import os
import subprocess
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

# Start services
python_exe = str(ROOT / ".venv/Scripts/python.exe")

env = os.environ.copy()
env["PYTHONPATH"] = str(ROOT)
env["WAF_ADMIN_KEY"] = "waf-admin-secret-key-phase7"

print("Starting protected test app (port 8002)...")
p_app = subprocess.Popen(
    [python_exe, "-m", "uvicorn", "tests.test_app.app:app", "--host", "127.0.0.1", "--port", "8002"],
    cwd=str(ROOT),
    env=env,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

print("Starting ML inference service (port 8000)...")
p_ml = subprocess.Popen(
    [python_exe, "-m", "uvicorn", "src.ml_service.app:app", "--host", "127.0.0.1", "--port", "8000"],
    cwd=str(ROOT),
    env=env,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

print("Starting WAF Gateway (port 8001)...")
p_gw = subprocess.Popen(
    [python_exe, "-m", "uvicorn", "src.waf_gateway.app:app", "--host", "127.0.0.1", "--port", "8001"],
    cwd=str(ROOT),
    env=env,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)

time.sleep(5)

try:
    # Run the benchmark
    print("\nRunning modern WAF benchmark script...")
    res = subprocess.run(
        [python_exe, "scratch/run_modern_waf_benchmark.py"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True
    )
    print("STDOUT:\n", res.stdout)
    if res.stderr:
        print("STDERR:\n", res.stderr)
finally:
    print("\nTerminating background test services...")
    p_gw.terminate()
    p_ml.terminate()
    p_app.terminate()
    p_gw.wait()
    p_ml.wait()
    p_app.wait()
    print("Services stopped.")
