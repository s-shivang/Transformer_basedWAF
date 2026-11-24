import sys
import time
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.firewall.validate_firewall import run_tests as test_firewall
from src.models.train_transformer import train_model
from src.evaluation.evaluate_held_out import main as run_final_evaluation
from src.firewall.shadow_validator import run_shadow_mode_replay


def run_master_pipeline():
    print("=" * 80)
    print("TRANSFORMER-BASED WAF: MASTER END-TO-END EXECUTION PIPELINE")
    print("Hardware: Local Laptop (NVIDIA GeForce RTX 2050 4 GB / CPU)")
    print("Budget: $0 Cloud Spend (100% Local On-Device Compute)")
    print("=" * 80)

    # Step 1: Validate 4-Layer Firewall
    print("\n>>> STEP 1: VALIDATING 4-LAYER FIREWALL ARCHITECTURE & RULES ENGINE <<<")
    test_firewall()

    # Step 2: Train Transformer Model on Local GPU
    print("\n>>> STEP 2: FINE-TUNING TRANSFORMER ON LOCAL LAPTOP (RTX 2050 GPU) <<<")
    train_model(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        num_epochs=3,
        batch_size=16,
        learning_rate=2e-5,
        max_length=128,
    )

    # Step 3: Sealed Post-Hoc Held-Out CSIC Partition Evaluation
    print("\n>>> STEP 3: BENCHMARKING ON POST-HOC HELD-OUT CSIC PARTITION <<<")
    run_final_evaluation()

    # Step 4: Shadow Mode Replay Validation
    print("\n>>> STEP 4: EXECUTING SHADOW MODE REPLAY VALIDATION <<<")
    run_shadow_mode_replay(sample_size=2000)

    print("\n" + "=" * 80)
    print("MASTER PIPELINE COMPLETED SUCCESSFULLY!")
    print("All models, reports, and benchmarks generated in 'reports/' and 'models/saved/'.")
    print("=" * 80)


if __name__ == "__main__":
    run_master_pipeline()
