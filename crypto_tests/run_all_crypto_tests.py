"""
run_all_crypto_tests.py - Master Crypto Benchmark Runner & CSV Exporter

AR-SPECK Project Phase 5: Crypto-Quality Evaluation Suite

Executes Avalanche Effect measurements and NIST-style Ciphertext Randomness evaluation
across round counts T in {27, 20, 12}, displays a viva-ready console table, and writes
results to crypto_tests/results.csv.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import csv
from crypto_tests.avalanche import measure_plaintext_avalanche, measure_key_avalanche
from crypto_tests.randomness import evaluate_randomness


def run_crypto_suite(trials: int = 1000, num_blocks: int = 1000, 
                     csv_filepath: str = None) -> tuple[bool, list]:
    """
    Executes Phase 5 crypto benchmark battery across round counts 27, 20, 12.
    
    :param trials: Monte Carlo trials for avalanche tests
    :param num_blocks: Blocks for randomness stream
    :param csv_filepath: Path to save results CSV (defaults to crypto_tests/results.csv)
    :return: Tuple (all_passed: bool, results_data: list[dict])
    """
    if csv_filepath is None:
        csv_filepath = os.path.join(os.path.dirname(__file__), "results.csv")

    round_counts = [27, 20, 12]
    results = []
    all_passed = True

    for r in round_counts:
        # 1. Plaintext Avalanche %
        pt_av = measure_plaintext_avalanche(rounds=r, trials=trials)
        # 2. Key Avalanche %
        key_av = measure_key_avalanche(rounds=r, trials=trials)
        # 3. Ciphertext Randomness (Frequency + Runs tests)
        rand_res = evaluate_randomness(rounds=r, num_blocks=num_blocks)
        
        status = "PASS" if rand_res["all_passed"] else "FAIL"
        if not rand_res["all_passed"]:
            all_passed = False

        row = {
            "round_count": r,
            "pt_avalanche_pct": round(pt_av, 2),
            "key_avalanche_pct": round(key_av, 2),
            "freq_p_value": round(rand_res["freq_p_value"], 4),
            "runs_p_value": round(rand_res["runs_p_value"], 4),
            "status": status
        }
        results.append(row)

    # Export to CSV
    try:
        with open(csv_filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "round_count", "pt_avalanche_pct", "key_avalanche_pct",
                "freq_p_value", "runs_p_value", "status"
            ])
            writer.writeheader()
            writer.writerows(results)
    except Exception as e:
        print(f"Warning: Failed to write CSV file '{csv_filepath}': {e}")

    return all_passed, results


def main():
    print("=" * 85)
    print("      AR-SPECK PHASE 5: CRYPTO-QUALITY & AVALANCHE BENCHMARK SUITE          ")
    print("=" * 85)
    print("Running 1000 Avalanche trials and 64,000-bit Randomness evaluation per tier...\n")

    passed, results = run_crypto_suite(trials=1000, num_blocks=1000)

    print("-" * 85)
    print(f"{'Round Count':<12} | {'Plaintext Av (%)':<18} | {'Key Av (%)':<14} | {'Freq p-val':<12} | {'Runs p-val':<12} | {'Status':<6}")
    print("-" * 85)
    for r in results:
        print(f"{r['round_count']:<12} | {r['pt_avalanche_pct']:<18.2f} | {r['key_avalanche_pct']:<14.2f} | {r['freq_p_value']:<12.4f} | {r['runs_p_value']:<12.4f} | {r['status']:<6}")
    print("-" * 85)

    csv_path = os.path.join(os.path.dirname(__file__), "results.csv")
    print(f"\nResults successfully exported to: {os.path.abspath(csv_path)}")

    print("\n" + "=" * 85)
    if passed:
        print("  ALL PHASE 5 CRYPTO-QUALITY & RANDOMNESS BENCHMARKS PASSED (p > 0.01)!  ")
    else:
        print("  SOME STATISTICAL TESTS FAILED THE SIGNIFICANCE THRESHOLD!             ")
    print("=" * 85)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
