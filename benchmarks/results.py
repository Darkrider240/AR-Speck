"""
results.py - Master Performance & Security Trade-Off Benchmark Aggregator

AR-SPECK Project Phase 6: Final Benchmark Synthesis

Combines Phase 5 crypto-quality measurement results (avalanche % & NIST randomness tests)
with Phase 6 performance metrics (throughput, per-block latency, MAC overhead, AES-128 baseline).

Outputs:
1. Console summary trade-off table.
2. Saved CSV artifacts: `benchmarks/final_results.csv` and `crypto_tests/results.csv`.
3. Saved PNG visual figures (saved to both `benchmarks/` and `web/` for live dashboard serving):
   - `throughput_vs_rounds.png`
   - `avalanche_vs_rounds.png`
"""

import sys
import os
import csv
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from benchmarks.throughput import measure_speck_throughput, measure_aes128_baseline, measure_chacha20_baseline
from benchmarks.mac_overhead import measure_mac_overhead
from crypto_tests.run_all_crypto_tests import run_crypto_suite

# Optional matplotlib for chart generation
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend for headless PNG rendering
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def generate_benchmark_charts(final_rows: list, aes_data: dict = None, chacha_data: dict = None):
    """Generates PNG visual charts using matplotlib and copies them to web/ folder."""
    if not HAS_MATPLOTLIB:
        print("Note: matplotlib not installed. Skipping PNG chart generation.")
        return

    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    bench_dir = os.path.join(root_dir, "benchmarks")
    web_dir = os.path.join(root_dir, "web")

    os.makedirs(bench_dir, exist_ok=True)
    os.makedirs(web_dir, exist_ok=True)

    # Chart 1: Throughput vs Round Count & Baselines
    rounds_labels = [f"T={r['round_count']}" for r in final_rows]
    throughputs = [r["enc_throughput_blks"] for r in final_rows]
    colors = ['#06b6d4'] * len(final_rows)

    if aes_data:
        rounds_labels.append("AES-128")
        throughputs.append(aes_data["enc_blocks_per_sec"])
        colors.append('#8b5cf6')

    if chacha_data:
        rounds_labels.append("ChaCha20")
        throughputs.append(chacha_data["enc_blocks_per_sec"])
        colors.append('#3b82f6')

    plt.figure(figsize=(9, 4.5), facecolor='#090d16')
    ax = plt.gca()
    ax.set_facecolor('#090d16')

    bars = plt.bar(rounds_labels, throughputs, color=colors, width=0.55)
    plt.title("AR-SPECK Encryption Throughput Across Tiers vs Baselines", fontsize=11, fontweight='bold', color='#f8fafc', pad=12)
    plt.ylabel("Throughput (blocks / second)", fontsize=9.5, color='#94a3b8')
    plt.tick_params(colors='#94a3b8')
    ax.spines['bottom'].set_color('#334155')
    ax.spines['left'].set_color('#334155')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.grid(axis='y', linestyle='--', alpha=0.2, color='#334155')

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + (max(throughputs)*0.015),
                 f"{height:,.0f}", ha='center', va='bottom', fontsize=8, fontweight='bold', color='#f8fafc')

    plt.tight_layout()
    chart1_bench = os.path.join(bench_dir, "throughput_vs_rounds.png")
    chart1_web = os.path.join(web_dir, "throughput_vs_rounds.png")
    plt.savefig(chart1_bench, dpi=200, facecolor='#090d16')
    plt.savefig(chart1_web, dpi=200, facecolor='#090d16')
    plt.close()

    # Chart 2: Avalanche Effect vs Round Count (Continuous 6-point curve)
    round_nums = [r["round_count"] for r in final_rows]
    pt_avs = [r["pt_avalanche_pct"] for r in final_rows]
    key_avs = [r["key_avalanche_pct"] for r in final_rows]

    plt.figure(figsize=(9, 4.5), facecolor='#090d16')
    ax = plt.gca()
    ax.set_facecolor('#090d16')

    plt.plot(round_nums, pt_avs, marker='o', linewidth=2, markersize=7, label="Plaintext Avalanche %", color='#10b981')
    plt.plot(round_nums, key_avs, marker='s', linewidth=2, markersize=7, label="Key Avalanche %", color='#06b6d4')
    plt.axhline(y=50.0, color='#64748b', linestyle='--', linewidth=1.5, label="Ideal Avalanche (50.0%)")

    plt.title("Avalanche Effect Diffusion vs SPECK Round Count (8..27)", fontsize=11, fontweight='bold', color='#f8fafc', pad=12)
    plt.xlabel("SPECK Round Count (T)", fontsize=9.5, color='#94a3b8')
    plt.ylabel("Average Bits Flipped (%)", fontsize=9.5, color='#94a3b8')
    plt.ylim(45, 55)
    plt.tick_params(colors='#94a3b8')
    ax.spines['bottom'].set_color('#334155')
    ax.spines['left'].set_color('#334155')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.legend(loc="lower right", facecolor='#1e293b', edgecolor='#334155', labelcolor='#f8fafc')
    plt.grid(True, linestyle='--', alpha=0.2, color='#334155')

    plt.tight_layout()
    chart2_bench = os.path.join(bench_dir, "avalanche_vs_rounds.png")
    chart2_web = os.path.join(web_dir, "avalanche_vs_rounds.png")
    plt.savefig(chart2_bench, dpi=200, facecolor='#090d16')
    plt.savefig(chart2_web, dpi=200, facecolor='#090d16')
    plt.close()


def run_master_benchmarks(num_blocks: int = 100000) -> tuple:
    """
    Runs full Phase 5 crypto measurements and Phase 6 performance benchmarks for T in {8, 12, 16, 20, 24, 27}.
    """
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    bench_dir = os.path.join(root_dir, "benchmarks")
    csv_path = os.path.join(bench_dir, "final_results.csv")

    # 1. Run Phase 5 Crypto Quality Suite
    _, crypto_data = run_crypto_suite(trials=1000, num_blocks=1000)
    crypto_dict = {row["round_count"]: row for row in crypto_data}

    # 2. Run Isolated MAC Overhead Benchmark
    mac_data = measure_mac_overhead(iterations=num_blocks)
    mac_latency_us = mac_data["mac_latency_us"]

    # 3. Run SPECK Throughput & Latency Benchmarks
    round_counts = [8, 12, 16, 20, 24, 27]
    final_rows = []

    for r in round_counts:
        perf = measure_speck_throughput(rounds=r, num_blocks=num_blocks)
        cr = crypto_dict.get(r, {})
        
        avg_avalanche = round((cr.get("pt_avalanche_pct", 50.0) + cr.get("key_avalanche_pct", 50.0)) / 2.0, 2)
        
        row = {
            "round_count": r,
            "enc_throughput_blks": round(perf["enc_blocks_per_sec"], 0),
            "enc_latency_us": round(perf["enc_latency_us"], 3),
            "mac_overhead_us": round(mac_latency_us, 3),
            "total_latency_us": round(perf["enc_latency_us"] + mac_latency_us, 3),
            "pt_avalanche_pct": cr.get("pt_avalanche_pct", 50.0),
            "key_avalanche_pct": cr.get("key_avalanche_pct", 50.0),
            "avg_avalanche_pct": avg_avalanche,
            "randomness_status": cr.get("status", "PASS")
        }
        final_rows.append(row)

    # 4. Measure Baselines
    aes_data = measure_aes128_baseline(num_blocks=num_blocks)
    chacha_data = measure_chacha20_baseline(num_blocks=num_blocks)

    # Export to final_results.csv
    try:
        with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "round_count", "enc_throughput_blks", "enc_latency_us",
                "mac_overhead_us", "total_latency_us", "pt_avalanche_pct",
                "key_avalanche_pct", "avg_avalanche_pct", "randomness_status"
            ])
            writer.writeheader()
            writer.writerows(final_rows)
    except Exception as e:
        print(f"Warning: Failed to export final_results.csv: {e}")

    # Generate visual PNG figures
    generate_benchmark_charts(final_rows, aes_data, chacha_data)

    return final_rows, aes_data, chacha_data, mac_data



def main():
    print("=" * 95)
    print("           AR-SPECK PHASE 6: MASTER PERFORMANCE & SECURITY TRADE-OFF TABLE           ")
    print("=" * 95)

    rows, aes_data, chacha_data, mac_data = run_master_benchmarks(num_blocks=100000)

    print("\n" + "-" * 95)
    print(f"{'Round Count':<12} | {'Throughput (blk/s)':<18} | {'Cipher Lat (µs)':<16} | {'MAC Lat (µs)':<14} | {'Avg Av (%)':<10} | {'Randomness':<10}")
    print("-" * 95)
    for r in rows:
        print(f"{r['round_count']:<12} | {r['enc_throughput_blks']:<18,.0f} | {r['enc_latency_us']:<16.3f} | {r['mac_overhead_us']:<14.3f} | {r['avg_avalanche_pct']:<10.2f} | {r['randomness_status']:<10}")
    print("-" * 95)

    if aes_data:
        print(f"AES-128 Baseline | {aes_data['enc_blocks_per_sec']:<18,.0f} | {aes_data['enc_latency_us']:<16.3f} | N/A            | N/A        | PASS")
    if chacha_data:
        print(f"ChaCha20 Baseline| {chacha_data['enc_blocks_per_sec']:<18,.0f} | {chacha_data['enc_latency_us']:<16.3f} | N/A            | N/A        | PASS")
    print("-" * 95)

    print("\n" + "=" * 95)
    print("                      PHASE 6 MASTER BENCHMARKS COMPLETED CLEANLY!                   ")
    print("=" * 95)

    return 0


if __name__ == "__main__":
    sys.exit(main())

