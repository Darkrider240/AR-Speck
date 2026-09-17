"""
mac_overhead.py - Isolated MAC Authentication Overhead Benchmark for AR-SPECK

AR-SPECK Project Phase 6: Performance Benchmarks

This module measures the added latency and throughput of compute_mac (HMAC-SHA256 with
8-byte truncation) in isolation, separate from SPECK cipher timing.

Isolating authentication cost from cipher cost enables the report to state:
  "Cost of Cipher (T=12 or T=27)" vs. "Cost of MAC Authentication".
"""

import time
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from protocol import compute_mac


def measure_mac_overhead(iterations: int = 100000) -> dict:
    """
    Measures HMAC-SHA256 computation overhead over 'iterations' 21-byte wire header+payload packets.
    
    :param iterations: Number of MAC computations (default 100,000)
    :return: Dictionary containing timing metrics
    """
    key = bytes.fromhex("0001020308090a0b1011121318191a1b")
    # Sample 13-byte message (1 byte Tier ID + 8 bytes Ciphertext + 4 bytes Sequence Number)
    sample_header_and_body = bytes.fromhex("019f7c99748e1da0b600000412")

    t0 = time.perf_counter()
    for _ in range(iterations):
        compute_mac(key, sample_header_and_body)
    t1 = time.perf_counter()

    total_time_sec = t1 - t0
    macs_per_sec = iterations / total_time_sec if total_time_sec > 0 else 0
    mac_latency_us = (total_time_sec / iterations) * 1e6

    return {
        "iterations": iterations,
        "total_time_sec": total_time_sec,
        "macs_per_sec": macs_per_sec,
        "mac_latency_us": mac_latency_us,
    }


if __name__ == "__main__":
    print("Measuring HMAC-SHA256 Overhead (100,000 iterations)...")
    res = measure_mac_overhead(iterations=100000)
    print(f"  MAC Computation -> {res['macs_per_sec']:,.0f} MACs/sec ({res['mac_latency_us']:.3f} µs/packet)")
