"""
randomness.py - Statistical Ciphertext Randomness Test Battery for AR-SPECK

AR-SPECK Project Phase 5: Crypto-Quality Evaluation

This module implements a lightweight subset of the NIST SP 800-22 statistical test suite
for randomness evaluation:
  1. Monobit Frequency Test (NIST SP 800-22 §2.1): Tests whether the number of 1s and 0s
     in the ciphertext stream is approximately equal.
  2. Runs Test (NIST SP 800-22 §2.2): Tests whether the total number of runs (uninterrupted
     sequences of identical bits) matches the expected distribution for random data.

Statistical Threshold:
  Evaluated at significance level alpha = 0.01. A p-value >= 0.01 indicates that the ciphertext
  stream is statistically indistinguishable from random noise (PASS).

Note on Scope (Viva Disclaimer):
  This is a lightweight subset of NIST SP 800-22 focused on primary frequency and run distribution
  metrics, implemented using standard Python math.erfc without external dependencies.
"""

import math
import random
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from speck64 import generate_key_schedule, encrypt_block, MASK_32


def generate_ciphertext_bitstream(rounds: int, num_blocks: int = 1000) -> list[int]:
    """
    Generates a continuous bitstream list of 0s and 1s by encrypting num_blocks
    with random plaintexts under a fixed key at the given round count.
    
    :param rounds: Number of SPECK encryption rounds
    :param num_blocks: Number of 64-bit blocks to encrypt (e.g. 1000 blocks = 64,000 bits)
    :return: List of integers (0 or 1) of length num_blocks * 64
    """
    key_words = [random.randint(0, MASK_32) for _ in range(4)]
    r_keys = generate_key_schedule(key_words, rounds=rounds)
    
    bitstream = []
    for _ in range(num_blocks):
        pt_x = random.randint(0, MASK_32)
        pt_y = random.randint(0, MASK_32)
        ct_x, ct_y = encrypt_block(pt_x, pt_y, r_keys)
        ct_64 = (ct_x << 32) | ct_y
        
        # Extract 64 bits MSB to LSB
        for shift in range(63, -1, -1):
            bitstream.append((ct_64 >> shift) & 1)
            
    return bitstream


def nist_monobit_frequency_test(bitstream: list[int]) -> tuple[float, bool]:
    """
    NIST SP 800-22 §2.1 Frequency (Monobit) Test.
    
    :param bitstream: List of bits (0 or 1)
    :return: Tuple (p_value: float, pass_flag: bool)
    """
    n = len(bitstream)
    if n == 0:
        return 0.0, False
        
    # Convert 0 -> -1 and 1 -> +1
    sum_val = sum((2 * b - 1) for b in bitstream)
    
    # Calculate S_obs
    s_obs = abs(sum_val) / math.sqrt(n)
    
    # Calculate p-value = erfc(s_obs / sqrt(2))
    p_value = math.erfc(s_obs / math.sqrt(2.0))
    
    # Standard threshold alpha = 0.01
    return p_value, (p_value >= 0.01)


def nist_runs_test(bitstream: list[int]) -> tuple[float, bool]:
    """
    NIST SP 800-22 §2.2 Runs Test.
    
    :param bitstream: List of bits (0 or 1)
    :return: Tuple (p_value: float, pass_flag: bool)
    """
    n = len(bitstream)
    if n == 0:
        return 0.0, False
        
    # Step 1: Pre-test proportion of ones (pi)
    pi = sum(bitstream) / n
    tau = 2.0 / math.sqrt(n)
    
    if abs(pi - 0.5) >= tau:
        # Fails pre-test (frequency condition not met)
        return 0.0, False
        
    # Step 2: Calculate total number of runs (V_n)
    # A run is an uninterrupted sequence of identical bits
    v_n = 1
    for k in range(n - 1):
        if bitstream[k] != bitstream[k + 1]:
            v_n += 1
            
    # Step 3: Compute test statistic P_obs
    numerator = abs(v_n - 2.0 * n * pi * (1.0 - pi))
    denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    
    if denominator == 0:
        return 0.0, False
        
    p_obs = numerator / denominator
    
    # Step 4: Calculate p-value = erfc(P_obs)
    p_value = math.erfc(p_obs)
    
    return p_value, (p_value >= 0.01)


def evaluate_randomness(rounds: int, num_blocks: int = 1000) -> dict:
    """
    Runs both Monobit Frequency and Runs tests on a generated ciphertext stream.
    
    :param rounds: Number of SPECK encryption rounds
    :param num_blocks: Number of 64-bit blocks
    :return: Dictionary containing test results and p-values
    """
    bits = generate_ciphertext_bitstream(rounds, num_blocks=num_blocks)
    freq_p, freq_pass = nist_monobit_frequency_test(bits)
    runs_p, runs_pass = nist_runs_test(bits)
    
    return {
        "rounds": rounds,
        "total_bits": len(bits),
        "freq_p_value": freq_p,
        "freq_pass": freq_pass,
        "runs_p_value": runs_p,
        "runs_pass": runs_pass,
        "all_passed": (freq_pass and runs_pass)
    }


if __name__ == "__main__":
    print("Testing Ciphertext Randomness (1000 blocks / 64,000 bits):")
    for r in [27, 20, 12]:
        res = evaluate_randomness(rounds=r, num_blocks=1000)
        print(f"  Rounds T={r:2d} -> Freq p: {res['freq_p_value']:.4f} ({'PASS' if res['freq_pass'] else 'FAIL'}), "
              f"Runs p: {res['runs_p_value']:.4f} ({'PASS' if res['runs_pass'] else 'FAIL'})")
