"""
avalanche.py - Avalanche Effect Measurement Module for AR-SPECK

AR-SPECK Project Phase 5: Crypto-Quality Evaluation

The Avalanche Effect is a fundamental property of cryptographically secure block ciphers.
It specifies that a small change in either the plaintext or the key (such as flipping a single bit)
should cause a drastic change in the ciphertext — ideally flipping approximately 50% of the
ciphertext bits (32 out of 64 bits for SPECK64).

This module measures:
  1. Plaintext Avalanche Effect: % of ciphertext bits flipped when 1 plaintext bit is flipped.
  2. Key Avalanche Effect:       % of ciphertext bits flipped when 1 key bit is flipped.

Target Ideal Value: ~50.0% (Full non-linear diffusion)
"""

import random
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from speck64 import generate_key_schedule, encrypt_block, MASK_32


def count_set_bits_64(val: int) -> int:
    """Counts the number of set bits (1s) in a 64-bit integer."""
    return bin(val & 0xFFFFFFFFFFFFFFFF).count('1')


def measure_plaintext_avalanche(rounds: int, trials: int = 1000) -> float:
    """
    Measures average % of ciphertext bits flipped when 1 plaintext bit is flipped.
    
    :param rounds: Number of SPECK encryption rounds
    :param trials: Number of Monte Carlo trials
    :return: Average percentage of ciphertext bits flipped (0.0% to 100.0%)
    """
    total_bit_flips = 0

    for _ in range(trials):
        # Generate random 64-bit plaintext as two 32-bit words (pt_x, pt_y)
        pt_x = random.randint(0, MASK_32)
        pt_y = random.randint(0, MASK_32)

        # Generate random 128-bit key as four 32-bit words
        key_words = [random.randint(0, MASK_32) for _ in range(4)]
        r_keys = generate_key_schedule(key_words, rounds=rounds)

        # Encrypt original plaintext block
        ct1_x, ct1_y = encrypt_block(pt_x, pt_y, r_keys)
        ct1_64 = (ct1_x << 32) | ct1_y

        # Flip 1 random bit in plaintext (bit position 0..63)
        bit_pos = random.randint(0, 63)
        if bit_pos < 32:
            mod_pt_x = pt_x
            mod_pt_y = pt_y ^ (1 << bit_pos)
        else:
            mod_pt_x = pt_x ^ (1 << (bit_pos - 32))
            mod_pt_y = pt_y

        # Encrypt modified plaintext block
        ct2_x, ct2_y = encrypt_block(mod_pt_x, mod_pt_y, r_keys)
        ct2_64 = (ct2_x << 32) | ct2_y

        # Count differing bits (XOR popcount)
        differing_bits = count_set_bits_64(ct1_64 ^ ct2_64)
        total_bit_flips += differing_bits

    avg_flips_per_trial = total_bit_flips / trials
    avg_percentage = (avg_flips_per_trial / 64.0) * 100.0
    return avg_percentage


def measure_key_avalanche(rounds: int, trials: int = 1000) -> float:
    """
    Measures average % of ciphertext bits flipped when 1 key bit is flipped.
    
    :param rounds: Number of SPECK encryption rounds
    :param trials: Number of Monte Carlo trials
    :return: Average percentage of ciphertext bits flipped (0.0% to 100.0%)
    """
    total_bit_flips = 0

    for _ in range(trials):
        # Generate random 64-bit plaintext
        pt_x = random.randint(0, MASK_32)
        pt_y = random.randint(0, MASK_32)

        # Generate random 128-bit key
        key_words = [random.randint(0, MASK_32) for _ in range(4)]
        r_keys1 = generate_key_schedule(key_words, rounds=rounds)

        # Encrypt plaintext under key 1
        ct1_x, ct1_y = encrypt_block(pt_x, pt_y, r_keys1)
        ct1_64 = (ct1_x << 32) | ct1_y

        # Flip 1 random bit in key (bit position 0..127)
        bit_pos = random.randint(0, 127)
        word_idx = bit_pos // 32
        bit_in_word = bit_pos % 32

        mod_key_words = list(key_words)
        mod_key_words[word_idx] ^= (1 << bit_in_word)

        r_keys2 = generate_key_schedule(mod_key_words, rounds=rounds)

        # Encrypt same plaintext under key 2
        ct2_x, ct2_y = encrypt_block(pt_x, pt_y, r_keys2)
        ct2_64 = (ct2_x << 32) | ct2_y

        # Count differing bits
        differing_bits = count_set_bits_64(ct1_64 ^ ct2_64)
        total_bit_flips += differing_bits

    avg_flips_per_trial = total_bit_flips / trials
    avg_percentage = (avg_flips_per_trial / 64.0) * 100.0
    return avg_percentage


if __name__ == "__main__":
    print("Testing Avalanche Effect (1000 trials):")
    for r in [27, 20, 12]:
        pt_av = measure_plaintext_avalanche(rounds=r, trials=1000)
        key_av = measure_key_avalanche(rounds=r, trials=1000)
        print(f"  Rounds T={r:2d} -> Plaintext Avalanche: {pt_av:.2f}%, Key Avalanche: {key_av:.2f}%")
