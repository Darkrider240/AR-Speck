"""
throughput.py - SPECK Throughput & Latency Benchmarks vs AES-128 Baseline

AR-SPECK Project Phase 6: Performance Benchmarks

This module measures the raw block encryption and decryption performance of SPECK64/128
across round counts T in {27, 20, 12}, and compares performance against an AES-128 baseline.

Measurement Parameters:
- High-precision timer: `time.perf_counter()`
- Batch size: N = 100,000 blocks (800,000 bytes)
- Measured Metrics:
  - Throughput (blocks/sec)
  - Data Throughput (MB/sec)
  - Per-block Latency (microseconds / block)

AES-128 Comparison Baseline Note (Viva Requirement):
- AES-128 operates on a 16-byte (128-bit) native block size.
- SPECK64/128 operates on an 8-byte (64-bit) native block size.
- Encrypting an 8-byte game payload with AES requires 8 bytes of padding (16 bytes on wire),
  doubling payload size. This overhead is explicitly noted in comparisons.
"""

import time
import random
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from speck64 import generate_key_schedule, encrypt_block, decrypt_block, MASK_32

# Optional AES import via pycryptodome (Crypto.Cipher.AES) for comparison baseline
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_AES = True
except ImportError:
    HAS_AES = False


def measure_speck_throughput(rounds: int, num_blocks: int = 100000) -> dict:
    """
    Measures SPECK64 encryption and decryption throughput and latency for a given round count.
    
    :param rounds: Number of SPECK encryption rounds
    :param num_blocks: Number of 64-bit blocks to benchmark (default 100,000)
    :return: Dictionary containing timing metrics
    """
    # Generate random test blocks
    blocks = [(random.randint(0, MASK_32), random.randint(0, MASK_32)) for _ in range(num_blocks)]
    key_words = [random.randint(0, MASK_32) for _ in range(4)]
    r_keys = generate_key_schedule(key_words, rounds=rounds)

    # -------------------------------------------------------------------------
    # 1. Encryption Benchmark
    # -------------------------------------------------------------------------
    ciphertexts = []
    t0 = time.perf_counter()
    for x, y in blocks:
        cx, cy = encrypt_block(x, y, r_keys)
        ciphertexts.append((cx, cy))
    t1 = time.perf_counter()

    enc_total_time = t1 - t0
    enc_blocks_per_sec = num_blocks / enc_total_time if enc_total_time > 0 else 0
    enc_latency_us = (enc_total_time / num_blocks) * 1e6
    enc_mb_per_sec = (num_blocks * 8) / (enc_total_time * 1024 * 1024)

    # -------------------------------------------------------------------------
    # 2. Decryption Benchmark
    # -------------------------------------------------------------------------
    t0 = time.perf_counter()
    for cx, cy in ciphertexts:
        decrypt_block(cx, cy, r_keys)
    t1 = time.perf_counter()

    dec_total_time = t1 - t0
    dec_blocks_per_sec = num_blocks / dec_total_time if dec_total_time > 0 else 0
    dec_latency_us = (dec_total_time / num_blocks) * 1e6
    dec_mb_per_sec = (num_blocks * 8) / (dec_total_time * 1024 * 1024)

    return {
        "rounds": rounds,
        "num_blocks": num_blocks,
        "enc_time_sec": enc_total_time,
        "enc_blocks_per_sec": enc_blocks_per_sec,
        "enc_latency_us": enc_latency_us,
        "enc_mb_per_sec": enc_mb_per_sec,
        "dec_time_sec": dec_total_time,
        "dec_blocks_per_sec": dec_blocks_per_sec,
        "dec_latency_us": dec_latency_us,
        "dec_mb_per_sec": dec_mb_per_sec,
    }


def measure_aes128_baseline(num_blocks: int = 100000) -> dict:
    """
    Measures AES-128 baseline encryption and decryption throughput and latency.
    Requires pycryptodome (Crypto.Cipher.AES).
    
    :param num_blocks: Number of 8-byte payload blocks to encrypt (padded to 16 bytes for AES)
    :return: Dictionary containing timing metrics or None if pycryptodome unavailable
    """
    if not HAS_AES:
        return None

    aes_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    raw_payloads = [f"P_{i:06d}".encode("utf-8")[:8] for i in range(num_blocks)]
    
    # AES-ECB mode used for fair block-level benchmark comparison
    cipher_enc = AES.new(aes_key, AES.MODE_ECB)

    # 1. AES Encryption
    padded_payloads = [pad(p, 16) for p in raw_payloads]
    ciphertexts = []
    t0 = time.perf_counter()
    for p in padded_payloads:
        ciphertexts.append(cipher_enc.encrypt(p))
    t1 = time.perf_counter()

    enc_total_time = t1 - t0
    enc_blocks_per_sec = num_blocks / enc_total_time if enc_total_time > 0 else 0
    enc_latency_us = (enc_total_time / num_blocks) * 1e6
    enc_mb_per_sec = (num_blocks * 8) / (enc_total_time * 1024 * 1024)

    # 2. AES Decryption
    cipher_dec = AES.new(aes_key, AES.MODE_ECB)
    t0 = time.perf_counter()
    for c in ciphertexts:
        unpad(cipher_dec.decrypt(c), 16)
    t1 = time.perf_counter()

    dec_total_time = t1 - t0
    dec_blocks_per_sec = num_blocks / dec_total_time if dec_total_time > 0 else 0
    dec_latency_us = (dec_total_time / num_blocks) * 1e6
    dec_mb_per_sec = (num_blocks * 8) / (dec_total_time * 1024 * 1024)

    return {
        "cipher": "AES-128 (ECB)",
        "num_blocks": num_blocks,
        "enc_time_sec": enc_total_time,
        "enc_blocks_per_sec": enc_blocks_per_sec,
        "enc_latency_us": enc_latency_us,
        "enc_mb_per_sec": enc_mb_per_sec,
        "dec_time_sec": dec_total_time,
        "dec_blocks_per_sec": dec_blocks_per_sec,
        "dec_latency_us": dec_latency_us,
        "dec_mb_per_sec": dec_mb_per_sec,
        "note": "16-byte AES block size doubles payload overhead for 8-byte game traffic"
    }


def measure_chacha20_baseline(num_blocks: int = 100000) -> dict:
    """
    Measures ChaCha20 baseline encryption and decryption throughput and latency.
    Requires pycryptodome (Crypto.Cipher.ChaCha20).
    """
    try:
        from Crypto.Cipher import ChaCha20
    except ImportError:
        return None

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce = bytes.fromhex("0000000000000000")
    raw_payloads = [f"P_{i:06d}".encode("utf-8")[:8] for i in range(num_blocks)]

    # 1. ChaCha20 Encryption
    ciphertexts = []
    t0 = time.perf_counter()
    for p in raw_payloads:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertexts.append(cipher.encrypt(p))
    t1 = time.perf_counter()

    enc_total_time = t1 - t0
    enc_blocks_per_sec = num_blocks / enc_total_time if enc_total_time > 0 else 0
    enc_latency_us = (enc_total_time / num_blocks) * 1e6
    enc_mb_per_sec = (num_blocks * 8) / (enc_total_time * 1024 * 1024)

    # 2. ChaCha20 Decryption
    t0 = time.perf_counter()
    for c in ciphertexts:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        cipher.decrypt(c)
    t1 = time.perf_counter()

    dec_total_time = t1 - t0
    dec_blocks_per_sec = num_blocks / dec_total_time if dec_total_time > 0 else 0
    dec_latency_us = (dec_total_time / num_blocks) * 1e6
    dec_mb_per_sec = (num_blocks * 8) / (dec_total_time * 1024 * 1024)

    return {
        "cipher": "ChaCha20",
        "num_blocks": num_blocks,
        "enc_time_sec": enc_total_time,
        "enc_blocks_per_sec": enc_blocks_per_sec,
        "enc_latency_us": enc_latency_us,
        "enc_mb_per_sec": enc_mb_per_sec,
        "dec_time_sec": dec_total_time,
        "dec_blocks_per_sec": dec_blocks_per_sec,
        "dec_latency_us": dec_latency_us,
        "dec_mb_per_sec": dec_mb_per_sec,
        "note": "Stream cipher baseline used in WireGuard/QUIC"
    }


if __name__ == "__main__":
    print("Running Throughput & Latency Benchmarks (100,000 blocks)...")
    for r in [8, 12, 16, 20, 24, 27]:
        res = measure_speck_throughput(rounds=r, num_blocks=100000)
        print(f"  SPECK64 T={r:2d} -> Enc: {res['enc_blocks_per_sec']:,.0f} blocks/s ({res['enc_latency_us']:.3f} µs/blk), "
              f"Dec: {res['dec_blocks_per_sec']:,.0f} blocks/s ({res['dec_latency_us']:.3f} µs/blk)")

    aes_res = measure_aes128_baseline(num_blocks=100000)
    if aes_res:
        print(f"  AES-128 Baseline -> Enc: {aes_res['enc_blocks_per_sec']:,.0f} blocks/s ({aes_res['enc_latency_us']:.3f} µs/blk)")

    chacha_res = measure_chacha20_baseline(num_blocks=100000)
    if chacha_res:
        print(f"  ChaCha20 Baseline -> Enc: {chacha_res['enc_blocks_per_sec']:,.0f} blocks/s ({chacha_res['enc_latency_us']:.3f} µs/blk)")

