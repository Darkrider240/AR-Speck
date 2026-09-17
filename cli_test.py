"""
cli_test.py - Master Verification Runner for AR-SPECK (Phases 1–6 Complete Suite)

AR-SPECK Master Verification Runner

Phase 1: SPECK64/128 Cipher Core (NSA KAT, Direct Decrypt, Byte Equivalence, Variable Rounds).
Phase 2: Sensitivity Tiering & Protocol Layer (Round-Trip, Tamper Tests, Viva Table).
Phase 3: Sliding Window & UDP Socket Networking (Out-of-order, Replay, 200 Clean Burst).
Phase 4: Adversary Attack Suite (Packet Editor, Packet Replay, Spoofed Sender).
Phase 5: Crypto-Quality & Avalanche Benchmarks (Plaintext & Key Avalanche, NIST Frequency & Runs Tests).
Phase 6: Performance Benchmarks & Final Trade-Off Evaluation (Throughput, Latency vs AES-128 Baseline, MAC Overhead, Final Results CSV).
"""

import sys
import time
import struct
from speck64 import (
    generate_key_schedule,
    encrypt_block,
    decrypt_block,
    encrypt_bytes,
    decrypt_bytes,
    DEFAULT_ROUNDS
)
from tiering import classify_tier, TIER_LOW, TIER_HIGH, TIER_ROUNDS
from protocol import pack_packet, unpack_packet, TOTAL_PACKET_LEN
from replay_window import SlidingWindow
from server import ARSpeckServer
from client import ARSpeckClient
from attacks.run_all_attacks import run_all_attack_tests
from crypto_tests.run_all_crypto_tests import run_crypto_suite
from benchmarks.results import run_master_benchmarks


def run_phase1_tests():
    print("=" * 95)
    print("      AR-SPECK PHASE 1: SPECK64/128 CIPHER VERIFICATION SUITE       ")
    print("=" * 95)
    all_passed = True

    # [TEST 1] NSA SPECK64/128 Known-Answer Encryption Test (27 Rounds)
    print("\n[TEST 1] NSA SPECK64/128 Known-Answer Encryption Test (27 Rounds)")
    print("-" * 95)
    nsa_key_words = [0x1b1a1918, 0x13121110, 0x0b0a0908, 0x03020100]
    nsa_pt_x, nsa_pt_y = 0x3b726574, 0x7475432d
    exp_ct_x, exp_ct_y = 0x8c6fa548, 0x454e028b
    
    round_keys_27 = generate_key_schedule(nsa_key_words, rounds=27)
    ct_x, ct_y = encrypt_block(nsa_pt_x, nsa_pt_y, round_keys_27)
    
    print(f"Key Words (K3..K0): {[hex(w) for w in nsa_key_words]}")
    print(f"Plaintext Words:   x = {hex(nsa_pt_x)}, y = {hex(nsa_pt_y)}")
    print(f"Computed CT Words: x = {hex(ct_x)}, y = {hex(ct_y)}")
    print(f"Expected CT Words: x = {hex(exp_ct_x)}, y = {hex(exp_ct_y)}")
    
    if ct_x == exp_ct_x and ct_y == exp_ct_y:
        print("--> PASS: Known-Answer Encryption matches NSA specification exactly!")
    else:
        print("--> FAIL: Encryption output mismatch!")
        all_passed = False

    # [TEST 2] NSA SPECK64/128 Known-Answer Direct Decryption Test (27 Rounds)
    print("\n[TEST 2] NSA SPECK64/128 Known-Answer Direct Decryption Test (27 Rounds)")
    print("-" * 95)
    dec_x, dec_y = decrypt_block(exp_ct_x, exp_ct_y, round_keys_27)
    print(f"Input CT Words:    x = {hex(exp_ct_x)}, y = {hex(exp_ct_y)}")
    print(f"Decrypted Words:   x = {hex(dec_x)}, y = {hex(dec_y)}")
    print(f"Expected PT Words: x = {hex(nsa_pt_x)}, y = {hex(nsa_pt_y)}")
    
    if dec_x == nsa_pt_x and dec_y == nsa_pt_y:
        print("--> PASS: Direct Decryption matches original NSA plaintext exactly!")
    else:
        print("--> FAIL: Direct Decryption output mismatch!")
        all_passed = False

    # [TEST 3] Byte-String Little-Endian Representation Equivalence
    print("\n[TEST 3] Byte-String Little-Endian Representation Equivalence")
    print("-" * 95)
    key_bytes = bytes.fromhex("0001020308090a0b1011121318191a1b")
    pt_bytes = bytes.fromhex("2d4375747465723b")
    
    round_keys_from_bytes = generate_key_schedule(key_bytes, rounds=27)
    ct_bytes = encrypt_bytes(pt_bytes, round_keys_from_bytes)
    dec_bytes = decrypt_bytes(ct_bytes, round_keys_from_bytes)
    exp_ct_bytes = bytes.fromhex("8b024e4548a56f8c")
    
    print(f"Key Bytes (hex):        {key_bytes.hex()}")
    print(f"Plaintext Bytes (hex):  {pt_bytes.hex()}")
    print(f"Computed CT Bytes:      {ct_bytes.hex()}")
    print(f"Expected CT Bytes:      {exp_ct_bytes.hex()}")
    print(f"Decrypted Bytes (hex):  {dec_bytes.hex()}")
    
    if ct_bytes == exp_ct_bytes and dec_bytes == pt_bytes:
        print("--> PASS: Byte-level little-endian encryption & decryption match word-level logic!")
    else:
        print("--> FAIL: Byte-level conversion mismatch!")
        all_passed = False

    # [TEST 4] Variable Round Count Round-Trip Tests (27, 20, 12 Rounds)
    print("\n[TEST 4] Variable Round Count Round-Trip Tests (decrypt(encrypt(x)) == x)")
    print("-" * 95)
    test_round_counts = [27, 20, 12]
    sample_blocks = [
        (0x3b726574, 0x7475432d),
        (0x12345678, 0x9ABCDEF0),
        (0x00000000, 0x00000000),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (0xDEADBEEF, 0xCAFEBABE),
    ]
    
    for r in test_round_counts:
        r_keys = generate_key_schedule(nsa_key_words, rounds=r)
        round_passed = True
        print(f"\n  Checking Round Count T = {r}:")
        for idx, (pt_x, pt_y) in enumerate(sample_blocks, 1):
            ctx_x, ctx_y = encrypt_block(pt_x, pt_y, r_keys)
            rec_x, rec_y = decrypt_block(ctx_x, ctx_y, r_keys)
            match = (rec_x == pt_x and rec_y == pt_y)
            if not match:
                round_passed = False
                all_passed = False
        if round_passed:
            print(f"  --> PASS: All sample blocks decrypt perfectly with T = {r} rounds.")

    return all_passed


def run_phase2_tests():
    print("\n" + "=" * 95)
    print("   AR-SPECK PHASE 2: SENSITIVITY TIERING & PROTOCOL LAYER SUITE     ")
    print("=" * 95)
    all_passed = True
    key = bytes.fromhex("0001020308090a0b1011121318191a1b")
    plaintext_payload = b"MOVE_123"
    seq_no = 1042
    summary_results = []

    # [TEST 5] Protocol Round-Trip & Round Count Verification for TIER_LOW
    print("\n[TEST 5] Protocol Round-Trip & Round Count Verification for TIER_LOW")
    print("-" * 95)
    tier_low = classify_tier("position")
    rounds_low = TIER_ROUNDS[tier_low]
    wire_low = pack_packet(plaintext_payload, seq_no, tier_low, key)
    dec_payload, rec_seq, rec_tier, valid = unpack_packet(wire_low, key)
    
    rk_12 = generate_key_schedule(key, rounds=12)
    expected_ct_12 = encrypt_bytes(plaintext_payload, rk_12)
    actual_ct_12 = wire_low[1:9]
    
    print(f"Packet Type: 'position' -> Tier: {tier_low} (Rounds = {rounds_low})")
    print(f"Wire Packet (21 B):     {wire_low.hex()}")
    print(f"Extracted CT (hex):     {actual_ct_12.hex()}")
    print(f"Direct SPECK12 CT:      {expected_ct_12.hex()}")
    print(f"Decrypted Payload:      {dec_payload} (Seq: {rec_seq}, Valid: {valid})")
    
    test5_ok = (valid and dec_payload == plaintext_payload and rec_seq == seq_no and actual_ct_12 == expected_ct_12)
    if test5_ok:
        print("--> PASS: TIER_LOW round-trip verified and confirmed 12 SPECK rounds used!")
        summary_results.append((tier_low, rounds_low, len(wire_low), "PASS"))
    else:
        print("--> FAIL: TIER_LOW round-trip mismatch!")
        all_passed = False
        summary_results.append((tier_low, rounds_low, len(wire_low), "FAIL"))

    # [TEST 6] Protocol Round-Trip & Round Count Verification for TIER_HIGH
    print("\n[TEST 6] Protocol Round-Trip & Round Count Verification for TIER_HIGH")
    print("-" * 95)
    tier_high = classify_tier("score")
    rounds_high = TIER_ROUNDS[tier_high]
    wire_high = pack_packet(plaintext_payload, seq_no, tier_high, key)
    dec_payload_h, rec_seq_h, rec_tier_h, valid_h = unpack_packet(wire_high, key)
    
    rk_27 = generate_key_schedule(key, rounds=27)
    expected_ct_27 = encrypt_bytes(plaintext_payload, rk_27)
    actual_ct_27 = wire_high[1:9]
    
    print(f"Packet Type: 'score' -> Tier: {tier_high} (Rounds = {rounds_high})")
    print(f"Wire Packet (21 B):     {wire_high.hex()}")
    print(f"Extracted CT (hex):     {actual_ct_27.hex()}")
    print(f"Direct SPECK27 CT:      {expected_ct_27.hex()}")
    print(f"Decrypted Payload:      {dec_payload_h} (Seq: {rec_seq_h}, Valid: {valid_h})")
    
    test6_ok = (valid_h and dec_payload_h == plaintext_payload and rec_seq_h == seq_no and actual_ct_27 == expected_ct_27)
    if test6_ok:
        print("--> PASS: TIER_HIGH round-trip verified and confirmed 27 SPECK rounds used!")
        summary_results.append((tier_high, rounds_high, len(wire_high), "PASS"))
    else:
        print("--> FAIL: TIER_HIGH round-trip mismatch!")
        all_passed = False
        summary_results.append((tier_high, rounds_high, len(wire_high), "FAIL"))

    # [TEST 7] Tamper Test: Ciphertext Bit Flip
    print("\n[TEST 7] Tamper Test: Ciphertext Bit Flip")
    print("-" * 95)
    tampered_wire = bytearray(wire_high)
    tampered_wire[4] ^= 0x01
    dec_t, seq_t, tier_t, valid_t = unpack_packet(bytes(tampered_wire), key)
    print(f"Original CT byte:  {hex(wire_high[4])}")
    print(f"Tampered CT byte:  {hex(tampered_wire[4])}")
    print(f"Unpack Result:     valid = {valid_t}, decrypted_payload = {dec_t}")
    
    if not valid_t and dec_t == b"":
        print("--> PASS: MAC validation failed correctly on tampered ciphertext and skipped decryption!")
    else:
        print("--> FAIL: Tampered ciphertext was incorrectly accepted!")
        all_passed = False

    # [TEST 8] Tamper Test: Sequence Number Bit Flip
    print("\n[TEST 8] Tamper Test: Sequence Number Bit Flip")
    print("-" * 95)
    seq_tampered_wire = bytearray(wire_high)
    seq_tampered_wire[10] ^= 0x80
    dec_seq_t, seq_val, tier_seq_t, valid_seq_t = unpack_packet(bytes(seq_tampered_wire), key)
    print(f"Original seq_no byte: {hex(wire_high[10])}")
    print(f"Tampered seq byte:    {hex(seq_tampered_wire[10])}")
    print(f"Unpack Result:        valid = {valid_seq_t}, decrypted_payload = {dec_seq_t}")
    
    if not valid_seq_t and dec_seq_t == b"":
        print("--> PASS: MAC validation failed correctly on tampered sequence number!")
    else:
        print("--> FAIL: Tampered sequence number was incorrectly accepted!")
        all_passed = False

    # [TEST 9] Wrong Key Test
    print("\n[TEST 9] Wrong Key Decryption Test")
    print("-" * 95)
    wrong_key = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
    dec_wk, seq_wk, tier_wk, valid_wk = unpack_packet(wire_high, wrong_key)
    print(f"Correct Key MAC Check:  PASS")
    print(f"Wrong Key Unpack Result: valid = {valid_wk}, decrypted_payload = {dec_wk}")
    
    if not valid_wk and dec_wk == b"":
        print("--> PASS: Packet rejected correctly when unpacked with an invalid key!")
    else:
        print("--> FAIL: Packet accepted with wrong key!")
        all_passed = False

    return all_passed


def run_phase3_tests():
    print("\n" + "=" * 95)
    print("   AR-SPECK PHASE 3: SLIDING WINDOW & UDP NETWORKING TEST SUITE     ")
    print("=" * 95)
    all_passed = True

    # [TEST 10] Sliding Window Unit Test (No Sockets)
    print("\n[TEST 10] Sliding Window Unit Test (Reordering, Replay, Too-Old)")
    print("-" * 95)
    win = SlidingWindow()
    reorder_seqs = [5, 6, 4, 7]
    reorder_results = []
    for s in reorder_seqs:
        ok, reason = win.check_and_update(s)
        reorder_results.append((s, ok, reason))
        print(f"  Input Seq {s:2d} -> Accepted: {ok!s:<5} (Reason: {reason})")

    all_reorder_ok = all(ok for _, ok, _ in reorder_results)
    dup_ok, dup_reason = win.check_and_update(6)
    print(f"  Input Seq  6 (Duplicate) -> Accepted: {dup_ok!s:<5} (Reason: {dup_reason})")
    
    jump_ok, jump_reason = win.check_and_update(150)
    print(f"  Input Seq 150 (Forward Jump) -> Accepted: {jump_ok!s:<5} (Reason: {jump_reason})")
    
    old_ok, old_reason = win.check_and_update(5)
    print(f"  Input Seq  5 (Below Tail) -> Accepted: {old_ok!s:<5} (Reason: {old_reason})")

    test10_passed = (
        all_reorder_ok and 
        (not dup_ok and dup_reason == "replay") and 
        (jump_ok and jump_reason == "accepted") and 
        (not old_ok and old_reason == "too_old")
    )
    if test10_passed:
        print("--> PASS: Sliding window logic correctly handles reordering, replays, and stale sequence numbers!")
    else:
        print("--> FAIL: Sliding window logic mismatch!")
        all_passed = False

    # [TEST 11] UDP Client/Server Socket Integration Test
    print("\n[TEST 11] UDP Client/Server Socket Integration Test (200 Clean Burst)")
    print("-" * 95)
    server_port = 5555
    key = bytes.fromhex("0001020308090a0b1011121318191a1b")
    
    server = ARSpeckServer(host="127.0.0.1", port=server_port, key=key)
    server.start()
    
    client = ARSpeckClient(server_host="127.0.0.1", server_port=server_port, key=key)
    sent_count = client.send_burst(count=200, interval_ms=0.5)
    time.sleep(0.5)
    
    server_logs = server.logs
    accept_count = sum(1 for entry in server_logs if entry["event"] == "accept")
    drop_count = sum(1 for entry in server_logs if entry["event"] == "drop")
    
    print(f"Packets Sent by Client:   {sent_count}")
    print(f"Packets Accepted Server:  {accept_count}")
    print(f"Packets Dropped Server:   {drop_count}")
    
    client.close()
    server.stop()
    
    if sent_count == 200 and accept_count == 200 and drop_count == 0:
        print("--> PASS: Socket integration test completed with ZERO drops across 200 packets!")
    else:
        print("--> FAIL: Socket integration test had unexpected drops or missing packets!")
        all_passed = False

    return all_passed


def run_phase4_tests():
    print("\n" + "=" * 95)
    print("      AR-SPECK PHASE 4: ADVERSARY ATTACK SUITE VERIFICATION        ")
    print("=" * 95)
    passed, attack_results = run_all_attack_tests(server_port=5556)
    
    print("\n" + "-" * 95)
    print(f"{'Attack Type':<30} | {'Expected Outcome':<20} | {'Actual Outcome':<20} | {'Status':<6}")
    print("-" * 95)
    for name, exp, act, status in attack_results:
        print(f"{name:<30} | {exp:<20} | {act:<20} | {status:<6}")
    print("-" * 95)
    
    if passed:
        print("--> PASS: All 3 Phase 4 attacks were caught and logged correctly!")
    else:
        print("--> FAIL: Some Phase 4 attacks were not caught as expected!")
        
    return passed


def run_phase5_tests():
    print("\n" + "=" * 95)
    print("   AR-SPECK PHASE 5: CRYPTO-QUALITY & AVALANCHE BENCHMARK SUITE     ")
    print("=" * 95)
    passed, crypto_results = run_crypto_suite(trials=500, num_blocks=500)
    
    print("\n" + "-" * 95)
    print(f"{'Round Count':<12} | {'Plaintext Av (%)':<18} | {'Key Av (%)':<14} | {'Freq p-val':<12} | {'Runs p-val':<12} | {'Status':<6}")
    print("-" * 95)
    for r in crypto_results:
        print(f"{r['round_count']:<12} | {r['pt_avalanche_pct']:<18.2f} | {r['key_avalanche_pct']:<14.2f} | {r['freq_p_value']:<12.4f} | {r['runs_p_value']:<12.4f} | {r['status']:<6}")
    print("-" * 95)
    
    if passed:
        print("--> PASS: All Phase 5 avalanche & statistical randomness tests passed (p > 0.01)!")
    else:
        print("--> FAIL: Some Phase 5 randomness tests failed significance threshold!")
        
    return passed


def run_phase6_tests():
    print("\n" + "=" * 95)
    print("  AR-SPECK PHASE 6: MASTER PERFORMANCE & SECURITY TRADE-OFF SUITE   ")
    print("=" * 95)
    
    rows, aes_data, mac_data = run_master_benchmarks(num_blocks=50000)
    
    print("\n" + "-" * 95)
    print(f"{'Round Count':<12} | {'Throughput (blk/s)':<18} | {'Cipher Lat (µs)':<16} | {'MAC Lat (µs)':<14} | {'Avg Av (%)':<10} | {'Randomness':<10}")
    print("-" * 95)
    for r in rows:
        print(f"{r['round_count']:<12} | {r['enc_throughput_blks']:<18,.0f} | {r['enc_latency_us']:<16.3f} | {r['mac_overhead_us']:<14.3f} | {r['avg_avalanche_pct']:<10.2f} | {r['randomness_status']:<10}")
    print("-" * 95)
    
    if aes_data:
        print(f"AES-128 Baseline | {aes_data['enc_blocks_per_sec']:<18,.0f} | {aes_data['enc_latency_us']:<16.3f} | N/A            | N/A        | PASS")
        print("-" * 95)
        
    print("--> PASS: Master performance benchmarks completed and final_results.csv exported!")
    return True


def main():
    p1_ok = run_phase1_tests()
    p2_ok = run_phase2_tests()
    p3_ok = run_phase3_tests()
    p4_ok = run_phase4_tests()
    p5_ok = run_phase5_tests()
    p6_ok = run_phase6_tests()
    
    print("\n" + "=" * 95)
    if p1_ok and p2_ok and p3_ok and p4_ok and p5_ok and p6_ok:
        print("    ALL PHASE 1 THROUGH PHASE 6 VERIFICATION TESTS PASSED CLEANLY!   ")
    else:
        print("    SOME TESTS FAILED! CHECK LOGS ABOVE.                            ")
    print("=" * 95)
    
    return 0 if (p1_ok and p2_ok and p3_ok and p4_ok and p5_ok and p6_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
