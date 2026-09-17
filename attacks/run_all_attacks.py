"""
run_all_attacks.py - Master Attack Orchestrator & Viva Summary Generator

AR-SPECK Project Phase 4: Adversary Attack Suite Runner

Orchestrates the three Phase 4 attack scenarios against a live ARSpeckServer instance,
inspects structured drop logs, and formats a viva-ready summary table.
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server import ARSpeckServer
from attacks.packet_editor import run_packet_editor_attack
from attacks.replay import run_replay_attack
from attacks.spoofed_sender import run_spoofed_sender_attack


def run_all_attack_tests(server_port: int = 5556) -> tuple[bool, list]:
    """
    Runs all 3 Phase 4 attack scenarios against a live UDP server and verifies outcomes.
    
    :param server_port: Dedicated UDP port for attack testing
    :return: Tuple (all_passed: bool, results_table: list[tuple])
    """
    key = bytes.fromhex("0001020308090a0b1011121318191a1b")
    
    # 1. Start server instance
    server = ARSpeckServer(host="127.0.0.1", port=server_port, key=key)
    server.start()
    
    results = []
    all_passed = True
    
    try:
        # ---------------------------------------------------------------------
        # Attack 1: Packet Editor (Ciphertext Bit Flip)
        # ---------------------------------------------------------------------
        seq1, name1 = run_packet_editor_attack(server_port=server_port, key=key, seq_no=7001)
        time.sleep(0.1)
        
        # Check server logs for seq 7001
        log1 = [e for e in server.logs if e["seq_no"] == seq1]
        act1 = log1[0]["reason"] if log1 else "no_log"
        exp1 = "bad_mac"
        pass1 = (act1 == exp1)
        results.append((name1, exp1, act1, "PASS" if pass1 else "FAIL"))
        if not pass1:
            all_passed = False

        # ---------------------------------------------------------------------
        # Attack 2: Packet Replay Attack
        # ---------------------------------------------------------------------
        seq2, name2 = run_replay_attack(server_port=server_port, key=key, seq_no=7002)
        time.sleep(0.1)
        
        # Check server logs for seq 7002 (should have 2 log entries: 1 accept, 1 replay drop)
        logs2 = [e for e in server.logs if e["seq_no"] == seq2]
        if len(logs2) >= 2:
            act2_first = logs2[0]["reason"]  # Should be "ok"
            act2_second = logs2[1]["reason"] # Should be "replay"
            act2 = f"1st:{act2_first}, 2nd:{act2_second}"
            exp2 = "1st:ok, 2nd:replay"
            pass2 = (act2_first == "ok" and act2_second == "replay")
        else:
            act2 = "incomplete_logs"
            exp2 = "1st:ok, 2nd:replay"
            pass2 = False
            
        results.append((name2, exp2, act2, "PASS" if pass2 else "FAIL"))
        if not pass2:
            all_passed = False

        # ---------------------------------------------------------------------
        # Attack 3: Spoofed Sender (Invalid Key)
        # ---------------------------------------------------------------------
        seq3, name3 = run_spoofed_sender_attack(server_port=server_port, seq_no=7003)
        time.sleep(0.1)
        
        log3 = [e for e in server.logs if e["seq_no"] == seq3]
        act3 = log3[0]["reason"] if log3 else "no_log"
        exp3 = "bad_mac"
        pass3 = (act3 == exp3)
        results.append((name3, exp3, act3, "PASS" if pass3 else "FAIL"))
        if not pass3:
            all_passed = False

    finally:
        server.stop()
        
    return all_passed, results


def main():
    print("=" * 80)
    print("        AR-SPECK PHASE 4: ADVERSARY ATTACK SUITE & VIVA SUMMARY        ")
    print("=" * 80)
    
    passed, results = run_all_attack_tests(server_port=5556)
    
    print("\n" + "-" * 80)
    print(f"{'Attack Type':<30} | {'Expected Outcome':<20} | {'Actual Outcome':<20} | {'Status':<6}")
    print("-" * 80)
    for name, exp, act, status in results:
        print(f"{name:<30} | {exp:<20} | {act:<20} | {status:<6}")
    print("-" * 80)
    
    print("\n" + "=" * 80)
    if passed:
        print("    ALL PHASE 4 ATTACKS WERE SUCCESSFULLY DETECTED AND DEFENDED!    ")
    else:
        print("    SOME ATTACKS SUCCEEDED UNEXPECTEDLY! CHECK LOGS.               ")
    print("=" * 80)
    
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
