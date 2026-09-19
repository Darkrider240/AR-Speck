"""
replay.py - Packet Replay Attack Script for AR-SPECK

AR-SPECK Project Phase 4: Adversary Attack Suite

Attack Description:
  Simulates a passive network eavesdropper who captures a valid encrypted UDP packet transmitted
  by a legitimate client, and later re-transmits the exact raw wire bytes to the server in an attempt
  to duplicate a game action (e.g., repeating a score increment or item pickup).

Expected Server Defense:
  - Packet 1: Passes MAC check and Sliding Window check -> ACCEPTED ('ok').
  - Packet 2 (Replay): Passes MAC check (bytes are intact), BUT fails the 64-bit Sliding Window check
    because sequence number is marked as already received -> DROPPED with reason 'replay'.
"""

import socket
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from protocol import pack_packet
from tiering import TIER_HIGH


def run_replay_attack(server_host: str = "127.0.0.1", server_port: int = 5000, 
                       key: bytes = None, seq_no: int = 7002) -> tuple[int, str]:
    """
    Executes the packet replay attack.
    
    :param server_host: Target UDP server IP
    :param server_port: Target UDP server Port
    :param key: Shared secret key bytes
    :param seq_no: Sequence number for packet
    :return: Tuple (seq_no, attack_name)
    """
    key = key or bytes.fromhex("0001020308090a0b1011121318191a1b")
    
    # Step 1: Construct a valid packed packet
    plaintext = b"ITEM_999"
    valid_wire = pack_packet(plaintext, seq_no, TIER_HIGH, key)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Step 2: Send legitimate packet 1
    sock.sendto(valid_wire, (server_host, server_port))
    
    # Step 3: Wait briefly to simulate wire delay before replay
    time.sleep(0.05)
    
    # Step 4: Re-send exact same raw wire bytes (Replay)
    sock.sendto(valid_wire, (server_host, server_port))
    sock.close()
    
    return seq_no, "Packet Replay", valid_wire


if __name__ == "__main__":
    seq, name = run_replay_attack()
    print(f"Executed attack '{name}' with seq_no={seq}")
