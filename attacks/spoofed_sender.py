"""
spoofed_sender.py - Key Spoofing / Unauthorized Sender Attack Script for AR-SPECK

AR-SPECK Project Phase 4: Adversary Attack Suite

Attack Description:
  Simulates an unauthorized third-party attacker who attempts to forge UDP game packets
  without possessing the valid shared secret key. The attacker packs a packet using a random
  or guessed key and sends it to the server.

Expected Server Defense:
  The server recomputes the HMAC-SHA256 MAC using its own secret key. Because the attacker
  used a wrong key, the MAC check fails immediately. The server logs a 'bad_mac' event and
  drops the packet prior to invoking SPECK decryption or touching the sliding window.
"""

import socket
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from protocol import pack_packet
from tiering import TIER_HIGH


def run_spoofed_sender_attack(server_host: str = "127.0.0.1", server_port: int = 5000, 
                               seq_no: int = 7003) -> tuple[int, str]:
    """
    Executes the key spoofing / unauthorized sender attack.
    
    :param server_host: Target UDP server IP
    :param server_port: Target UDP server Port
    :param seq_no: Sequence number for attack packet
    :return: Tuple (seq_no, attack_name)
    """
    # Attacker uses an invalid/spoofed key (16 bytes)
    spoofed_key = bytes.fromhex("DEADBEEFDEADBEEFDEADBEEFDEADBEEF")
    plaintext = b"HACK_100"
    
    # Pack packet with spoofed key
    spoofed_wire = pack_packet(plaintext, seq_no, TIER_HIGH, spoofed_key)
    
    # Send packet over raw UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(spoofed_wire, (server_host, server_port))
    sock.close()
    
    return seq_no, "Spoofed Sender (Invalid Key)"


if __name__ == "__main__":
    seq, name = run_spoofed_sender_attack()
    print(f"Executed attack '{name}' with seq_no={seq}")
