"""
packet_editor.py - Ciphertext Tampering Attack Script for AR-SPECK

AR-SPECK Project Phase 4: Adversary Attack Suite

Attack Description:
  Simulates an active Man-in-the-Middle (MitM) adversary on the network path who intercepts
  a legitimate UDP packet and tampers with the ciphertext payload in transit before forwarding
  it to the server.

Expected Server Defense:
  The server recomputes the HMAC-SHA256 MAC over the received packet (Verify-Then-Decrypt).
  Because the MAC covers the ciphertext, the computed MAC will fail to match the packet's MAC tag.
  The server MUST log a 'bad_mac' event and drop the packet immediately without attempting decryption.
"""

import socket
import sys
import os

# Add parent directory to path so protocol and tiering can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from protocol import pack_packet
from tiering import TIER_HIGH


def run_packet_editor_attack(server_host: str = "127.0.0.1", server_port: int = 5000, 
                             key: bytes = None, seq_no: int = 7001) -> tuple[int, str]:
    """
    Executes the ciphertext tampering attack.
    
    :param server_host: Target UDP server IP
    :param server_port: Target UDP server Port
    :param key: Shared secret key bytes
    :param seq_no: Sequence number to use for attack packet
    :return: Tuple (seq_no, attack_name)
    """
    key = key or bytes.fromhex("0001020308090a0b1011121318191a1b")
    
    # Step 1: Construct a legitimate packed packet
    plaintext = b"SCORE_99"  # 8 bytes
    legit_wire = pack_packet(plaintext, seq_no, TIER_HIGH, key)
    
    # Step 2: Tamper with ciphertext (byte offset 4, inside ciphertext region 1..8)
    mangled_wire = bytearray(legit_wire)
    mangled_wire[4] ^= 0xFF  # Invert all bits of 4th byte in ciphertext
    
    # Step 3: Send mangled packet over raw UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytes(mangled_wire), (server_host, server_port))
    sock.close()
    
    return seq_no, "Packet Editor (Ciphertext Bit Flip)", bytes(mangled_wire)


if __name__ == "__main__":
    seq, name = run_packet_editor_attack()
    print(f"Executed attack '{name}' with seq_no={seq}")
