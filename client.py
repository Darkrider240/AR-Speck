"""
client.py - UDP Game Client for AR-SPECK

AR-SPECK Project Phase 3: UDP Client Infrastructure

This module implements the AR-SPECK UDP game client. It simulates real-time game traffic
by sending game-state packets over UDP at configurable tick rates.

Traffic Tiering Ratio:
  - ~90% Low-Tier Traffic (routine movement/position streams: packet_type = 'position').
  - ~10% High-Tier Traffic (critical state mutations: packet_type = 'score' or 'inventory').

Key Operations:
  - Increments a local sequence number per packet.
  - Classifies packet sensitivity via tiering.classify_tier().
  - Packs wire payload (21 bytes) via protocol.pack_packet().
  - Transmits via fire-and-forget UDP socket to server.
"""

import socket
import time
import random
from protocol import pack_packet
from tiering import classify_tier, TIER_LOW, TIER_HIGH


class ARSpeckClient:
    """
    UDP Game Client for AR-SPECK.
    """
    def __init__(self, server_host: str = "127.0.0.1", server_port: int = 5000, key: bytes = None):
        self.server_host = server_host
        self.server_port = server_port
        self.key = key or bytes.fromhex("0001020308090a0b1011121318191a1b")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Monotonic sequence counter starting at 1
        self.seq_no = 1

    def send_game_packet(self, packet_type: str = "position", payload: bytes = None) -> bytes:
        """
        Packs and transmits a single game packet to the server over UDP.
        
        :param packet_type: String type ('position', 'score', etc.)
        :param payload: 8-byte payload (generated if None)
        :return: Transmitted 21-byte wire bytes
        """
        tier = classify_tier(packet_type)
        if payload is None:
            # Generate sample 8-byte payload
            payload = f"PT_{self.seq_no:05d}".encode("utf-8")[:8]
        elif len(payload) != 8:
            payload = payload.ljust(8, b" ")[:8]
            
        wire_packet = pack_packet(payload, self.seq_no, tier, self.key)
        self.sock.sendto(wire_packet, (self.server_host, self.server_port))
        
        # Increment sequence counter
        self.seq_no += 1
        return wire_packet

    def send_burst(self, count: int = 200, interval_ms: float = 0.0) -> int:
        """
        Sends a burst of 'count' game packets with 9:1 Low:High sensitivity ratio.
        
        :param count: Total number of packets to send
        :param interval_ms: Delay between packets in milliseconds
        :return: Number of packets sent
        """
        sent_count = 0
        for i in range(count):
            # 9:1 Low:High tier ratio
            if i % 10 == 0:
                pkt_type = "score"  # High tier (27 rounds)
            else:
                pkt_type = "position"  # Low tier (12 rounds)
                
            self.send_game_packet(packet_type=pkt_type)
            sent_count += 1
            
            if interval_ms > 0:
                time.sleep(interval_ms / 1000.0)
                
        return sent_count

    def close(self):
        """Closes the UDP socket."""
        if self.sock:
            self.sock.close()


if __name__ == "__main__":
    print("Sending 200 clean test packets to 127.0.0.1:5000...")
    client = ARSpeckClient(server_host="127.0.0.1", server_port=5000)
    count = client.send_burst(count=200, interval_ms=1.0)
    print(f"Done! Sent {count} packets.")
    client.close()
