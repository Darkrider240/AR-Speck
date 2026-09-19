"""
client.py - UDP Game Client for AR-SPECK (Extended with Adaptive Engines)

Extended for three adaptive systems:

  [Idea 1] Entropy-Driven Round Selection:
      Each 8-byte payload block's Shannon entropy H is computed before encryption.
      entropy_to_rounds(H) determines T, overriding the static tier lookup.
      The client stores last_entropy and last_entropy_rounds for telemetry.

  [Idea 3] Markov Next-Packet Predictor:
      After every sent packet, markov_predict_next(current_type) pre-speculates
      the most likely next packet type and pre-fetches its round count. The key
      schedule for round T_next is available before send_game_packet is called
      again, simulating speculative pipelining to reduce effective encryption latency.
"""

import socket
import time
import random
from protocol import pack_packet
from tiering import (
    classify_tier, TIER_LOW, TIER_HIGH,
    compute_block_entropy, entropy_to_rounds,
    markov_predict_next, markov_predict_rounds
)


class ARSpeckClient:
    """
    UDP Game Client for AR-SPECK with Entropy + Markov Adaptive Engines.
    """
    def __init__(self, server_host: str = "127.0.0.1", server_port: int = 5000,
                 key: bytes = None):
        self.server_host = server_host
        self.server_port = server_port
        self.key = key or bytes.fromhex("0001020308090a0b1011121318191a1b")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Monotonic sequence counter starting at 1
        self.seq_no = 1

        # ── Idea 1: Entropy state ──────────────────────────────────────────
        self.last_entropy = 0.0          # Shannon entropy of last block (bits)
        self.last_entropy_rounds = 8     # T chosen by entropy for last packet

        # ── Idea 3: Markov speculative state ──────────────────────────────
        self.last_packet_type = None                    # most recent pkt type sent
        self.markov_next_prediction = None              # (type_str, probability)
        self.markov_prefetch_rounds = None              # pre-fetched T for next pkt

        # Pre-warm Markov prefetch assuming first packet is "position"
        self._update_markov_state("position")

    def _update_markov_state(self, sent_type: str):
        """Update Markov speculation state after a packet is sent."""
        self.last_packet_type = sent_type
        self.markov_next_prediction = markov_predict_next(sent_type)
        self.markov_prefetch_rounds = markov_predict_rounds(sent_type)

    def send_game_packet(self, packet_type: str = "position",
                         payload: bytes = None) -> bytes:
        """
        Packs and transmits a single game packet to the server over UDP.

        Adaptive Pipeline:
        1. Build 8-byte payload.
        2. [Idea 1] Compute Shannon entropy H of payload bytes.
        3. [Idea 1] Map H → entropy-driven round count T via entropy_to_rounds().
        4. Pack wire packet with entropy-override T (bypasses static tier table).
        5. Transmit over UDP.
        6. [Idea 3] Update Markov state: predict next type + prefetch T_next.

        :param packet_type: String type ('position', 'score', etc.)
        :param payload: 8-byte payload (auto-generated if None)
        :return: Transmitted 21-byte wire bytes
        """
        tier = classify_tier(packet_type)

        if payload is None:
            payload = f"PT_{self.seq_no:05d}".encode("utf-8")[:8]
        elif len(payload) != 8:
            payload = payload.ljust(8, b" ")[:8]

        # ── Idea 1: Entropy-driven round selection ─────────────────────────
        H = compute_block_entropy(payload)
        entropy_T = entropy_to_rounds(H)

        # Store for telemetry exposure via web_server
        self.last_entropy = round(H, 4)
        self.last_entropy_rounds = entropy_T

        # Pack with entropy T override — protocol maps T → nearest valid tier byte
        wire_packet = pack_packet(payload, self.seq_no, tier, self.key,
                                  rounds=entropy_T)
        self.sock.sendto(wire_packet, (self.server_host, self.server_port))

        self.seq_no += 1

        # ── Idea 3: Markov speculative update ─────────────────────────────
        self._update_markov_state(packet_type)

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
            pkt_type = "score" if i % 10 == 0 else "position"
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
