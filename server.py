"""
server.py - UDP Socket Server with Sliding-Window Replay Protection for AR-SPECK

AR-SPECK Project Phase 3: UDP Server Infrastructure

This module implements the AR-SPECK UDP game server. It processes incoming datagrams
using a strict two-stage security pipeline:
  1. Cryptographic Authentication & Decryption (protocol.unpack_packet):
     Recomputes and verifies HMAC-SHA256 before attempting SPECK decryption. If MAC is invalid,
     the packet is dropped immediately with reason 'bad_mac' without modifying sliding-window state.
  2. Sliding Window Replay Defense (replay_window.SlidingWindow):
     Checks packet sequence numbers against a 64-bit window per client IP:Port address to prevent
     replay attacks while accepting out-of-order UDP deliveries.

Structured Event Logging:
  Every packet processing event is logged as a structured JSON object/dictionary containing:
  {"event": "accept"|"drop", "reason": "ok"|"bad_mac"|"replay"|"too_old", "seq_no": int, "tier": str, "client": str}
  This structured log format is scored against by Phase 4 attack scripts.
"""

import socket
import json
import threading
import time
from protocol import unpack_packet
from replay_window import SlidingWindow


class ARSpeckServer:
    """
    UDP Game Server for AR-SPECK.
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 5000, key: bytes = None):
        self.host = host
        self.port = port
        self.key = key or bytes.fromhex("0001020308090a0b1011121318191a1b")
        self.sock = None
        self.is_running = False
        self.thread = None
        
        # Per-client sliding window states: dict[(ip, port), SlidingWindow]
        self.client_windows = {}
        
        # Event logs list storing structured dictionaries
        self.logs = []
        
        # Lock for thread-safe state and log access
        self.lock = threading.Lock()

    def get_window_for_client(self, client_addr: tuple) -> SlidingWindow:
        """Retrieves or creates a SlidingWindow instance for a client address."""
        if client_addr not in self.client_windows:
            self.client_windows[client_addr] = SlidingWindow()
        return self.client_windows[client_addr]

    def log_event(self, event_type: str, reason: str, seq_no: int, tier: str, client_addr: tuple):
        """Logs a structured packet processing event."""
        client_str = f"{client_addr[0]}:{client_addr[1]}" if client_addr else "unknown"
        log_entry = {
            "event": event_type,     # "accept" or "drop"
            "reason": reason,        # "ok", "bad_mac", "replay", "too_old"
            "seq_no": seq_no,
            "tier": tier,
            "client": client_str,
            "timestamp": time.time()
        }
        with self.lock:
            self.logs.append(log_entry)
        # Printable JSON line for terminal inspection
        # print(json.dumps(log_entry))

    def process_game_state(self, plaintext_block: bytes, seq_no: int, tier: str, client_addr: tuple):
        """
        Stub game-state handler called ONLY when packet passes BOTH MAC and Sliding Window checks.
        """
        # In full game engine, this updates player position/score
        pass

    def handle_datagram(self, wire_bytes: bytes, client_addr: tuple):
        """
        Processes a single incoming UDP datagram through the security pipeline.
        
        Pipeline:
        1. MAC Verification & Decryption (protocol.unpack_packet)
           - If bad MAC: drop immediately with reason 'bad_mac' (DO NOT touch sliding window!).
        2. Replay Window Check (SlidingWindow.check_and_update)
           - If duplicate/out-of-window: drop with reason 'replay' or 'too_old'.
        3. Game State Handoff (process_game_state)
           - Hand off decrypted payload only if both checks pass.
        """
        # Step 1: MAC Verification & Decryption
        plaintext_block, seq_no, tier, valid_mac = unpack_packet(wire_bytes, self.key)
        
        if not valid_mac:
            # MAC check failed -> bad MAC or tampered header/payload
            self.log_event("drop", "bad_mac", seq_no, tier, client_addr)
            return

        # Step 2: Sliding Window Replay Check
        with self.lock:
            window = self.get_window_for_client(client_addr)
            accepted, window_reason = window.check_and_update(seq_no)
            
        if not accepted:
            # Replay or too old
            self.log_event("drop", window_reason, seq_no, tier, client_addr)
            return

        # Step 3: Accept & Hand off to Game Logic
        self.log_event("accept", "ok", seq_no, tier, client_addr)
        self.process_game_state(plaintext_block, seq_no, tier, client_addr)

    def serve_forever(self):
        """Main server socket loop."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.is_running = True
        
        # Set socket timeout so thread can poll self.is_running
        self.sock.settimeout(0.2)
        
        while self.is_running:
            try:
                data, addr = self.sock.recvfrom(2048)
                if data:
                    self.handle_datagram(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    print(f"Server error: {e}")
                break

    def start(self):
        """Starts server in a background daemon thread."""
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()
        # Wait briefly for socket binding
        time.sleep(0.1)

    def stop(self):
        """Stops the server cleanly."""
        self.is_running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=1.0)


if __name__ == "__main__":
    print("Starting AR-SPECK UDP Server on 127.0.0.1:5000...")
    server = ARSpeckServer(host="127.0.0.1", port=5000)
    server.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping server...")
        server.stop()
