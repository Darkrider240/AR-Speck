"""
server.py - UDP Socket Server with Sliding-Window Replay Protection for AR-SPECK

Extended for Idea 2 — Threat-Signal Security Level Automaton:

  The server monitors a rolling 10-second window of threat events (bad MACs and
  replays). When thresholds are crossed, it escalates a global security level:

    NOMINAL  → Default operation. No escalation.
    ELEVATED → >= 5 replay events in 10s. All client round floors raised +4.
    CRITICAL → >= 3 bad MAC events in 10s. All clients forced to T=27.

  Escalation lasts 30 seconds after the last threshold crossing, then decays
  back to NOMINAL automatically. The threat state is exposed via `threat_stats`
  for the web dashboard and `/api/status` endpoint.

  This is analogous to TCP's congestion window control but for cryptographic
  security depth — a formal "Security Level Automaton" (SLA) model.
"""

import socket
import json
import threading
import time
from protocol import unpack_packet
from replay_window import SlidingWindow


class ARSpeckServer:
    """
    UDP Game Server for AR-SPECK with Threat-Signal Security Automaton (Idea 2).
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

        # ── Idea 2: Threat-Signal Security Level Automaton ─────────────────
        self.threat_level = "NOMINAL"       # "NOMINAL", "ELEVATED", "CRITICAL"
        self.threat_escalation_end = 0.0    # Unix timestamp when escalation expires
        self.ESCALATION_DURATION = 30.0     # seconds of escalated protection

        # Rolling 10-second event window: list of (timestamp, event_reason) tuples
        self._threat_window_events = []

    # ── Existing Methods ───────────────────────────────────────────────────────

    def get_window_for_client(self, client_addr: tuple) -> SlidingWindow:
        """Retrieves or creates a SlidingWindow instance for a client address."""
        if client_addr not in self.client_windows:
            self.client_windows[client_addr] = SlidingWindow()
        return self.client_windows[client_addr]

    def log_event(self, event_type: str, reason: str, seq_no: int,
                  tier: str, client_addr: tuple):
        """Logs a structured packet processing event."""
        client_str = f"{client_addr[0]}:{client_addr[1]}" if client_addr else "unknown"
        log_entry = {
            "event": event_type,
            "reason": reason,
            "seq_no": seq_no,
            "tier": tier,
            "client": client_str,
            "timestamp": time.time()
        }
        with self.lock:
            self.logs.append(log_entry)

        # ── Idea 2: Feed threat events into rolling window ─────────────────
        if reason in ("bad_mac", "replay", "too_old"):
            self._record_threat_event(reason)

    def process_game_state(self, plaintext_block: bytes, seq_no: int,
                           tier: str, client_addr: tuple):
        """Stub game-state handler for accepted packets."""
        pass

    def handle_datagram(self, wire_bytes: bytes, client_addr: tuple):
        """
        Processes a single incoming UDP datagram through the security pipeline.

        Pipeline:
        1. MAC Verification & Decryption (VERIFY-THEN-DECRYPT).
        2. Replay Window Check per client.
        3. Game State Handoff on full acceptance.
        """
        plaintext_block, seq_no, tier, valid_mac = unpack_packet(wire_bytes, self.key)

        if not valid_mac:
            self.log_event("drop", "bad_mac", seq_no, tier, client_addr)
            return

        with self.lock:
            window = self.get_window_for_client(client_addr)
            accepted, window_reason = window.check_and_update(seq_no)

        if not accepted:
            self.log_event("drop", window_reason, seq_no, tier, client_addr)
            return

        self.log_event("accept", "ok", seq_no, tier, client_addr)
        self.process_game_state(plaintext_block, seq_no, tier, client_addr)

    def serve_forever(self):
        """Main server socket loop."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.is_running = True
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

    # ── Idea 2: Threat Automaton Methods ──────────────────────────────────────

    def _record_threat_event(self, event_reason: str):
        """
        Records a threat event into the rolling 10-second window and
        re-evaluates the security level automaton state.

        Transition rules:
          bad_mac count >= 3 in 10s  →  CRITICAL  (T=27 forced for all)
          replay count  >= 5 in 10s  →  ELEVATED  (T += 4 for all)
          window empty / expired     →  NOMINAL   (no escalation)
        """
        now = time.time()

        # Thread-safe update of threat window
        with self.lock:
            self._threat_window_events.append((now, event_reason))
            # Prune events older than 10 seconds
            cutoff = now - 10.0
            self._threat_window_events = [
                (t, r) for (t, r) in self._threat_window_events if t >= cutoff
            ]

            # Count threat types in rolling window
            bad_mac_count = sum(
                1 for (_, r) in self._threat_window_events if r == "bad_mac"
            )
            replay_count = sum(
                1 for (_, r) in self._threat_window_events
                if r in ("replay", "too_old")
            )

            # State machine transitions
            if bad_mac_count >= 3:
                self.threat_level = "CRITICAL"
                self.threat_escalation_end = now + self.ESCALATION_DURATION
            elif replay_count >= 5:
                if self.threat_level != "CRITICAL":  # don't downgrade from CRITICAL
                    self.threat_level = "ELEVATED"
                self.threat_escalation_end = now + self.ESCALATION_DURATION

    def get_threat_level(self) -> str:
        """
        Returns the current threat level, decaying to NOMINAL if escalation
        window has expired.
        """
        if time.time() > self.threat_escalation_end:
            self.threat_level = "NOMINAL"
        return self.threat_level

    def get_escalated_rounds(self, base_rounds: int) -> int:
        """
        Returns the threat-escalated round count for a given base T.
        Called by clients or the server to enforce the global security floor.

          CRITICAL  → T = 27 (maximum, always)
          ELEVATED  → T = min(base_rounds + 4, 27)
          NOMINAL   → T = base_rounds (unchanged)

        :param base_rounds: The entropy-computed or tier-baseline round count
        :return: Escalated round count T
        """
        level = self.get_threat_level()
        if level == "CRITICAL":
            return 27
        elif level == "ELEVATED":
            return min(base_rounds + 4, 27)
        return base_rounds

    @property
    def threat_stats(self) -> dict:
        """
        Returns a snapshot of the current threat automaton state for telemetry.
        Exposed via /api/status → dashboard threat panel.
        """
        now = time.time()
        level = self.get_threat_level()
        escalation_active = now < self.threat_escalation_end

        with self.lock:
            cutoff = now - 10.0
            window = [(t, r) for (t, r) in self._threat_window_events if t >= cutoff]

        bad_mac_count = sum(1 for (_, r) in window if r == "bad_mac")
        replay_count = sum(
            1 for (_, r) in window if r in ("replay", "too_old")
        )

        return {
            "threat_level": level,
            "escalation_active": escalation_active,
            "escalation_expires_in": round(
                max(0.0, self.threat_escalation_end - now), 1
            ),
            "window_replay_count": replay_count,
            "window_bad_mac_count": bad_mac_count,
        }


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
