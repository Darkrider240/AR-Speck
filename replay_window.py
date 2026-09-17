"""
replay_window.py - Sliding Window Replay Defense for AR-SPECK

AR-SPECK Project Phase 3: Sliding Window Protocol Defense

UDP is an unreliable protocol that allows packet loss, duplication, and reordering in transit.
A naive "last seen sequence number" check (e.g., seq > last_seq) would incorrectly drop legitimate
out-of-order network packets.

This module implements a 64-bit Sliding Window sequence receiver:
  - Maintains the highest accepted sequence number (max_seq).
  - Uses a 64-bit bitmap integer to track which sequence numbers in the range
    [max_seq - 63, max_seq] have already been received.
  - Allows packets arriving out-of-order within a 64-packet window while strictly dropping duplicates
    (replays) and packets that fall behind the window tail.

Design Invariant:
  Window checks occur AFTER MAC verification (Verify-Then-Decrypt). If a packet fails MAC verification,
  it is dropped immediately and NEVER touches the sliding window state.
"""

WINDOW_SIZE = 64  # 64-bit acceptance window width
MASK_64 = 0xFFFFFFFFFFFFFFFF  # 64-bit bitmask


class SlidingWindow:
    """
    Per-client 64-bit sliding window sequence number validator.
    """
    def __init__(self):
        # Highest valid sequence number accepted so far (-1 = uninitialized state)
        self.max_seq = -1
        # 64-bit bitmap tracking accepted sequence numbers in window range [max_seq - 63, max_seq]
        # Bit 0 (LSB) represents max_seq. Bit offset represents (max_seq - seq_no).
        self.bitmap = 0

    def check_and_update(self, seq_no: int) -> tuple[bool, str]:
        """
        Validates a sequence number against the sliding window and updates window state if accepted.
        
        :param seq_no: 32-bit sequence number extracted from unpacked packet
        :return: Tuple (accepted: bool, status_reason: str)
                 status_reason is one of: 'accepted', 'replay', 'too_old'
        """
        if not (0 <= seq_no <= 0xFFFFFFFF):
            return False, "invalid_seq_range"

        # Case 0: First packet received for this client
        if self.max_seq == -1:
            self.max_seq = seq_no
            self.bitmap = 1  # Set bit 0 for max_seq
            return True, "accepted"

        # Case 1: Newer packet received (seq_no > max_seq)
        if seq_no > self.max_seq:
            shift = seq_no - self.max_seq
            if shift >= WINDOW_SIZE:
                # Sequence jump larger than window width -> reset window completely
                self.bitmap = 1
            else:
                # Shift bitmap left by 'shift' bits and set bit 0 for new max_seq
                self.bitmap = ((self.bitmap << shift) & MASK_64) | 1
            self.max_seq = seq_no
            return True, "accepted"

        # Case 2: Packet inside current window range [max_seq - 63, max_seq]
        elif self.max_seq - (WINDOW_SIZE - 1) <= seq_no <= self.max_seq:
            offset = self.max_seq - seq_no
            # Check if bit at 'offset' is already set
            if (self.bitmap >> offset) & 1:
                # Already received -> REPLAY ATTACK DETECTED
                return False, "replay"
            else:
                # Mark bit at 'offset' as received
                self.bitmap |= (1 << offset)
                return True, "accepted"

        # Case 3: Packet sequence number is too old (below window tail)
        else:
            return False, "too_old"

    def reset(self):
        """Resets window state."""
        self.max_seq = -1
        self.bitmap = 0
