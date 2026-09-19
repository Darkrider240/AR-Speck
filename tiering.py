"""
tiering.py - Adaptive Sensitivity Classification Module for AR-SPECK

AR-SPECK Project — Extended with Three Advanced Adaptive Systems:

  [Idea 1] Shannon Entropy-Driven Round Selection:
      Round count T is computed per-block from the Shannon entropy H of the 8-byte
      plaintext. High-entropy blocks (dense/random data) receive more rounds;
      low-entropy blocks (repeated patterns like pings) receive fewer.

  [Idea 2] Threat-Signal Security Automaton (see server.py):
      Server monitors rolling 10-second replay/bad-MAC rates and escalates
      the minimum round floor for all clients when thresholds are crossed.

  [Idea 3] Markov Transition Matrix Predictor:
      A 6x6 empirical Markov transition matrix over packet types predicts the
      most likely next packet type, pre-speculating round count before the
      current packet finishes encrypting.
"""

import math
from collections import Counter

# -----------------------------------------------------------------------------
# Tier Identifiers & Numerical IDs (used in binary wire headers)
# -----------------------------------------------------------------------------
TIER_T8   = "T8_HEARTBEAT"
TIER_T10  = "T10_ENTROPY"    # New: entropy-selected intermediate tier
TIER_LOW  = "LOW"            # T=12
TIER_T16  = "T16_CAMERA"
TIER_T20  = "T20_COMBAT"
TIER_T24  = "T24_TRADE"
TIER_HIGH = "HIGH"           # T=27

# Binary tier IDs encoded in wire format (1 byte)
TIER_BYTE_MAP = {
    TIER_T8:   0x08,
    TIER_T10:  0x0A,   # 10
    TIER_LOW:  0x0C,   # 12
    TIER_T16:  0x10,   # 16
    TIER_T20:  0x14,   # 20
    TIER_T24:  0x18,   # 24
    TIER_HIGH: 0x1B,   # 27
}

# Reverse mapping for unpacking wire bytes to tier string
BYTE_TIER_MAP = {
    0x08: TIER_T8,
    0x0A: TIER_T10,
    0x0C: TIER_LOW,
    0x10: TIER_T16,
    0x14: TIER_T20,
    0x18: TIER_T24,
    0x1B: TIER_HIGH,
}

# -----------------------------------------------------------------------------
# Tier-to-Round-Count Configuration
# -----------------------------------------------------------------------------
TIER_ROUNDS = {
    TIER_T8:   8,
    TIER_T10:  10,
    TIER_LOW:  12,
    TIER_T16:  16,
    TIER_T20:  20,
    TIER_T24:  24,
    TIER_HIGH: 27,
}

# Valid dynamic round counts (used by entropy selector and protocol override)
VALID_ROUNDS = {8, 10, 12, 16, 20, 24, 27}

# Ordered list for nearest-tier resolution
_ROUNDS_ORDERED = sorted(VALID_ROUNDS)

# -----------------------------------------------------------------------------
# Explicit Packet Type Mapping Dictionary
# -----------------------------------------------------------------------------
PACKET_TIER_MAP = {
    # 8 Rounds: Ultra-fast heartbeat & ping streams (single-frame lifetime)
    "ping":         TIER_T8,
    "heartbeat":    TIER_T8,

    # 12 Rounds: Routine high-frequency position & movement streams
    "position":     TIER_LOW,
    "input":        TIER_LOW,
    "movement":     TIER_LOW,

    # 16 Rounds: Camera orientation & view direction updates
    "camera":       TIER_T16,
    "rotation":     TIER_T16,

    # 20 Rounds: Medium sensitivity combat & health events
    "combat":       TIER_T20,
    "health":       TIER_T20,

    # 24 Rounds: High sensitivity trade drafts & state sync
    "trade":        TIER_T24,
    "state_sync":   TIER_T24,

    # 27 Rounds: Maximum security persistent mutations
    "score":        TIER_HIGH,
    "inventory":    TIER_HIGH,
    "hit_confirm":  TIER_HIGH,
    "player_spawn": TIER_HIGH,
    "chat_cmd":     TIER_HIGH,
}


# -----------------------------------------------------------------------------
# Existing Tier Classification Functions (unchanged)
# -----------------------------------------------------------------------------
def classify_tier(packet_type: str) -> str:
    """Classifies a game packet type string into a sensitivity tier."""
    normalized_type = packet_type.strip().lower()
    if normalized_type not in PACKET_TIER_MAP:
        raise ValueError(
            f"Unrecognized packet_type '{packet_type}'. "
            f"Allowed types: {list(PACKET_TIER_MAP.keys())}"
        )
    return PACKET_TIER_MAP[normalized_type]


def classify_tier_adaptive(packet_type: str, stream_freq_hz: float = None) -> tuple:
    """
    Dynamically classifies a packet into a sensitivity tier and round count T
    based on measured stream frequency (Hz). Falls back to type lookup if no Hz given.
    Returns: Tuple of (tier_name_str, round_count_int)
    """
    if stream_freq_hz is not None and stream_freq_hz > 0:
        if stream_freq_hz >= 100.0:
            tier = TIER_T8
        elif stream_freq_hz >= 60.0:
            tier = TIER_LOW
        elif stream_freq_hz >= 30.0:
            tier = TIER_T16
        elif stream_freq_hz >= 10.0:
            tier = TIER_T20
        else:
            tier = TIER_HIGH
        return tier, TIER_ROUNDS[tier]

    tier = classify_tier(packet_type)
    return tier, TIER_ROUNDS[tier]


def classify_tier_from_rounds(rounds: int) -> str:
    """
    Maps a raw round count back to the nearest valid tier string.
    Used when entropy overrides produce a non-standard T value that
    still needs a valid wire tier byte.
    """
    # Find the nearest tier by round count
    nearest = min(VALID_ROUNDS, key=lambda r: abs(r - rounds))
    for tier, r in TIER_ROUNDS.items():
        if r == nearest:
            return tier
    return TIER_HIGH  # safe fallback


# =============================================================================
# IDEA 1 — Shannon Entropy-Driven Round Selection
# =============================================================================

def compute_block_entropy(block: bytes) -> float:
    """
    Computes the Shannon entropy H of an 8-byte plaintext block.

    Formula:
        H = -sum(p_i * log2(p_i)) for each distinct byte value i with count > 0
        where p_i = count(i) / len(block)

    For an 8-byte block, H_max = log2(8) = 3.0 bits (all 8 bytes distinct).
    H_min = 0.0 bits (all 8 bytes identical).

    :param block: Exactly 8 bytes of plaintext
    :return: Shannon entropy in bits, clamped to [0.0, 3.0]
    """
    if len(block) == 0:
        return 0.0

    counts = Counter(block)
    n = len(block)
    H = 0.0
    for count in counts.values():
        if count > 0:
            p = count / n
            H -= p * math.log2(p)

    # Clamp to [0.0, 3.0] — theoretical max for 8 distinct bytes
    return min(max(H, 0.0), 3.0)


def entropy_to_rounds(entropy: float) -> int:
    """
    Maps Shannon entropy H (bits) of an 8-byte block to an adaptive round count T.

    Rationale:
      - Low entropy (repeated/structured data like pings): attacker has little
        information to gain — fewer rounds sufficient.
      - High entropy (dense/random data like session tokens): more rounds needed
        to ensure full diffusion and resist differential distinguishers.

    Mapping:
        H < 0.5        →  T = 8   (near-constant, ping/heartbeat patterns)
        0.5 <= H < 1.0 →  T = 10  (slight variation, structured position data)
        1.0 <= H < 1.5 →  T = 12  (moderate structure, routine movement)
        1.5 <= H < 2.0 →  T = 16  (higher variation, camera/orientation)
        2.0 <= H < 2.5 →  T = 20  (significant entropy, combat events)
        2.5 <= H < 2.8 →  T = 24  (high entropy, trade/state sync)
        H >= 2.8       →  T = 27  (near-maximum entropy, auth tokens/scores)

    :param entropy: Shannon entropy value in [0.0, 3.0]
    :return: Round count T in VALID_ROUNDS
    """
    if entropy < 0.5:
        return 8
    elif entropy < 1.0:
        return 10
    elif entropy < 1.5:
        return 12
    elif entropy < 2.0:
        return 16
    elif entropy < 2.5:
        return 20
    elif entropy < 2.8:
        return 24
    else:
        return 27


# =============================================================================
# IDEA 3 — Markov Transition Matrix for Next-Packet Prediction
# =============================================================================

# Packet type index ordering (must match PACKET_SEQUENCE_TYPES in web_server.py)
PACKET_TYPE_INDEX = {
    "ping":     0,
    "position": 1,
    "camera":   2,
    "combat":   3,
    "trade":    4,
    "score":    5,
}
INDEX_PACKET_TYPE = {v: k for k, v in PACKET_TYPE_INDEX.items()}

# 6x6 Empirical Markov Transition Matrix
# Rows = current packet type, Columns = next packet type probability
# Derived from realistic game session traffic patterns:
#   - Position loops at high frequency (~55% self-transition)
#   - Combat leads frequently to score updates (~25%)
#   - Trade is rare but leads back to position after completion
#   - Score/auth resets to normal gameplay (position)
#   Row sums are exactly 1.0
MARKOV_TRANSITION = [
    # ping   pos    cam    com    trade  score
    [0.10,  0.60,  0.15,  0.10,  0.03,  0.02],  # from ping
    [0.05,  0.55,  0.20,  0.12,  0.05,  0.03],  # from position
    [0.05,  0.30,  0.35,  0.20,  0.05,  0.05],  # from camera
    [0.03,  0.20,  0.10,  0.35,  0.07,  0.25],  # from combat
    [0.03,  0.20,  0.10,  0.15,  0.30,  0.22],  # from trade
    [0.10,  0.40,  0.15,  0.15,  0.08,  0.12],  # from score
]


def markov_predict_next(current_type: str) -> tuple:
    """
    Predicts the most likely next packet type given the current packet type,
    using the empirical Markov transition matrix.

    :param current_type: Current packet type string (e.g. "position")
    :return: Tuple (predicted_next_type: str, probability: float)
             e.g. ("position", 0.55)
    """
    current_type = current_type.strip().lower()
    if current_type not in PACKET_TYPE_INDEX:
        return ("position", 0.55)  # safe default

    row_idx = PACKET_TYPE_INDEX[current_type]
    row = MARKOV_TRANSITION[row_idx]

    # Find the column with maximum probability
    max_prob = max(row)
    max_col = row.index(max_prob)
    predicted_type = INDEX_PACKET_TYPE[max_col]

    return (predicted_type, round(max_prob, 4))


def markov_predict_rounds(current_type: str) -> int:
    """
    Pre-speculates the round count T for the next packet based on
    the Markov-predicted next packet type.

    This enables the key schedule for round T_next to be precomputed
    speculatively while the current packet is still being encrypted —
    reducing effective latency of the next pack_packet call.

    :param current_type: Current packet type string
    :return: Pre-fetched round count T for predicted next packet
    """
    predicted_type, _ = markov_predict_next(current_type)
    predicted_tier = classify_tier(predicted_type)
    return TIER_ROUNDS[predicted_tier]
