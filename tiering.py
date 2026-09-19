"""
tiering.py - Sensitivity Classification Module for AR-SPECK

AR-SPECK Project Phase 2: Sensitivity-Tiered Encryption

This module defines the sensitivity tiers and deterministic packet classification logic.
Instead of applying uniform cryptographic strength to all packets, AR-SPECK categorizes
packet types into sensitivity tiers:
  - TIER_LOW: Routine high-frequency traffic (movement, position updates).
              Uses reduced SPECK rounds (12 rounds) to minimize UDP processing latency.
  - TIER_HIGH: Critical low-frequency traffic (score, inventory, hit confirmations).
               Uses standard full-strength SPECK rounds (27 rounds) for maximum security.

Design Invariant:
  Round count tuning is configured via the TIER_ROUNDS dictionary constant so it can be
  dynamically adjusted during Phase 5 benchmarking.
"""

# -----------------------------------------------------------------------------
# Tier Identifiers & Numerical IDs (used in binary wire headers)
# -----------------------------------------------------------------------------
TIER_T8  = "T8_HEARTBEAT"
TIER_LOW = "LOW"            # T=12
TIER_T16 = "T16_CAMERA"
TIER_T20 = "T20_COMBAT"
TIER_T24 = "T24_TRADE"
TIER_HIGH = "HIGH"          # T=27

# Binary tier IDs encoded in wire format (1 byte)
TIER_BYTE_MAP = {
    TIER_T8:   0x08,
    TIER_LOW:  0x0C,  # 12
    TIER_T16:  0x10,  # 16
    TIER_T20:  0x14,  # 20
    TIER_T24:  0x18,  # 24
    TIER_HIGH: 0x1B,  # 27
}

# Reverse mapping for unpacking wire bytes to tier string
BYTE_TIER_MAP = {
    0x08: TIER_T8,
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
    TIER_LOW:  12,
    TIER_T16:  16,
    TIER_T20:  20,
    TIER_T24:  24,
    TIER_HIGH: 27,
}

# -----------------------------------------------------------------------------
# Explicit Packet Type Mapping Dictionary
# -----------------------------------------------------------------------------
PACKET_TIER_MAP = {
    # 8 Rounds: Ultra-fast heartbeat & ping streams (single-frame lifetime)
    "ping": TIER_T8,
    "heartbeat": TIER_T8,
    
    # 12 Rounds: Routine high-frequency position & movement streams
    "position": TIER_LOW,
    "input": TIER_LOW,
    "movement": TIER_LOW,
    
    # 16 Rounds: Camera orientation & view direction updates
    "camera": TIER_T16,
    "rotation": TIER_T16,
    
    # 20 Rounds: Medium sensitivity combat & health events
    "combat": TIER_T20,
    "health": TIER_T20,
    
    # 24 Rounds: High sensitivity trade drafts & state sync
    "trade": TIER_T24,
    "state_sync": TIER_T24,
    
    # 27 Rounds: Maximum security persistent mutations (Score, Inventory, Auth)
    "score": TIER_HIGH,
    "inventory": TIER_HIGH,
    "hit_confirm": TIER_HIGH,
    "player_spawn": TIER_HIGH,
    "chat_cmd": TIER_HIGH,
}


def classify_tier(packet_type: str) -> str:
    """
    Classifies a game packet type string into a sensitivity tier.
    """
    normalized_type = packet_type.strip().lower()
    if normalized_type not in PACKET_TIER_MAP:
        raise ValueError(
            f"Unrecognized packet_type '{packet_type}'. "
            f"Allowed types: {list(PACKET_TIER_MAP.keys())}"
        )
    return PACKET_TIER_MAP[normalized_type]


def classify_tier_adaptive(packet_type: str, stream_freq_hz: float = None) -> tuple[str, int]:
    """
    Dynamically classifies a packet into a sensitivity tier and round count T.
    
    Adaptive Rounding (AR) Criterion:
    If stream_freq_hz is provided (measured real-time transmission frequency in Hz),
    the round count T is dynamically adapted to meet the packet frequency budget:
    
      - stream_freq_hz >= 100 Hz (e.g. 120Hz high-tick position): TIER_T8  (T = 8 rounds, ~0.38us)
      - 60 Hz <= stream_freq_hz < 100 Hz (routine movement stream): TIER_LOW (T = 12 rounds, ~0.48us)
      - 30 Hz <= stream_freq_hz < 60 Hz (camera orientation):      TIER_T16 (T = 16 rounds, ~0.58us)
      - 10 Hz <= stream_freq_hz < 30 Hz (combat events):           TIER_T20 (T = 20 rounds, ~0.69us)
      - < 10 Hz or event-driven (trade, inventory, score):          TIER_HIGH (T = 27 rounds, ~0.88us)
      
    If stream_freq_hz is None, falls back to payload type classification.
    
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

