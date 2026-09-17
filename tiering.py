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
TIER_LOW = "LOW"
TIER_HIGH = "HIGH"

# Binary tier IDs encoded in wire format (1 byte)
TIER_BYTE_MAP = {
    TIER_LOW: 0x01,
    TIER_HIGH: 0x02,
}

# Reverse mapping for unpacking wire bytes to tier string
BYTE_TIER_MAP = {
    0x01: TIER_LOW,
    0x02: TIER_HIGH,
}

# -----------------------------------------------------------------------------
# Tier-to-Round-Count Configuration (Tunable for Phase 5 Benchmarking)
# -----------------------------------------------------------------------------
# Standard SPECK64/128 uses 27 rounds.
# Low tier reduces round count to 12 to save CPU cycles on routine movement packets.
TIER_ROUNDS = {
    TIER_LOW: 12,
    TIER_HIGH: 27,
}

# -----------------------------------------------------------------------------
# Explicit Packet Type Mapping Dictionary (Deterministic Rule-Based)
# -----------------------------------------------------------------------------
# Explicitly maps game-state packet type strings to their assigned sensitivity tier.
# Avoids ML/heuristics for predictable, low-overhead execution.
PACKET_TIER_MAP = {
    # Low Sensitivity: Routine position and input streams
    "position": TIER_LOW,
    "input": TIER_LOW,
    "movement": TIER_LOW,
    "ping": TIER_LOW,
    
    # High Sensitivity: Critical game state mutations
    "score": TIER_HIGH,
    "inventory": TIER_HIGH,
    "hit_confirm": TIER_HIGH,
    "player_spawn": TIER_HIGH,
    "chat_cmd": TIER_HIGH,
}


def classify_tier(packet_type: str) -> str:
    """
    Classifies a game packet type string into a sensitivity tier.
    
    :param packet_type: String identifier of the packet (e.g., 'position', 'score')
    :return: Tier identifier string (TIER_LOW or TIER_HIGH)
    :raises ValueError: If packet_type is unrecognized
    """
    normalized_type = packet_type.strip().lower()
    if normalized_type not in PACKET_TIER_MAP:
        raise ValueError(
            f"Unrecognized packet_type '{packet_type}'. "
            f"Allowed types: {list(PACKET_TIER_MAP.keys())}"
        )
    return PACKET_TIER_MAP[normalized_type]
