"""
protocol.py - Authenticated Replay-Protected Wire Protocol Layer for AR-SPECK

Wire Format Specification (21 Bytes Total Fixed Length):
+-----------------+-------------------+---------------------+------------------+
| Tier ID (1 B)   | Ciphertext (8 B)  | Sequence No (4 B)   | MAC (8 B)        |
| Byte offset 0   | Byte offset 1..8  | Byte offset 9..12   | Byte offset 13..20|
+-----------------+-------------------+---------------------+------------------+

Extended for Idea 1 — Entropy-Driven Round Override:
  pack_packet() now accepts an optional `rounds` parameter. When provided (and
  in VALID_ROUNDS), the entropy-computed T bypasses the static TIER_ROUNDS
  lookup and directly controls SPECK round depth. The tier byte on the wire is
  set to the nearest valid tier for the given round count, preserving wire
  format compatibility with unpack_packet().

Design Invariants:
1. VERIFY-THEN-DECRYPT: MAC verified BEFORE decryption attempt.
2. MAC INDEPENDENCE: HMAC-SHA256 always runs at full strength regardless of T.
3. WIRE COMPATIBILITY: All 7 valid tier bytes (0x08, 0x0A, 0x0C, 0x10, 0x14,
   0x18, 0x1B) are accepted by unpack_packet.
"""

import hmac
import hashlib
import struct
from speck64 import encrypt_bytes, decrypt_bytes
from tiering import (
    TIER_ROUNDS, TIER_BYTE_MAP, BYTE_TIER_MAP,
    TIER_LOW, TIER_HIGH, VALID_ROUNDS, classify_tier_from_rounds
)

# Wire format byte lengths
HEADER_TIER_LEN = 1
CIPHERTEXT_LEN = 8
SEQ_NO_LEN = 4
MAC_LEN = 8
TOTAL_PACKET_LEN = HEADER_TIER_LEN + CIPHERTEXT_LEN + SEQ_NO_LEN + MAC_LEN  # 21 bytes


def compute_mac(key: bytes, message: bytes) -> bytes:
    """
    Computes an HMAC-SHA256 MAC over the provided message bytes, truncated to 8 bytes.

    Design Invariant:
    HMAC-SHA256 always executes at full strength (256-bit hash function), completely
    independent of the SPECK cipher's round-count tiering. Truncation to 8 bytes (64 bits)
    is standard for bandwidth-constrained UDP protocols while offering 2^64 forgery security.

    :param key: Secret key bytes
    :param message: Header and payload bytes (Tier ID || Ciphertext || Sequence Number)
    :return: 8-byte truncated MAC
    """
    full_hmac = hmac.new(key, message, hashlib.sha256).digest()
    return full_hmac[:MAC_LEN]


def pack_packet(plaintext_block: bytes, seq_no: int, tier: str, key: bytes,
                rounds: int = None) -> bytes:
    """
    Packs a 64-bit plaintext block into an authenticated AR-SPECK wire packet.

    Pipeline Steps:
    1. Determine round count:
       - If `rounds` is provided and in VALID_ROUNDS → use entropy-driven T directly.
       - Otherwise → lookup TIER_ROUNDS[tier] as normal.
    2. Resolve tier byte: if rounds override active, map rounds→nearest tier byte.
    3. Encrypt plaintext_block using SPECK64/128 with the resolved round count.
    4. Format wire fields: Tier Byte (1B) || Ciphertext (8B) || Seq No (4B big-endian).
    5. Compute truncated HMAC-SHA256 over authenticated data.
    6. Append MAC and return 21-byte wire payload.

    :param plaintext_block: 8-byte plaintext payload
    :param seq_no: Unsigned 32-bit integer sequence number
    :param tier: Sensitivity tier string (used if rounds not overridden)
    :param key: Secret key bytes (16 bytes)
    :param rounds: Optional entropy-driven round count override (must be in VALID_ROUNDS)
    :return: 21-byte wire packet
    """
    if len(plaintext_block) != CIPHERTEXT_LEN:
        raise ValueError(f"Plaintext block must be exactly {CIPHERTEXT_LEN} bytes.")
    if not (0 <= seq_no <= 0xFFFFFFFF):
        raise ValueError("Sequence number must be a 32-bit unsigned integer.")

    # Resolve round count and wire tier byte
    if rounds is not None and rounds in VALID_ROUNDS:
        # Entropy-driven override: compute nearest tier for wire byte
        wire_tier_str = classify_tier_from_rounds(rounds)
        actual_rounds = rounds
    else:
        # Static tier lookup
        if tier not in TIER_ROUNDS:
            raise ValueError(f"Invalid tier '{tier}'.")
        wire_tier_str = tier
        actual_rounds = TIER_ROUNDS[tier]

    # Step 1: Encrypt with SPECK using the resolved round count
    from speck64 import generate_key_schedule
    round_keys = generate_key_schedule(key, rounds=actual_rounds)
    ciphertext = encrypt_bytes(plaintext_block, round_keys)

    # Step 2: Format binary wire components
    tier_byte = bytes([TIER_BYTE_MAP[wire_tier_str]])
    seq_bytes = struct.pack(">I", seq_no)

    # Step 3: Authenticated data = Tier Byte || Ciphertext || Seq No
    authenticated_data = tier_byte + ciphertext + seq_bytes

    # Step 4: Compute MAC over authenticated data
    mac_bytes = compute_mac(key, authenticated_data)

    # Step 5: Assemble 21-byte wire packet
    return authenticated_data + mac_bytes


def unpack_packet(wire_bytes: bytes, key: bytes) -> tuple:
    """
    Unpacks and verifies an AR-SPECK wire packet using VERIFY-THEN-DECRYPT.

    Supports all 7 valid tier bytes including the new T10_ENTROPY (0x0A).

    :param wire_bytes: Received 21-byte wire packet
    :param key: Secret key bytes
    :return: Tuple (plaintext_block, seq_no, tier, valid_flag)
    """
    if len(wire_bytes) != TOTAL_PACKET_LEN:
        return b"", 0, "", False

    tier_byte_val = wire_bytes[0]
    if tier_byte_val not in BYTE_TIER_MAP:
        return b"", 0, "", False

    tier = BYTE_TIER_MAP[tier_byte_val]
    ciphertext = wire_bytes[1:9]
    seq_bytes = wire_bytes[9:13]
    received_mac = wire_bytes[13:21]

    seq_no = struct.unpack(">I", seq_bytes)[0]

    # Recompute MAC over (Tier Byte || Ciphertext || Seq No)
    authenticated_data = wire_bytes[:13]
    computed_mac = compute_mac(key, authenticated_data)

    # Constant-time MAC comparison (timing side-channel defence)
    mac_valid = hmac.compare_digest(computed_mac, received_mac)

    if not mac_valid:
        return b"", seq_no, tier, False

    # Decrypt only after authentication passes
    from speck64 import generate_key_schedule
    rounds = TIER_ROUNDS[tier]
    round_keys = generate_key_schedule(key, rounds=rounds)
    plaintext_block = decrypt_bytes(ciphertext, round_keys)

    return plaintext_block, seq_no, tier, True
