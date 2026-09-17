"""
protocol.py - Authenticated Replay-Protected Wire Protocol Layer for AR-SPECK

AR-SPECK Project Phase 2: MAC & Sequence-Number Protocol Wrapper

This module implements the packet formatting, MAC generation/verification, and SPECK
encryption/decryption pipeline for AR-SPECK network payloads.

Wire Format Specification (21 Bytes Total Fixed Length):
+-----------------+-------------------+---------------------+------------------+
| Tier ID (1 B)   | Ciphertext (8 B)  | Sequence No (4 B)   | MAC (8 B)        |
| Byte offset 0   | Byte offset 1..8  | Byte offset 9..12   | Byte offset 13..20|
+-----------------+-------------------+---------------------+------------------+

Field Descriptions:
1. Tier ID (1 byte): Identifies sensitivity level (0x01 = LOW, 0x02 = HIGH).
2. Ciphertext (8 bytes): 64-bit plaintext block encrypted with SPECK64/128 using TIER_ROUNDS[tier].
3. Sequence Number (4 bytes): Big-endian 32-bit unsigned integer (>I) carrying packet sequence.
4. MAC (8 bytes): HMAC-SHA256 computed over (Tier ID || Ciphertext || Sequence Number),
   truncated to 8 bytes (64 bits) to balance security with low UDP payload overhead.

Design Invariants (Critical for Viva):
1. VERIFY-THEN-DECRYPT: The receiver MUST recompute and verify the MAC BEFORE attempting
   SPECK decryption. If the MAC fails, decryption is completely skipped. This prevents unauthenticated
   ciphertext from entering the decryption pipeline (defending against chosen-ciphertext attacks).
2. MAC INDEPENDENCE: The MAC computation ALWAYS uses full SHA-256 cryptographic hashing
   regardless of the encryption round count tier. Round-count reduction ONLY affects the SPECK block cipher.
"""

import hmac
import hashlib
import struct
from speck64 import encrypt_bytes, decrypt_bytes
from tiering import TIER_ROUNDS, TIER_BYTE_MAP, BYTE_TIER_MAP, TIER_LOW, TIER_HIGH

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
    # Full HMAC-SHA256 computation using Python standard library
    full_hmac = hmac.new(key, message, hashlib.sha256).digest()
    # Explicitly truncate 32-byte hash output to first 8 bytes for UDP wire efficiency
    return full_hmac[:MAC_LEN]


def pack_packet(plaintext_block: bytes, seq_no: int, tier: str, key: bytes) -> bytes:
    """
    Packs a 64-bit plaintext block into an authenticated AR-SPECK wire packet.
    
    Pipeline Steps:
    1. Lookup round count for the given tier (e.g. LOW=12, HIGH=27).
    2. Encrypt plaintext_block using SPECK64/128 with the specified round count.
    3. Format wire fields: Tier ID (1 byte) || Ciphertext (8 bytes) || Seq No (4 bytes big-endian).
    4. Compute truncated HMAC-SHA256 over (Tier ID || Ciphertext || Seq No).
    5. Append MAC and return 21-byte wire payload.
    
    :param plaintext_block: 8-byte plaintext payload
    :param seq_no: Unsigned 32-bit integer sequence number (0 <= seq_no <= 2^32 - 1)
    :param tier: Sensitivity tier string (TIER_LOW or TIER_HIGH)
    :param key: Secret key bytes (16 bytes for SPECK64/128 and HMAC)
    :return: 21-byte wire packet
    """
    if len(plaintext_block) != CIPHERTEXT_LEN:
        raise ValueError(f"Plaintext block must be exactly {CIPHERTEXT_LEN} bytes.")
    if not (0 <= seq_no <= 0xFFFFFFFF):
        raise ValueError("Sequence number must be a 32-bit unsigned integer (0..4294967295).")
    if tier not in TIER_ROUNDS:
        raise ValueError(f"Invalid tier '{tier}'. Must be TIER_LOW or TIER_HIGH.")
        
    # Step 1: Encrypt payload with SPECK using the tier's designated round count
    from speck64 import generate_key_schedule
    rounds = TIER_ROUNDS[tier]
    round_keys = generate_key_schedule(key, rounds=rounds)
    ciphertext = encrypt_bytes(plaintext_block, round_keys)
    
    # Step 2: Format binary header components
    tier_byte = bytes([TIER_BYTE_MAP[tier]])
    seq_bytes = struct.pack(">I", seq_no)  # Big-endian 4-byte sequence number
    
    # Step 3: Combine authenticated data (header + ciphertext + sequence number)
    authenticated_data = tier_byte + ciphertext + seq_bytes
    
    # Step 4: Compute MAC over authenticated data
    mac_bytes = compute_mac(key, authenticated_data)
    
    # Step 5: Assemble final wire packet (21 bytes)
    wire_packet = authenticated_data + mac_bytes
    return wire_packet


def unpack_packet(wire_bytes: bytes, key: bytes) -> tuple[bytes, int, str, bool]:
    """
    Unpacks and verifies an AR-SPECK wire packet using VERIFY-THEN-DECRYPT.
    
    Pipeline Steps:
    1. Check wire length (must be exactly 21 bytes).
    2. Extract Tier ID, Ciphertext, Sequence Number, and Received MAC.
    3. Recompute HMAC-SHA256 over (Tier ID || Ciphertext || Sequence Number).
    4. Perform constant-time MAC verification (hmac.compare_digest).
    5. CRITICAL: If MAC verification FAILS, return (b"", seq_no, tier, False) immediately
       WITHOUT attempting SPECK decryption.
    6. If MAC verification SUCCEEDS, decrypt ciphertext with SPECK at TIER_ROUNDS[tier]
       and return (plaintext_block, seq_no, tier, True).
    
    :param wire_bytes: Received 21-byte wire packet
    :param key: Secret key bytes
    :return: Tuple (plaintext_block, seq_no, tier, valid_flag)
    """
    # Step 1: Wire structure length validation
    if len(wire_bytes) != TOTAL_PACKET_LEN:
        # Invalid wire size -> reject immediately
        return b"", 0, "", False

    # Step 2: Extract packet components
    tier_byte_val = wire_bytes[0]
    if tier_byte_val not in BYTE_TIER_MAP:
        # Invalid tier identifier -> reject
        return b"", 0, "", False
        
    tier = BYTE_TIER_MAP[tier_byte_val]
    ciphertext = wire_bytes[1:9]
    seq_bytes = wire_bytes[9:13]
    received_mac = wire_bytes[13:21]
    
    seq_no = struct.unpack(">I", seq_bytes)[0]
    
    # Step 3: Recompute MAC over (Tier ID || Ciphertext || Sequence Number)
    authenticated_data = wire_bytes[:13]
    computed_mac = compute_mac(key, authenticated_data)
    
    # Step 4: Constant-time MAC comparison (prevents timing side-channel attacks)
    mac_valid = hmac.compare_digest(computed_mac, received_mac)
    
    # Step 5: VERIFY-THEN-DECRYPT ordering enforcement
    if not mac_valid:
        # MAC mismatch (packet tampered with, corrupted, or forged key)
        # Skip SPECK decryption entirely to maintain secure control flow!
        return b"", seq_no, tier, False
        
    # Step 6: Decrypt ciphertext only after successful authentication
    from speck64 import generate_key_schedule
    rounds = TIER_ROUNDS[tier]
    round_keys = generate_key_schedule(key, rounds=rounds)
    plaintext_block = decrypt_bytes(ciphertext, round_keys)
    
    return plaintext_block, seq_no, tier, True
