"""
speck64.py - Core Implementation of SPECK64/128 Block Cipher

AR-SPECK Project Phase 1: Cryptography and Network Security Course Project

SPECK is a family of lightweight Add-Rotate-XOR (ARX) block ciphers designed by the NSA.
This file implements SPECK64/128 (64-bit block size, 128-bit key size) from scratch.

Parameters:
- Word size (n): 32 bits
- Key size (m * n): 128 bits (4 words of 32 bits each)
- Rotation alpha (x right rotation): 8 bits
- Rotation beta (y left rotation): 3 bits
- Standard rounds (T): 27 rounds (parameterized to allow reduced-round tiers)

Endianness Convention:
- Little-endian byte order is used when converting between byte strings and 32-bit words,
  per the official SPECK specification guidelines.
"""

import struct

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
WORD_BITS = 32
MASK_32 = 0xFFFFFFFF  # 32-bit mask (2^32 - 1) to enforce modulo 2^32 arithmetic

# SPECK64/128 rotation amounts
ALPHA = 8  # Right rotation amount applied to word 'x' and key state 'l'
BETA = 3   # Left rotation amount applied to word 'y' and key state 'k'

# Standard number of rounds for SPECK64/128
DEFAULT_ROUNDS = 27


# -----------------------------------------------------------------------------
# Circular Shift (Bitwise Rotation) Helpers
# -----------------------------------------------------------------------------
def ror32(x: int, shift: int) -> int:
    """
    Circular Right Shift (Rotate Right) on a 32-bit word.
    
    :param x: 32-bit unsigned integer
    :param shift: Number of bits to rotate right
    :return: 32-bit rotated integer
    """
    # Bitwise shift right by 'shift', combined with bitwise shift left by (32 - shift)
    # Masking with MASK_32 keeps the result strictly within 32 bits.
    return ((x >> shift) | (x << (WORD_BITS - shift))) & MASK_32


def rol32(x: int, shift: int) -> int:
    """
    Circular Left Shift (Rotate Left) on a 32-bit word.
    
    :param x: 32-bit unsigned integer
    :param shift: Number of bits to rotate left
    :return: 32-bit rotated integer
    """
    # Bitwise shift left by 'shift', combined with bitwise shift right by (32 - shift)
    return ((x << shift) | (x >> (WORD_BITS - shift))) & MASK_32


# -----------------------------------------------------------------------------
# Little-Endian Byte / Word Conversion Helpers
# -----------------------------------------------------------------------------
def bytes_to_words32(data: bytes) -> list[int]:
    """
    Converts a byte sequence into a list of 32-bit unsigned integers
    using Little-Endian byte order (<I).
    
    :param data: Input bytes (length must be a multiple of 4)
    :return: List of 32-bit integers
    """
    if len(data) % 4 != 0:
        raise ValueError("Data length must be a multiple of 4 bytes (32-bit words).")
    num_words = len(data) // 4
    # unpack as unsigned 32-bit integers ('I') in little-endian order ('<')
    return list(struct.unpack(f'<{num_words}I', data))


def words32_to_bytes(words: list[int]) -> bytes:
    """
    Converts a list of 32-bit unsigned integers into a byte sequence
    using Little-Endian byte order (<I).
    
    :param words: List of 32-bit integers
    :return: Little-endian byte string
    """
    # pack integers into little-endian 32-bit unsigned bytes
    return struct.pack(f'<{len(words)}I', *[w & MASK_32 for w in words])


# -----------------------------------------------------------------------------
# Key Schedule (Key Expansion)
# -----------------------------------------------------------------------------
def generate_key_schedule(key_input, rounds: int = DEFAULT_ROUNDS) -> list[int]:
    """
    Expands a 128-bit master key into 'rounds' subkeys (round keys).
    
    SPECK Key Schedule ARX recurrence:
        l_{i+3} = ((k_i + ROR_8(l_i)) mod 2^32) ^ i
        k_{i+1} = ROL_3(k_i) ^ l_{i+3}
    
    Key representations accepted:
    - 16-byte `bytes` or `bytearray` object (unpacked in Little-Endian order: k0, l0, l1, l2).
    - List of 4 32-bit words: `[l2, l1, l0, k0]` (NSA paper order) or `[k0, l0, l1, l2]`.
    
    :param key_input: 128-bit key as bytes or list of four 32-bit integers
    :param rounds: Total round count (default 27)
    :return: List of 'rounds' 32-bit round keys
    """
    if isinstance(key_input, (bytes, bytearray)):
        if len(key_input) != 16:
            raise ValueError("Byte key must be exactly 16 bytes (128 bits).")
        words = bytes_to_words32(bytes(key_input))
        # In Little-Endian byte unpacking: words[0]=k0, words[1]=l0, words[2]=l1, words[3]=l2
        k0 = words[0]
        l0 = words[1]
        l1 = words[2]
        l2 = words[3]
    elif isinstance(key_input, (list, tuple)) and len(key_input) == 4:
        w = key_input
        # Check if caller passed [l2, l1, l0, k0] (NSA paper notation) or [k0, l0, l1, l2]
        if w[3] == 0x03020100:
            l2, l1, l0, k0 = w[0], w[1], w[2], w[3]
        elif w[0] == 0x03020100:
            k0, l0, l1, l2 = w[0], w[1], w[2], w[3]
        else:
            # Default convention for list input: [l2, l1, l0, k0] per NSA spec tuple (l2, l1, l0, k0)
            l2, l1, l0, k0 = w[0], w[1], w[2], w[3]
    else:
        raise ValueError("Key input must be 16 bytes or a list/tuple of 4 32-bit integers.")

    # Initialize key state arrays
    # 'l' holds non-linear state words: [l0, l1, l2, l3, ...]
    l = [l0, l1, l2]
    # 'k' holds round subkeys: [k0, k1, k2, ...]
    k = [k0]

    round_keys = [k[0]]

    for i in range(rounds - 1):
        # 1. Rotate l[i] right by alpha (8), add to k[i] modulo 2^32, and XOR round index i
        new_l = ((k[i] + ror32(l[i], ALPHA)) & MASK_32) ^ i
        l.append(new_l)

        # 2. Rotate k[i] left by beta (3) and XOR with new_l to get next round key k[i+1]
        new_k = rol32(k[i], BETA) ^ new_l
        k.append(new_k)

        # Store subkey
        round_keys.append(new_k)

    return round_keys


# -----------------------------------------------------------------------------
# Single Block Encryption & Decryption (Word Level)
# -----------------------------------------------------------------------------
def encrypt_block(x: int, y: int, round_keys: list[int]) -> tuple[int, int]:
    """
    Encrypts a single 64-bit plaintext block (represented as two 32-bit words x, y)
    using the provided round keys.
    
    Round function (R_rk):
        x_{i+1} = ((ROR_8(x_i) + y_i) mod 2^32) ^ rk_i
        y_{i+1} = ROL_3(y_i) ^ x_{i+1}
    
    :param x: High/Left 32-bit word of plaintext
    :param y: Low/Right 32-bit word of plaintext
    :param round_keys: List of 32-bit round subkeys generated by key schedule
    :return: Tuple (x, y) containing the 64-bit ciphertext words
    """
    for rk in round_keys:
        # Step 1: Rotate x right by 8 bits, add y mod 2^32, XOR round key
        x = ((ror32(x, ALPHA) + y) & MASK_32) ^ rk
        # Step 2: Rotate y left by 3 bits, XOR updated x
        y = rol32(y, BETA) ^ x
    return x, y


def decrypt_block(x: int, y: int, round_keys: list[int]) -> tuple[int, int]:
    """
    Decrypts a single 64-bit ciphertext block (represented as two 32-bit words x, y)
    using the provided round keys in reverse order.
    
    Inverse round function (R_rk^-1):
        y_i = ROL_{32 - 3}(y_{i+1} ^ x_{i+1})  [which is ROR_3(y_{i+1} ^ x_{i+1})]
        x_i = ROL_8(((x_{i+1} ^ rk_i) - y_i) mod 2^32)
    
    :param x: High/Left 32-bit word of ciphertext
    :param y: Low/Right 32-bit word of ciphertext
    :param round_keys: List of 32-bit round subkeys generated by key schedule
    :return: Tuple (x, y) containing the decrypted 64-bit plaintext words
    """
    # Reverse iterate through round subkeys
    for rk in reversed(round_keys):
        # Step 1: Invert y step -> XOR y with x, then rotate right by beta (3 bits)
        # ROL(v, 32 - 3) == ROR(v, 3)
        y = rol32(y ^ x, WORD_BITS - BETA)
        # Step 2: Invert x step -> XOR x with round key, subtract y mod 2^32, rotate left by alpha (8 bits)
        x_sub = ((x ^ rk) - y) & MASK_32
        x = rol32(x_sub, ALPHA)
    return x, y


# -----------------------------------------------------------------------------
# Byte-Level Encryption & Decryption Wrappers
# -----------------------------------------------------------------------------
def encrypt_bytes(pt_bytes: bytes, round_keys: list[int]) -> bytes:
    """
    Encrypts an 8-byte plaintext block into an 8-byte ciphertext block.
    
    :param pt_bytes: 8 bytes of plaintext
    :param round_keys: Pre-generated round subkeys
    :return: 8 bytes of ciphertext
    """
    if len(pt_bytes) != 8:
        raise ValueError("Plaintext block must be exactly 8 bytes (64 bits).")
    words = bytes_to_words32(pt_bytes)
    # words[0] is y (low word), words[1] is x (high word) in little-endian order
    y, x = words[0], words[1]
    ctx_x, ctx_y = encrypt_block(x, y, round_keys)
    # Convert back to bytes in little-endian order: [ctx_y, ctx_x]
    return words32_to_bytes([ctx_y, ctx_x])


def decrypt_bytes(ct_bytes: bytes, round_keys: list[int]) -> bytes:
    """
    Decrypts an 8-byte ciphertext block into an 8-byte plaintext block.
    
    :param ct_bytes: 8 bytes of ciphertext
    :param round_keys: Pre-generated round subkeys
    :return: 8 bytes of plaintext
    """
    if len(ct_bytes) != 8:
        raise ValueError("Ciphertext block must be exactly 8 bytes (64 bits).")
    words = bytes_to_words32(ct_bytes)
    ctx_y, ctx_x = words[0], words[1]
    pt_x, pt_y = decrypt_block(ctx_x, ctx_y, round_keys)
    return words32_to_bytes([pt_y, pt_x])
