# AR-SPECK: Adaptive Round-Based SPECK Cipher & UDP Protocol Architecture

AR-SPECK is an adaptive lightweight block cipher project designed for real-time multiplayer game UDP traffic. This repository contains:
- **Phase 1**: SPECK64/128 Cipher Core (`speck64.py`)
- **Phase 2**: Sensitivity Tiering & Authenticated Protocol Layer (`tiering.py`, `protocol.py`)
- **Phase 3**: UDP Client/Server Pair & Sliding-Window Replay Protection (`replay_window.py`, `server.py`, `client.py`)
- **Phase 4**: Adversary Attack Suite & Defense Verification (`attacks/packet_editor.py`, `attacks/replay.py`, `attacks/spoofed_sender.py`, `attacks/run_all_attacks.py`)
- **Phase 5**: Crypto-Quality Evaluation Suite (`crypto_tests/avalanche.py`, `crypto_tests/randomness.py`, `crypto_tests/run_all_crypto_tests.py`, `crypto_tests/results.csv`)

Implementation uses Python 3 standard library only (`socket`, `hmac`, `hashlib`, `struct`, `math`, `threading`).

---

## 1. What is an ARX Cipher?

SPECK belongs to the **ARX** family of block ciphers. ARX stands for:
- **Add**: Modular addition ($\pmod{2^{32}}$)
- **Rotate**: Bitwise circular shifts ($\text{ROR}$ / $\text{ROL}$)
- **XOR**: Bitwise Exclusive-OR ($\oplus$)

### Why ARX? (Viva Explanation)
Traditional block ciphers like AES rely on **S-Boxes** (Substitution Boxes / lookup tables) for non-linearity. Lookup tables introduce potential vulnerability to cache-timing side-channel attacks and require extra memory. 

ARX ciphers achieve high security and performance using only three basic CPU instructions:
1. **Modular Addition ($+$)**: Provides **non-linear mixing** and diffusion through carry propagation across bit positions.
2. **Circular Rotation ($\lll, \ggg$)**: Provides **linear diffusion**, rapidly spreading bit alterations across the entire 32-bit word.
3. **Bitwise XOR ($\oplus$)**: Injects round keys and combines state variables linearly.

---

## 2. SPECK64/128 Cipher Parameters

| Parameter | Value | Description |
|---|---|---|
| **Word Size ($n$)** | 32 bits | Processing unit size |
| **Block Size ($2n$)** | 64 bits | Two 32-bit words ($x$: high/left word, $y$: low/right word) |
| **Key Size ($m \cdot n$)** | 128 bits | Four 32-bit key words ($K = (l_2, l_1, l_0, k_0)$) |
| **Rotation $\alpha$** | 8 bits | Circular right shift applied to word $x$ and key state $l$ |
| **Rotation $\beta$** | 3 bits | Circular left shift applied to word $y$ and subkey $k$ |
| **Standard Rounds ($T$)** | 27 rounds | Standard security level (parameterized for reduced-round tiers) |

---

## 3. Endianness & Byte Representation

Per the official NSA SPECK reference specification:
- Multi-byte data (keys, plaintexts, ciphertexts) are packed into 32-bit words using **Little-Endian byte order** (`<I`).
- A 16-byte key `b'\x00\x01\x02\x03\x08\x09\x0a\x0b\x10\x11\x12\x13\x18\x19\x1a\x1b'` unpacks to:
  - $k_0 = \text{0x03020100}$ (Byte offsets 0..3)
  - $l_0 = \text{0x0b0a0908}$ (Byte offsets 4..7)
  - $l_1 = \text{0x13121110}$ (Byte offsets 8..11)
  - $l_2 = \text{0x1b1a1918}$ (Byte offsets 12..15)

---

## 4. Sensitivity Tiering & Wire Protocol

### Sensitivity Tiers (`tiering.py`)
AR-SPECK categorizes game traffic into sensitivity tiers:
- `TIER_LOW` (12 rounds): High-frequency routine traffic (`position`, `input`, `movement`).
- `TIER_HIGH` (27 rounds): Critical state updates (`score`, `inventory`, `hit_confirm`).

### Authenticated Wire Format (`protocol.py`)
Every packed packet is 21 bytes in length:
```text
+-----------------+-------------------+---------------------+------------------+
| Tier ID (1 B)   | Ciphertext (8 B)  | Sequence No (4 B)   | MAC (8 B)        |
| Byte offset 0   | Byte offset 1..8  | Byte offset 9..12   | Byte offset 13..20|
+-----------------+-------------------+---------------------+------------------+
```

---

## 5. Sliding-Window Replay Protection & UDP Server

### Sliding-Window Replay Defense (`replay_window.py`)
UDP is connectionless and unacknowledged; packets can arrive out-of-order or be duplicated by attackers.
- **Why a 64-bit Bitmap over a Simple "Last-Seen" Counter?**
  A simple increasing-only counter (`seq > last_seq`) drops any packet that arrives out of order (e.g. sequence 4 arriving after sequence 5). 
  A **64-bit sliding bitmap** tracks the acceptance state of 64 consecutive sequence numbers in range $[\text{max\_seq} - 63, \text{max\_seq}]$. Out-of-order packets inside this window are accepted, while genuine duplicate sequence numbers are detected instantly as replays.

### Two-Stage Security Pipeline (`server.py`)
```text
                  Incoming UDP Datagram (21 bytes)
                                |
                                v
               [Stage 1: HMAC-SHA256 MAC Check]
                  /                         \
            (MAC Invalid)              (MAC Valid)
               /                               \
     DROP: "bad_mac"             [Stage 2: Sliding Window Check]
  (Skip SPECK Decrypt)               /                   \
                               (Duplicate/Old)          (Valid Seq)
                                     /                       \
                              DROP: "replay"           ACCEPT & DECRYPT
                              DROP: "too_old"       Hand off to Game Logic
```

---

## 6. Adversary Attack Suite & Defense Results (Phase 4)

| Attack Type | Expected Outcome | Actual Outcome | Status |
|---|---|---|---|
| **Packet Editor (Ciphertext Bit Flip)** | `bad_mac` | `bad_mac` | **PASS** |
| **Packet Replay** | `1st:ok, 2nd:replay` | `1st:ok, 2nd:replay` | **PASS** |
| **Spoofed Sender (Invalid Key)** | `bad_mac` | `bad_mac` | **PASS** |

---

## 7. Phase 5: Crypto-Quality & Avalanche Benchmarks

Phase 5 evaluates the mathematical diffusion and statistical randomness of SPECK ciphertext output across round counts $T \in \{27, 20, 12\}$.

### Avalanche Effect Measurement (`crypto_tests/avalanche.py`)
- **Plaintext Avalanche**: Flipping 1 random plaintext bit alters $\approx 50\%$ of ciphertext bits after encryption.
- **Key Avalanche**: Flipping 1 random key bit alters $\approx 50\%$ of ciphertext bits after encryption.
- **Target Ideal**: $50.0\%$ (Complete diffusion).

### Statistical Randomness Tests (`crypto_tests/randomness.py`)
- **Monobit Frequency Test (NIST SP 800-22 §2.1)**: Tests proportion of 0s and 1s in a 64,000-bit stream ($N=1000$ ciphertext blocks). Passed if $p \ge 0.01$.
- **Runs Test (NIST SP 800-22 §2.2)**: Tests total count of consecutive identical bit runs. Passed if $p \ge 0.01$.

### Benchmark Summary Table (`crypto_tests/results.csv`)

| Round Count ($T$) | Plaintext Avalanche (%) | Key Avalanche (%) | Frequency Test $p$-value | Runs Test $p$-value | Randomness Status |
|---|---|---|---|---|---|
| **27 (HIGH Tier)** | 50.23% | 49.78% | 0.4817 | 0.3706 | **PASS** ($p > 0.01$) |
| **20 (MEDIUM Tier)** | 49.86% | 50.30% | 0.5692 | 0.5314 | **PASS** ($p > 0.01$) |
| **12 (LOW Tier)** | 49.90% | 50.36% | 0.2788 | 0.8335 | **PASS** ($p > 0.01$) |

> **Viva Insight**: Even at reduced round count $T=12$, SPECK achieves near-ideal avalanche diffusion ($\approx 50\%$) and passes NIST frequency and run distribution tests ($p > 0.01$). This confirms that $T=12$ provides adequate statistical diffusion for high-frequency low-sensitivity UDP movement packets while reducing CPU load.

---

## 8. Running the Verification Suite

Execute `cli_test.py` to run all Phase 1–5 verification tests:

```powershell
python cli_test.py
```
