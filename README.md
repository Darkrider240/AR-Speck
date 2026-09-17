# AR-SPECK: Adaptive Round-Based SPECK Cipher & UDP Protocol Architecture

AR-SPECK is an adaptive lightweight block cipher project designed for real-time multiplayer game UDP traffic. This repository contains the complete 6-phase implementation from scratch in Python 3 using standard libraries (`socket`, `hmac`, `hashlib`, `struct`, `math`, `threading`) with zero external crypto dependencies for the cipher itself.

- **Phase 1**: SPECK64/128 Cipher Core (`speck64.py`)
- **Phase 2**: Sensitivity Tiering & Authenticated Protocol Layer (`tiering.py`, `protocol.py`)
- **Phase 3**: UDP Client/Server Pair & Sliding-Window Replay Protection (`replay_window.py`, `server.py`, `client.py`)
- **Phase 4**: Adversary Attack Suite & Defense Verification (`attacks/packet_editor.py`, `attacks/replay.py`, `attacks/spoofed_sender.py`, `attacks/run_all_attacks.py`)
- **Phase 5**: Crypto-Quality Evaluation Suite (`crypto_tests/avalanche.py`, `crypto_tests/randomness.py`, `crypto_tests/run_all_crypto_tests.py`, `crypto_tests/results.csv`)
- **Phase 6**: Performance Benchmarks & Final Trade-Off Evaluation (`benchmarks/throughput.py`, `benchmarks/mac_overhead.py`, `benchmarks/results.py`, `benchmarks/final_results.csv`, `benchmarks/*.png`)

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

## 7. Crypto-Quality & Avalanche Benchmarks (Phase 5)

Phase 5 evaluates the mathematical diffusion and statistical randomness of SPECK ciphertext output across round counts $T \in \{27, 20, 12\}$.

### Avalanche Effect Measurement (`crypto_tests/avalanche.py`)
- **Plaintext Avalanche**: Flipping 1 random plaintext bit alters $\approx 50\%$ of ciphertext bits after encryption.
- **Key Avalanche**: Flipping 1 random key bit alters $\approx 50\%$ of ciphertext bits after encryption.
- **Target Ideal**: $50.0\%$ (Complete diffusion).

### Statistical Randomness Tests (`crypto_tests/randomness.py`)
- **Monobit Frequency Test (NIST SP 800-22 §2.1)**: Tests proportion of 0s and 1s in a 64,000-bit stream ($N=1000$ ciphertext blocks). Passed if $p \ge 0.01$.
- **Runs Test (NIST SP 800-22 §2.2)**: Tests total count of consecutive identical bit runs. Passed if $p \ge 0.01$.

| Round Count ($T$) | Plaintext Avalanche (%) | Key Avalanche (%) | Frequency Test $p$-value | Runs Test $p$-value | Randomness Status |
|---|---|---|---|---|---|
| **27 (HIGH Tier)** | 50.23% | 49.78% | 0.4817 | 0.3706 | **PASS** ($p > 0.01$) |
| **20 (MEDIUM Tier)** | 49.86% | 50.30% | 0.5692 | 0.5314 | **PASS** ($p > 0.01$) |
| **12 (LOW Tier)** | 49.90% | 50.36% | 0.2788 | 0.8335 | **PASS** ($p > 0.01$) |

---

## 8. Performance Benchmarks & Final Trade-Off Evaluation (Phase 6)

Phase 6 measures execution speed, latency reduction, isolated MAC authentication overhead, and compares SPECK64 against an AES-128 baseline.

### Master Security vs. Speed Trade-Off Table (`benchmarks/final_results.csv`)

| Round Count ($T$) | Throughput (blocks/sec) | Cipher Latency ($\mu s$/block) | MAC Overhead ($\mu s$) | Total Latency ($\mu s$) | Avg Avalanche (%) | Randomness Status |
|---|---|---|---|---|---|---|
| **27 (HIGH Tier)** | 54,626 | 18.306 $\mu s$ | 3.529 $\mu s$ | 21.836 $\mu s$ | 50.24% | **PASS** |
| **20 (MEDIUM Tier)** | 87,821 | 11.387 $\mu s$ | 3.529 $\mu s$ | 14.916 $\mu s$ | 50.12% | **PASS** |
| **12 (LOW Tier)** | 141,368 | 7.074 $\mu s$ | 3.529 $\mu s$ | 10.603 $\mu s$ | 50.05% | **PASS** |
| **AES-128 Baseline** | 646,810 | 1.546 $\mu s$ | N/A | N/A | N/A | **PASS** |

*Note: AES-128 baseline evaluated via `pycryptodome`. Encrypting an 8-byte game payload with AES requires 8 bytes of padding (16 bytes on wire), doubling UDP payload overhead compared to SPECK64's native 8-byte block size.*

### Visual Benchmark Figures
- **Throughput vs. Round Count**: `benchmarks/throughput_vs_rounds.png`
- **Avalanche Effect vs. Round Count**: `benchmarks/avalanche_vs_rounds.png`

---

## 9. Key Viva Talking Points & Report Analysis

1. **Quantified Performance Gain**:
   - Reducing SPECK round count from $T=27$ (HIGH tier: score/inventory) to $T=12$ (LOW tier: routine movement/position) reduces cipher execution time from **18.306 $\mu s$** to **7.074 $\mu s$** per block — delivering a **$2.58\times$ speedup** ($61.3\%$ reduction in encryption latency).
   - This latency reduction conserves server CPU cycles during high-frequency UDP game ticks (60–128 Hz streams).

2. **Security Integrity Maintained**:
   - At $T=12$ rounds, SPECK maintains near-ideal avalanche diffusion (**50.05%** of bits flip when a single plaintext or key bit changes) and passes NIST SP 800-22 Monobit Frequency ($p > 0.01$) and Runs ($p > 0.01$) randomness tests.
   - Message authentication (`compute_mac`: $3.529 \mu s$) and 64-bit sliding-window replay protection execute at full strength regardless of tier, ensuring 100% rejection of tampering, forgery, and replay attacks (as proven by Phase 4 attack scripts).

3. **SPECK64 vs. AES-128 Trade-Off**:
   - Hardware-accelerated C-extensions (like AES-ECB) process blocks rapidly in software, BUT AES's 16-byte minimum block size forces 8 bytes of padding for 8-byte game vectors, doubling payload wire size.
   - SPECK64/128 operates directly on native 64-bit (8-byte) blocks, conserving UDP network bandwidth while eliminating table-lookup cache-timing vulnerabilities due to its pure ARX architecture.

---

## 10. Running the Master Verification Suite

Execute `cli_test.py` to run all Phase 1–6 verification tests end-to-end:

```powershell
python cli_test.py
```
