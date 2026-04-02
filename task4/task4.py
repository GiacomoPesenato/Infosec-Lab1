"""
Task 4 — Break a 3-round Luby-Rackoff block cipher
=====================================================

OBJECTIVE:
    Devise a distinguisher between a 3-round Feistel cipher F^(3) (using a
    secure PRF as round function) and an ideal random permutation.
    The distinguisher has access to both encryption and decryption oracles.

DEVELOPMENT APPROACH (following the hint):
    Step 1: Analyze the 2-round Feistel to build intuition (CPA only).
    Step 2: Extend the analysis to 3 rounds (CPA + CCA).
    Step 3: Implement and empirically verify.

================================================================================
CRYPTOGRAPHIC ANALYSIS
================================================================================

--- Notation ---

    A single Feistel round with key k maps:
        (u0, u1) -> (u1, u0 XOR F(k, u1))
    where F is the PRF (GGM construction).

--- 2-Round Feistel Distinguisher (warm-up, encryption oracle only) ---

    Encrypt (L, R) through 2 rounds with keys k1, k2:
        Round 1: (L, R)                       -> (R, L XOR F(k1, R))
        Round 2: (R, L XOR F(k1, R))          -> (L XOR F(k1, R), R XOR F(k2, L XOR F(k1, R)))
        Output:  c_L = L XOR F(k1, R),  c_R = R XOR F(k2, L XOR F(k1, R))

    Now encrypt two plaintexts (L, R) and (L', R) sharing the same right half:
        c_L  = L  XOR F(k1, R)
        c_L' = L' XOR F(k1, R)
        =>  c_L XOR c_L' = L XOR L'

    This XOR relationship ALWAYS holds for F^(2). For a random permutation,
    it occurs with probability 1/2^80 (negligible for 10-byte half-blocks).

    Distinguisher: encrypt (L||R) and (L'||R), check c_L XOR c_L' == L XOR L'.

--- 3-Round Feistel Distinguisher (main result, both oracles needed) ---

    The Luby-Rackoff theorem proves F^(3) is a secure PRP under chosen-
    plaintext attack. However, it is NOT a strong PRP: an adversary with
    access to BOTH encryption and decryption oracles can distinguish it.

    Encryption of (L, R) through 3 rounds with keys k1, k2, k3:
        Let A = L XOR F(k1, R)
        Round 1: (L, R)    -> (R, A)
        Round 2: (R, A)    -> (A, R XOR F(k2, A))
        Round 3:           -> (R XOR F(k2, A),  A XOR F(k3, R XOR F(k2, A)))
        Output:  c_L = R XOR F(k2, A),  c_R = A XOR F(k3, c_L)

    For two plaintexts (L, R) and (L', R) with the same R:
        A  = L  XOR F(k1, R)
        A' = L' XOR F(k1, R)
        Note: A XOR A' = L XOR L' = delta (known to the attacker)

    ATTACK: construct modified ciphertexts c1* = (c1_L, c1_R XOR delta)
    and c2* = (c2_L, c2_R XOR delta), then decrypt both.

    Decrypting c1* = (c1_L, c1_R XOR delta):
        Undo round 3:
            (c1_R XOR delta) XOR F(k3, c1_L) = A XOR delta = A'
            State: (A', c1_L) = (A', R XOR F(k2, A))

        Undo round 2:
            (R XOR F(k2, A)) XOR F(k2, A') = R XOR F(k2, A) XOR F(k2, A')
            State: (R XOR F(k2, A) XOR F(k2, A'),  A')

        Undo round 1:
            Final right half = R XOR F(k2, A) XOR F(k2, A')

    Decrypting c2* = (c2_L, c2_R XOR delta):
        [Symmetric derivation — A and A' swap roles]
            Final right half = R XOR F(k2, A') XOR F(k2, A)

    Since XOR is commutative:
        right(Dec(c1*)) = R XOR F(k2,A) XOR F(k2,A')
                        = R XOR F(k2,A') XOR F(k2,A)
                        = right(Dec(c2*))

    The right halves are ALWAYS equal for F^(3). For a random permutation,
    this occurs with probability 1/2^80 (negligible).

    Total oracle queries: 4 (2 encryptions + 2 decryptions).
    Distinguisher advantage: 1.

================================================================================
IMPLEMENTATION
================================================================================

    The distinguisher itself is oracle-agnostic (it treats enc/dec as black
    boxes). To empirically verify it, we need a working 3-round Feistel,
    which requires the GGM PRF (Task 2) and Feistel structure (Task 3) as
    minimal supporting code. Trivium (Task 1) is imported from trivium.py.
"""

import os
import json
from task1.trivium import Trivium, bytes_to_bits


HALF_BLOCK = 10  # bytes (ell/2)


# =============================================================================
# Supporting code: GGM PRF and Feistel cipher (Tasks 2-3, needed for oracles)
# =============================================================================

def ggm_prf(key: bytes, input_data: bytes) -> bytes:
    """
    GGM tree PRF: Trivium as length-doubling PRG, all-zero IV.
    Input bits are traversed MSB-first within each byte (the standard
    convention for tree-based constructions, where the most significant
    bit determines the first branch from the root).
    """
    input_bits = []
    for byte in input_data:
        for i in range(7, -1, -1):
            input_bits.append((byte >> i) & 1)
    zero_iv = bytes(10)
    s = key
    for bit in input_bits:
        prg = Trivium(s, zero_iv)
        output = prg.keystream_bytes(20)
        s = output[10:] if bit else output[:10]
    return s


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def feistel_encrypt(key: bytes, plaintext: bytes, rounds: int) -> bytes:
    """r-round Feistel encryption. Key = k1||k2||...||kr (each 10 bytes)."""
    left, right = plaintext[:HALF_BLOCK], plaintext[HALF_BLOCK:]
    for i in range(rounds):
        rk = key[i * HALF_BLOCK : (i + 1) * HALF_BLOCK]
        left, right = right, xor_bytes(left, ggm_prf(rk, right))
    return left + right


def feistel_decrypt(key: bytes, ciphertext: bytes, rounds: int) -> bytes:
    """r-round Feistel decryption. Rounds undone in reverse order."""
    left, right = ciphertext[:HALF_BLOCK], ciphertext[HALF_BLOCK:]
    for i in range(rounds - 1, -1, -1):
        rk = key[i * HALF_BLOCK : (i + 1) * HALF_BLOCK]
        left, right = xor_bytes(right, ggm_prf(rk, left)), left
    return left + right


# =============================================================================
# TASK 4 CORE: Distinguishers
# =============================================================================

def distinguisher_2round(enc_oracle) -> str:
    """
    2-round Feistel distinguisher (CPA only, warm-up).

    Exploits: for plaintexts (L||R) and (L'||R), the 2-round Feistel always
    produces ciphertexts where c_L XOR c_L' = L XOR L'.
    """
    L = os.urandom(HALF_BLOCK)
    L_prime = os.urandom(HALF_BLOCK)
    R = os.urandom(HALF_BLOCK)
    while L == L_prime:
        L_prime = os.urandom(HALF_BLOCK)

    c1 = enc_oracle(L + R)
    c2 = enc_oracle(L_prime + R)

    if xor_bytes(c1[:HALF_BLOCK], c2[:HALF_BLOCK]) == xor_bytes(L, L_prime):
        return "feistel"
    return "random"


def distinguisher_3round(enc_oracle, dec_oracle) -> str:
    """
    3-round Feistel distinguisher (CPA + CCA).

    Algorithm:
        1. Pick random L, L' (distinct) and R.
        2. c1 = Enc(L||R),  c2 = Enc(L'||R).
        3. delta = L XOR L'.
        4. c1* = (c1_left || c1_right XOR delta).
           c2* = (c2_left || c2_right XOR delta).
        5. m1* = Dec(c1*),  m2* = Dec(c2*).
        6. If right_half(m1*) == right_half(m2*) -> "feistel", else "random".
    """
    L = os.urandom(HALF_BLOCK)
    L_prime = os.urandom(HALF_BLOCK)
    R = os.urandom(HALF_BLOCK)
    while L == L_prime:
        L_prime = os.urandom(HALF_BLOCK)

    # 2 encryption queries
    c1 = enc_oracle(L + R)
    c2 = enc_oracle(L_prime + R)

    # Modify ciphertexts: XOR delta into the right half
    delta = xor_bytes(L, L_prime)
    c1_star = c1[:HALF_BLOCK] + xor_bytes(c1[HALF_BLOCK:], delta)
    c2_star = c2[:HALF_BLOCK] + xor_bytes(c2[HALF_BLOCK:], delta)

    # 2 decryption queries
    m1_star = dec_oracle(c1_star)
    m2_star = dec_oracle(c2_star)

    # Check structural invariant: right halves must match for F^(3)
    if m1_star[HALF_BLOCK:] == m2_star[HALF_BLOCK:]:
        return "feistel"
    return "random"


# =============================================================================
# Empirical verification
# =============================================================================

if __name__ == "__main__":

    NUM_TRIALS = 3  # each trial is slow due to Trivium-based GGM PRF

    # ------------------------------------------------------------------
    # Verify supporting code against test vectors (sanity check)
    # ------------------------------------------------------------------
    print("=" * 60)
    print("Sanity check: GGM PRF (Task 2 vectors)")
    print("=" * 60)
    try:
        with open("lab1vectors/lab1task2.json") as f:
            for tv in json.load(f):
                key = bytes.fromhex(tv["key"])
                inp = bytes.fromhex(tv["in"])
                got = ggm_prf(key, inp).hex()
                status = "PASS" if got == tv["out"] else "FAIL"
                print(f"  Test {tv['number']}: {status}")
    except FileNotFoundError:
        print("  lab1task2.json not found, skipping.")

    print()
    print("=" * 60)
    print("Sanity check: 4-round Feistel (Task 3 vectors)")
    print("=" * 60)
    try:
        with open("lab1vectors/lab1task3.json") as f:
            for tv in json.load(f):
                key = bytes.fromhex(tv["key"])
                msg = bytes.fromhex(tv["msg"])
                ct = feistel_encrypt(key, msg, 4)
                pt = feistel_decrypt(key, ct, 4)
                enc_ok = ct.hex() == tv["ct"]
                dec_ok = pt == msg
                print(f"  Test {tv['number']}: Enc={'PASS' if enc_ok else 'FAIL'}"
                      f", Dec={'PASS' if dec_ok else 'FAIL'}")
    except FileNotFoundError:
        print("  lab1task3.json not found, skipping.")

    # ------------------------------------------------------------------
    # 2-round distinguisher (warm-up)
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print("2-Round Distinguisher (CPA only)")
    print("=" * 60)

    key_2r = os.urandom(20)
    enc_2r = lambda pt, k=key_2r: feistel_encrypt(k, pt, 2)
    print(f"  vs 2-round Feistel (expect 'feistel'):")
    for i in range(NUM_TRIALS):
        print(f"    Trial {i+1}: {distinguisher_2round(enc_2r)}")

    key_4r = os.urandom(40)
    enc_4r = lambda pt, k=key_4r: feistel_encrypt(k, pt, 4)
    print(f"  vs 4-round Feistel (expect 'random'):")
    for i in range(NUM_TRIALS):
        print(f"    Trial {i+1}: {distinguisher_2round(enc_4r)}")

    # ------------------------------------------------------------------
    # 3-round distinguisher (MAIN RESULT)
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print("3-Round Distinguisher (CPA + CCA) — TASK 4 MAIN RESULT")
    print("=" * 60)

    key_3r = os.urandom(30)
    enc_3r = lambda pt, k=key_3r: feistel_encrypt(k, pt, 3)
    dec_3r = lambda ct, k=key_3r: feistel_decrypt(k, ct, 3)
    print(f"  vs 3-round Feistel (expect 'feistel'):")
    for i in range(NUM_TRIALS):
        print(f"    Trial {i+1}: {distinguisher_3round(enc_3r, dec_3r)}")

    key_4r = os.urandom(40)
    enc_4r = lambda pt, k=key_4r: feistel_encrypt(k, pt, 4)
    dec_4r = lambda ct, k=key_4r: feistel_decrypt(k, ct, 4)
    print(f"  vs 4-round Feistel (expect 'random'):")
    for i in range(NUM_TRIALS):
        print(f"    Trial {i+1}: {distinguisher_3round(enc_4r, dec_4r)}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    print("=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print("""
  F^(3) is a secure PRP (CPA) but NOT a strong PRP (CPA+CCA).
  The 4-round F^(4) IS a strong PRP (Luby-Rackoff theorem).

  Our distinguisher uses only 4 oracle queries (2 Enc + 2 Dec)
  and achieves advantage = 1 against the 3-round Feistel.
""")
