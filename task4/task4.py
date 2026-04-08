import os
import json
from task2.prf import GGM_PRF
from task3.luby_rackoff import luby_rackoff_encrypt, luby_rackoff_decrypt, xor_bytes


HALF_BLOCK = 10  # bytes


def ggm_prf(key: bytes, input_data: bytes) -> bytes:
    u = GGM_PRF.hex_to_bitstring(input_data.hex())
    return GGM_PRF(key, u).result


def feistel_encrypt(key: bytes, plaintext: bytes, rounds: int) -> bytes:
    """r-round Feistel encryption; needed for 2- and 3-round variants."""
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


def distinguisher_2round(enc_oracle) -> str:
    """2-round Feistel distinguisher (CPA only).
    For plaintexts (L||R) and (L'||R), F^(2) always satisfies c_L XOR c_L' = L XOR L'."""
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
    """3-round Feistel distinguisher (CPA + CCA, 4 queries, advantage 1)."""
    L = os.urandom(HALF_BLOCK)
    L_prime = os.urandom(HALF_BLOCK)
    R = os.urandom(HALF_BLOCK)
    while L == L_prime:
        L_prime = os.urandom(HALF_BLOCK)

    # 2 encryption queries
    c1 = enc_oracle(L + R)
    c2 = enc_oracle(L_prime + R)

    # XOR delta into the right half of each ciphertext
    delta = xor_bytes(L, L_prime)
    c1_star = c1[:HALF_BLOCK] + xor_bytes(c1[HALF_BLOCK:], delta)
    c2_star = c2[:HALF_BLOCK] + xor_bytes(c2[HALF_BLOCK:], delta)

    # 2 decryption queries
    m1_star = dec_oracle(c1_star)
    m2_star = dec_oracle(c2_star)

    # Invariant: right halves always match for F^(3)
    if m1_star[HALF_BLOCK:] == m2_star[HALF_BLOCK:]:
        return "feistel"
    return "random"


if __name__ == "__main__":

    NUM_TRIALS = 3  # each trial is slow due to Trivium-based GGM PRF

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
                ct = luby_rackoff_encrypt(key, msg)
                pt = luby_rackoff_decrypt(key, ct)
                enc_ok = ct.hex() == tv["ct"]
                dec_ok = pt == msg
                print(f"  Test {tv['number']}: Enc={'PASS' if enc_ok else 'FAIL'}"
                      f", Dec={'PASS' if dec_ok else 'FAIL'}")
    except FileNotFoundError:
        print("  lab1task3.json not found, skipping.")

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
