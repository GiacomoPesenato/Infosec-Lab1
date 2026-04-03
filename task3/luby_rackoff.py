"""
Task 3 — Luby–Rackoff Block Cipher Implementation
=================================================
This script implements a 4-round Luby-Rackoff block cipher, which is a specific
construction of a Pseudo-Random Permutation (PRP) using a Feistel Network.

Key Parameters:
- Block Size: 20 bytes (160 bits)
- Key Size: 40 bytes (split into four 10-byte subkeys)
- Round Function: GGM PRF (implemented in Task 2)

To run the module:
python -m task3.luby_rackoff
"""

import json
import os

# Import the GGM PRF class from your Task 2 implementation
from task2.prf import GGM_PRF


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Performs a bitwise XOR operation between two byte strings of equal length.
    This is used to combine the PRF output with the data half in each round.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def F(ki: bytes, x: bytes) -> bytes:
    """
    The Round Function F: {0,1}^80 x {0,1}^80 -> {0,1}^80.
    It takes a 10-byte round key (ki) and a 10-byte data block (x).

    Logic:
    1. Converts the 10-byte data (x) into its bitstring representation.
    2. Uses the GGM PRF construction to evaluate the result using key 'ki'.
    """
    # Helper from Task 2 to convert hex/bytes to a string of '0's and '1's
    u = GGM_PRF.hex_to_bitstring(x.hex())

    # Initialize and evaluate the PRF as defined in Task 2
    prf = GGM_PRF(ki, u)
    return prf.result


def luby_rackoff_encrypt(key: bytes, msg: bytes) -> bytes:
    """
    Encrypts a 20-byte plaintext using a 4-round Feistel Network.

    Encryption Logic:
    1. Split the 40-byte key into four 10-byte round keys: k1, k2, k3, k4.
    2. Split the 20-byte message into Left (L) and Right (R) halves (10 bytes each).
    3. For each round i (1 to 4):
       - New_L = R_prev
       - New_R = L_prev XOR F(ki, R_prev)
    4. Concatenate L and R for the final 20-byte ciphertext.
    """
    if len(key) != 40:
        raise ValueError("Key must be 40 bytes")
    if len(msg) != 20:
        raise ValueError("Message must be 20 bytes")

    # Key Schedule: Extract four independent 10-byte subkeys
    round_keys = [key[i:i + 10] for i in range(0, 40, 10)]

    # Initial Split
    L = msg[:10]
    R = msg[10:]

    # 4 Feistel Rounds
    for ki in round_keys:
        # Feistel transformation: L is updated with R, R is updated with XORed F output
        L, R = R, xor_bytes(L, F(ki, R))

    return L + R


def luby_rackoff_decrypt(key: bytes, ct: bytes) -> bytes:
    """
    Decrypts a 20-byte ciphertext by reversing the Feistel rounds.

    Decryption Logic:
    1. Use the same 40-byte key, but apply the subkeys in REVERSE order: k4, k3, k2, k1.
    2. Because of the Feistel structure, the inverse of (L, R) = (R, L XOR F(k, R))
       is calculated by swapping and XORing in the opposite direction.
    """
    if len(key) != 40:
        raise ValueError("Key must be 40 bytes")
    if len(ct) != 20:
        raise ValueError("Ciphertext must be 20 bytes")

    # Key Schedule: Reverse the subkeys for decryption
    round_keys = [key[i:i + 10] for i in range(0, 40, 10)][::-1]

    L = ct[:10]
    R = ct[10:]

    # Inverse Feistel Rounds
    for ki in round_keys:
        # To undo the round: the current L becomes the previous R,
        # and the previous L is recovered by XORing current R with F(ki, current L)
        L, R = xor_bytes(R, F(ki, L)), L

    return L + R


def test_luby_rackoff(json_path: str):
    """
    Loads test vectors from JSON and validates both encryption and decryption.
    """
    if not os.path.exists(json_path):
        print(f"Error: Test vector file not found at {json_path}")
        return

    with open(json_path, "r") as f:
        test_vectors = json.load(f)

    print("Running Luby-Rackoff tests...\n")

    all_pass = True
    for tv in test_vectors:
        num = tv["number"]
        key = bytes.fromhex(tv["key"])
        msg = bytes.fromhex(tv["msg"])
        expected_ct = tv["ct"]

        # Validate Encryption
        ct = luby_rackoff_encrypt(key, msg)
        ct_hex = ct.hex()
        enc_ok = ct_hex == expected_ct

        # Validate Decryption (Ciphertext should return to original Message)
        decrypted = luby_rackoff_decrypt(key, ct)
        dec_ok = decrypted == msg

        if enc_ok and dec_ok:
            print(f"Test {num}: PASS (enc ✓, dec ✓)")
        else:
            all_pass = False
            print(f"Test {num}: FAIL")
            if not enc_ok:
                print(f"  [ENC] Expected: {expected_ct} | Got: {ct_hex}")
            if not dec_ok:
                print(f"  [DEC] Expected: {msg.hex()} | Got: {decrypted.hex()}")

    print(f"\n{'All tests passed!' if all_pass else 'Some tests FAILED.'}")


if __name__ == "__main__":
    # Ensure correct relative path to the test vectors folder
    json_path = os.path.join(os.path.dirname(__file__), "..", "lab1vectors", "lab1task3.json")
    test_luby_rackoff(json_path)
