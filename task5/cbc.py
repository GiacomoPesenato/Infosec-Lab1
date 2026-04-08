"""
Task 5 — CBC mode of operation on Luby-Rackoff
===============================================
Implements CBC encryption/decryption on top of the 4-round Luby-Rackoff
block cipher from Task 3, with ISO/IEC 7816-4 padding.

CBC (PDF slide 11-12):
    Encryption:  x_i = E_k(u_i XOR x_{i-1}),  x_0 = iv
    Decryption:  u_i = D_k(x_i) XOR x_{i-1}

ISO/IEC 7816-4 padding (PDF slide 14):
    Append 0x80 followed by zero or more 0x00 bytes until the total length
    is a multiple of block_size. If the plaintext length is already a
    multiple of block_size, a full extra block is appended.

Parameters (inherited from Task 3):
    Block size : 20 bytes (160 bits)
    Key size   : 40 bytes

Note on test vectors (lab1task5.json):
    The 'ct' field stores IV || ciphertext (IV prepended).
    cbc_encrypt() returns only the ciphertext; the caller is responsible
    for prepending/storing the IV.

To run the module:
    python -m task5.cbc
"""

import json
import os

from task3.luby_rackoff import luby_rackoff_encrypt, luby_rackoff_decrypt

BLOCK_SIZE = 20


def pad_iso7816(data: bytes, block_size: int) -> bytes:
    """
    Apply ISO/IEC 7816-4 padding.

    Appends 0x80 followed by (pad_len - 1) zero bytes, where pad_len is
    chosen so that len(data) + pad_len is a multiple of block_size.
    Because pad_len = block_size - (len(data) % block_size), a full extra
    block is always added when the input is already block-aligned.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def unpad_iso7816(data: bytes, block_size: int) -> bytes:
    """
    Remove ISO/IEC 7816-4 padding.

    Scans from the end, skipping 0x00 bytes, then expects 0x80.
    Raises ValueError if the padding is absent or malformed.
    """
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded length")
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i < 0 or data[i] != 0x80:
        raise ValueError("Invalid ISO/IEC 7816-4 padding: 0x80 marker not found")
    return data[:i]


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt variable-length plaintext in CBC mode with ISO 7816-4 padding.

    x_i = E_k(u_i XOR x_{i-1}),  x_0 = iv

    Returns: ciphertext only (without IV).
    The caller should store iv alongside the ciphertext for later decryption.
    """
    padded = pad_iso7816(plaintext, BLOCK_SIZE)
    prev = iv
    ct_blocks = []
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = luby_rackoff_encrypt(key, xored)
        ct_blocks.append(enc)
        prev = enc
    return b"".join(ct_blocks)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt a ciphertext (without IV) produced by cbc_encrypt.

    u_i = D_k(x_i) XOR x_{i-1},  x_0 = iv

    Validates and removes ISO 7816-4 padding before returning the plaintext.
    Raises ValueError if padding is invalid.
    """
    ct_blocks = [
        ciphertext[i : i + BLOCK_SIZE]
        for i in range(0, len(ciphertext), BLOCK_SIZE)
    ]
    prev = iv
    pt_blocks = []
    for block in ct_blocks:
        dec = luby_rackoff_decrypt(key, block)
        pt_blocks.append(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = block
    return unpad_iso7816(b"".join(pt_blocks), BLOCK_SIZE)


if __name__ == "__main__":
    json_path = os.path.join(
        os.path.dirname(__file__), "..", "lab1vectors", "lab1task5.json"
    )
    if not os.path.exists(json_path):
        print(f"Error: test vector file not found at {json_path}")
        raise SystemExit(1)

    with open(json_path) as f:
        test_vectors = json.load(f)

    print("Running CBC (Task 5) tests...\n")
    all_pass = True
    for tv in test_vectors:
        num = tv["number"]
        key = bytes.fromhex(tv["key"])
        iv  = bytes.fromhex(tv["iv"])
        msg = bytes.fromhex(tv["msg"])

        # tv["ct"] = IV || ciphertext; strip the prepended IV to get ct-only
        ct_full     = bytes.fromhex(tv["ct"])
        expected_ct = ct_full[BLOCK_SIZE:]

        ct = cbc_encrypt(key, iv, msg)
        enc_ok = ct == expected_ct

        pt = cbc_decrypt(key, iv, ct)
        dec_ok = pt == msg

        if enc_ok and dec_ok:
            print(f"Test {num}: PASS (enc ✓, dec ✓)")
        else:
            all_pass = False
            print(f"Test {num}: FAIL")
            if not enc_ok:
                print(f"  [ENC] Expected: {expected_ct.hex()}")
                print(f"  [ENC] Got:      {ct.hex()}")
            if not dec_ok:
                print(f"  [DEC] Expected: {msg.hex()}")
                print(f"  [DEC] Got:      {pt.hex()}")

    print(f"\n{'All tests passed!' if all_pass else 'Some tests FAILED.'}")
