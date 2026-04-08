import json
import os

from task3.luby_rackoff import luby_rackoff_encrypt, luby_rackoff_decrypt

BLOCK_SIZE = 20


def pad_iso7816(data: bytes, block_size: int) -> bytes:
    """Append 0x80 + zero bytes to reach next block boundary (full extra block if already aligned)."""
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def unpad_iso7816(data: bytes, block_size: int) -> bytes:
    """Remove ISO/IEC 7816-4 padding. Raises ValueError if padding is invalid."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded length")
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i < 0 or data[i] != 0x80:
        raise ValueError("Invalid ISO/IEC 7816-4 padding: 0x80 marker not found")
    return data[:i]


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt with CBC + ISO 7816-4 padding. Returns ciphertext only (no IV)."""
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
    """Decrypt CBC ciphertext (no IV) and remove ISO 7816-4 padding."""
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

        # tv["ct"] = IV || ciphertext; strip the prepended IV
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
