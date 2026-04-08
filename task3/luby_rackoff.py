import json
import os

from task2.prf import GGM_PRF


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def F(ki: bytes, x: bytes) -> bytes:
    u = GGM_PRF.hex_to_bitstring(x.hex())
    return GGM_PRF(ki, u).result


def luby_rackoff_encrypt(key: bytes, msg: bytes) -> bytes:
    if len(key) != 40:
        raise ValueError("Key must be 40 bytes")
    if len(msg) != 20:
        raise ValueError("Message must be 20 bytes")

    round_keys = [key[i:i + 10] for i in range(0, 40, 10)]
    L = msg[:10]
    R = msg[10:]
    for ki in round_keys:
        L, R = R, xor_bytes(L, F(ki, R))
    return L + R


def luby_rackoff_decrypt(key: bytes, ct: bytes) -> bytes:
    if len(key) != 40:
        raise ValueError("Key must be 40 bytes")
    if len(ct) != 20:
        raise ValueError("Ciphertext must be 20 bytes")

    round_keys = [key[i:i + 10] for i in range(0, 40, 10)][::-1]
    L = ct[:10]
    R = ct[10:]
    for ki in round_keys:
        L, R = xor_bytes(R, F(ki, L)), L
    return L + R


def test_luby_rackoff(json_path: str):
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

        ct = luby_rackoff_encrypt(key, msg)
        ct_hex = ct.hex()
        enc_ok = ct_hex == expected_ct
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
    json_path = os.path.join(os.path.dirname(__file__), "..", "lab1vectors", "lab1task3.json")
    test_luby_rackoff(json_path)
