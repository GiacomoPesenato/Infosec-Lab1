"""
Task 7 — Padding Encryption Oracle Attack (Rizzo-Duong, 2010)
=============================================================

Turns the padding *decryption* oracle from Task 6 into an *encryption* oracle.

The server at interrato.dev decrypts a CBC ciphertext and tells us whether the
padding is valid (HTTP 403) or not (HTTP 422).  That single bit of feedback is
enough to recover D_k(x) for any ciphertext block x — exactly the primitive
Task 6 already exploits.  The Rizzo-Duong trick constructs a valid ciphertext
*backwards*: pick a random last block, recover its D_k image, XOR with the
desired plaintext block to get the preceding ciphertext block, and repeat.

Algorithm (PDF slide 17):
    EncryptionOracle(u in {0,1}^{n*ell}):
        x_n  <-  random ell bits
        for i = n down to 1:
            x_{i-1}  :=  u_i  XOR  D_k^{oracle}(x_i)
        return x_0 || x_1 || ... || x_n      # x_0 is the IV

Correctness check (CBC decryption of the result):
    u_i  =  D_k(x_i) XOR x_{i-1}
         =  D_k(x_i) XOR (u_i XOR D_k(x_i))
         =  u_i                                # QED

Target plaintext
    Task 6 recovered:  {"group":"SOSEMANUK","privileged":false,...}
    We forge:          {"group":"SOSEMANUK","privileged":true,...}

To run:
    python -m task7.task7
"""

import os
import sys
import time
import requests

from task5.cbc import pad_iso7816

BLOCK_SIZE = 20
BASE_URL = "https://interrato.dev/infosec/lab1"

# ---------- oracle communication (same pattern as Task 6) ----------

session = requests.Session()
oracle_queries = 0


def query_oracle(token_hex: str) -> bool:
    """
    Send a 2-block token (probe || target) to the server.
    Returns True if padding is valid (HTTP != 422).  Retries on 429.
    """
    global oracle_queries
    while True:
        try:
            r = session.get(f"{BASE_URL}?token={token_hex}", timeout=10)
        except requests.RequestException:
            time.sleep(1)
            continue
        if r.status_code == 429:
            time.sleep(0.3)
            continue
        oracle_queries += 1
        return r.status_code != 422


# ---------- intermediate-value recovery (reused from Task 6) ----------

def recover_intermediate(target_block: bytes, label: str) -> bytes:
    """
    Recover I = D_k(target_block) via the padding oracle, byte by byte.

    Identical to Task 6's attack_block: for each byte position j (from 19
    down to 0) craft a probe block so that the decryption of target_block
    XOR probe has valid ISO 7816-4 padding (last byte = 0x80, suffix = 0x00).
    """
    intermediate = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        probe = bytearray(BLOCK_SIZE)

        # Suffix: already-known bytes must decrypt to 0x00
        for k in range(byte_pos + 1, BLOCK_SIZE):
            probe[k] = intermediate[k]          # I[k] XOR 0x00 = I[k]

        # Prefix: non-special filler (avoids accidental 0x80)
        for k in range(byte_pos):
            probe[k] = 0x41

        found = False
        for guess in range(256):
            probe[byte_pos] = guess
            token_hex = (bytes(probe) + target_block).hex()

            if query_oracle(token_hex):
                # Verify: flip the preceding byte to reject false positives
                # (an accidental 0x80 at an earlier position)
                if byte_pos > 0:
                    probe[byte_pos - 1] ^= 0xFF
                    if not query_oracle((bytes(probe) + target_block).hex()):
                        probe[byte_pos - 1] ^= 0xFF
                        continue
                    probe[byte_pos - 1] ^= 0xFF

                intermediate[byte_pos] = guess ^ 0x80
                found = True
                sys.stdout.write(
                    f"\r  {label}"
                    f" | byte {BLOCK_SIZE - byte_pos:2d}/{BLOCK_SIZE}"
                    f" | queries: {oracle_queries}"
                )
                sys.stdout.flush()
                break

        if not found:
            raise RuntimeError(
                f"Failed at byte {byte_pos} ({label})"
            )

    print()
    return bytes(intermediate)


# ---------- encryption oracle (Rizzo-Duong construction) ----------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encryption_oracle(plaintext: bytes) -> bytes:
    """
    Encrypt an arbitrary plaintext under the server's unknown key,
    using only the padding decryption oracle.

    1. Apply ISO 7816-4 padding, split into n blocks u_1 .. u_n.
    2. Pick random x_n.
    3. For i = n down to 1:  x_{i-1} = u_i XOR D_k(x_i).
    4. Return x_0 || x_1 || ... || x_n   (x_0 is the IV).
    """
    padded = pad_iso7816(plaintext, BLOCK_SIZE)
    n = len(padded) // BLOCK_SIZE
    u = [padded[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE] for i in range(n)]

    x = [None] * (n + 1)
    x[n] = os.urandom(BLOCK_SIZE)

    print(f"  Padded plaintext: {n} blocks ({n * BLOCK_SIZE} bytes)")
    print(f"  x_{n} (random):   {x[n].hex()}\n")

    for i in range(n, 0, -1):
        step = n - i + 1
        label = f"Step {step}/{n}  (x_{i} -> x_{i-1})"
        print(f"[*] {label}: recovering D_k(x_{i}) ...")
        D_k_xi = recover_intermediate(x[i], label)
        x[i - 1] = xor_bytes(u[i - 1], D_k_xi)
        print(f"    x_{i-1} = {x[i-1].hex()}")

    return b"".join(x)


# ---------- main ----------

def main():
    print("=" * 64)
    print("Task 7 — Padding Encryption Oracle Attack  |  Group: SOSEMANUK")
    print(f"  Endpoint: {BASE_URL}")
    print("=" * 64)

    # From Task 6 decryption
    original_json = (
        '{"group":"SOSEMANUK","privileged":false,'
        '"token-id":"20427f44eec58dce"}'
    )
    # Forge: flip privileged to true
    forged_json = (
        '{"group":"SOSEMANUK","privileged":true,'
        '"token-id":"20427f44eec58dce"}'
    )

    target = forged_json.encode()

    print(f"\n  Original:  {original_json}")
    print(f"  Forged:    {forged_json}")
    print(f"  Hex:       {target.hex()}")
    print(f"  Length:    {len(target)} bytes")
    padded = pad_iso7816(target, BLOCK_SIZE)
    print(f"  Padded:    {len(padded)} bytes "
          f"({len(padded) // BLOCK_SIZE} blocks)\n")

    t0 = time.time()
    token = encryption_oracle(target)
    elapsed = time.time() - t0

    token_hex = token.hex()
    print(f"\n{'=' * 64}")
    print(f"Forged token ({len(token)} bytes, "
          f"{len(token) // BLOCK_SIZE} blocks):")
    print(f"  {token_hex}")
    print(f"\nOracle queries: {oracle_queries}  |  Time: {elapsed:.0f}s")

    # ---------- verify against the server ----------
    print(f"\n{'=' * 64}")
    print("Verifying forged token ...")
    while True:
        try:
            r = session.get(f"{BASE_URL}?token={token_hex}", timeout=10)
        except requests.RequestException:
            time.sleep(1)
            continue
        if r.status_code == 429:
            time.sleep(0.3)
            continue
        break

    print(f"  HTTP {r.status_code}")
    print(f"  Body: {r.text[:300]}")
    if r.status_code == 200:
        print("\n  SUCCESS — privileged access granted!")
    elif r.status_code == 403:
        print("\n  Token valid but access denied (privileged=false?)")
    elif r.status_code == 422:
        print("\n  FAILURE — invalid padding")
    else:
        print(f"\n  Unexpected status code: {r.status_code}")


if __name__ == "__main__":
    main()
