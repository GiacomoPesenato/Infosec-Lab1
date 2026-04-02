"""
Task 6 — Padding Decryption Oracle Attack (Vaudenay, 2002)
==========================================================

Performs a padding oracle attack against a CBC-mode cipher with ISO/IEC 7816-4
padding, using the remote vulnerable endpoint at interrato.dev.

Oracle behavior (determined by probing):
  - HTTP 403 = valid padding (decryption succeeded, access forbidden)
  - HTTP 422 = invalid padding
  - HTTP 429 = rate limited (retry)

Cipher: 4-round Luby-Rackoff in CBC mode, block size = 20 bytes.
Padding: ISO/IEC 7816-4 (0x80 byte followed by zero or more 0x00 bytes).

Attack:
  For each ciphertext block x_i, send crafted 2-block ciphertexts (mask || x_i)
  to the oracle. Vary mask byte-by-byte from position 19 down to 0.
  Set the suffix so positions after the target decrypt to 0x00, then brute-force
  the target byte until the oracle reports valid padding (target = 0x80).
  This reveals I_i[j] = mask[j] XOR 0x80, where I_i = D_k(x_i).
  Finally: plaintext_i = I_i XOR x_{i-1}.
"""

import requests
import time
import sys

BLOCK_SIZE = 20
BASE_URL = "https://interrato.dev/infosec/lab1"

# SOSEMANUK group encrypted token
TOKEN = (
    "1f5d64313bf7fd50133dc9da95c32ec4c395f368"
    "cc975156ccce1b3af386c068e6ad058964dda2f1"
    "d46ff308772615b8155defcf97e252bcc1df60ad"
    "b98a6afe5f519c624166e765b8b46142d143dd61"
    "9d5a34f65804a7dae83eba5fb9e2dddd96728701"
)

# Persistent HTTP session (reuses TCP connection — much faster than per-request)
session = requests.Session()
oracle_queries = 0


def query_oracle(token_hex: str) -> bool:
    """Returns True if padding is valid (HTTP != 422). Retries on 429."""
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


def remove_padding(data: bytes) -> bytes:
    """Remove ISO/IEC 7816-4 padding."""
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i < 0 or data[i] != 0x80:
        raise ValueError("Invalid ISO 7816-4 padding")
    return data[:i]


def attack_block(target_block: bytes, block_idx: int, num_ct_blocks: int):
    """Recover I = D_k(target_block) via the padding oracle, byte by byte."""
    intermediate = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        mask = bytearray(BLOCK_SIZE)

        # Suffix: already-known bytes decrypt to 0x00
        for k in range(byte_pos + 1, BLOCK_SIZE):
            mask[k] = intermediate[k]

        # Prefix: fixed non-special value
        for k in range(byte_pos):
            mask[k] = 0x41

        found = False
        for guess in range(256):
            mask[byte_pos] = guess
            token_hex = (bytes(mask) + target_block).hex()

            if query_oracle(token_hex):
                # Verify: flip preceding byte to reject false positives
                # (accidental 0x80 at an earlier position)
                if byte_pos > 0:
                    mask[byte_pos - 1] ^= 0xFF
                    if not query_oracle((bytes(mask) + target_block).hex()):
                        mask[byte_pos - 1] ^= 0xFF
                        continue
                    mask[byte_pos - 1] ^= 0xFF

                intermediate[byte_pos] = guess ^ 0x80
                found = True
                sys.stdout.write(
                    f"\r  Block {block_idx}/{num_ct_blocks}"
                    f" | byte {BLOCK_SIZE - 1 - byte_pos + 1:2d}/{BLOCK_SIZE}"
                    f" | queries: {oracle_queries}"
                )
                sys.stdout.flush()
                break

        if not found:
            raise RuntimeError(
                f"Failed at byte {byte_pos} of block {block_idx}"
            )

    print()
    return bytes(intermediate)


def main():
    print("=" * 60)
    print("Task 6 — Padding Oracle Attack  |  Group: SOSEMANUK")
    print("=" * 60)

    ct = bytes.fromhex(TOKEN)
    blocks = [ct[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
              for i in range(len(ct) // BLOCK_SIZE)]
    num_ct = len(blocks) - 1  # exclude IV
    print(f"Token: {len(blocks)} blocks (1 IV + {num_ct} ciphertext)\n")

    plaintext_blocks = []
    t0 = time.time()

    for idx in range(1, len(blocks)):
        I = attack_block(blocks[idx], idx, num_ct)
        pt = bytes(I[j] ^ blocks[idx - 1][j] for j in range(BLOCK_SIZE))
        plaintext_blocks.append(pt)
        print(f"    => {pt.hex()}")

    elapsed = time.time() - t0
    full_pt = b"".join(plaintext_blocks)
    plaintext = remove_padding(full_pt)

    print(f"\nPlaintext (hex): {plaintext.hex()}")
    try:
        print(f"Plaintext (text): {plaintext.decode('utf-8')}")
    except UnicodeDecodeError:
        print("  (not valid UTF-8)")

    print(f"\nQueries: {oracle_queries}  |  Time: {elapsed:.0f}s")


if __name__ == "__main__":
    main()
