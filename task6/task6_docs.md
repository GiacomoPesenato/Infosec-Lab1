# Task 6 — Padding Decryption Oracle Attack

## Goal

Decrypt the SOSEMANUK group's encrypted token by exploiting a **padding oracle**
vulnerability on the remote endpoint `https://interrato.dev/infosec/lab1`.

## The vulnerability

The server decrypts CBC ciphertexts (4-round Luby-Rackoff, block size 20 bytes,
ISO/IEC 7816-4 padding) and leaks whether the padding is valid:

| HTTP status | Meaning |
|---|---|
| 403 | Padding valid, decryption OK (access forbidden) |
| 422 | **Invalid padding** |
| 429 | Rate limited (retry) |

The difference between 403 and 422 is the oracle.

## How the attack works (Vaudenay, 2002)

### CBC decryption recap

For ciphertext blocks `x0 (IV), x1, x2, ..., xn`:

```
plaintext_i = D_k(x_i) XOR x_{i-1}
```

Let `I_i = D_k(x_i)` (the "intermediate" value before XOR with the previous block).

### Byte-by-byte recovery

To recover `I_i`, we send crafted 2-block tokens `mask || x_i` to the oracle.
The server computes `D_k(x_i) XOR mask = I_i XOR mask` and checks padding.

For each byte position `j` (from 19 down to 0):

1. **Set the suffix** (positions `j+1..19`): use already-recovered `I_i` values
   so those bytes decrypt to `0x00`.
2. **Brute-force byte `j`**: try all 256 values for `mask[j]`.
3. **Valid padding** means byte `j` decrypted to `0x80` (the ISO 7816-4 marker),
   so `I_i[j] = mask[j] XOR 0x80`.
4. **Verify**: flip the preceding byte and re-query. If still valid, confirmed.
   If not, it was a false positive (byte `j` was `0x00`, and an accidental `0x80`
   appeared earlier) — skip and continue searching.

Once all 20 bytes of `I_i` are recovered: `plaintext_i = I_i XOR x_{i-1}`.

### Handling the ambiguity (false positives)

ISO 7816-4 padding is `0x80` followed by zero or more `0x00`. When the target
byte accidentally decrypts to `0x00` and some preceding byte happens to be `0x80`,
the padding looks valid. The verification step (flipping byte `j-1`) breaks the
accidental `0x80` at the earlier position, revealing the false positive.

## Token structure

The SOSEMANUK token is 100 bytes = 5 blocks of 20 bytes:

```
x0 (IV): 1f5d64313bf7fd50133dc9da95c32ec4c395f368
x1:      cc975156ccce1b3af386c068e6ad058964dda2f1
x2:      d46ff308772615b8155defcf97e252bcc1df60ad
x3:      b98a6afe5f519c624166e765b8b46142d143dd61
x4:      9d5a34f65804a7dae83eba5fb9e2dddd96728701
```

## Result

```
Plaintext (hex): 7b2267726f7570223a22534f53454d414e554b222c22707269
                 76696c65676564223a66616c73652c22746f6b656e2d6964223a
                 2232303432376634346565633538646365227d

Plaintext (JSON): {"group":"SOSEMANUK","privileged":false,"token-id":"20427f44eec58dce"}
```

The last block contained 11 bytes of ISO 7816-4 padding (`80 00 00 ... 00`),
confirming the padding removal worked correctly.

## Performance

| Metric | Value |
|---|---|
| Blocks attacked | 4 |
| Bytes per block | 20 |
| Total queries | ~10,200 |
| Wall time | ~5 minutes |
| Avg queries/byte | ~128 (expected for uniform brute-force) |

Key optimization: `requests.Session()` reuses the TCP/TLS connection across all
queries, avoiding the overhead of a new handshake per request.

## Implementation choices

- **No intermediate state saving**: the attack completes in ~5 minutes, making
  resume logic unnecessary complexity.
- **Verification step on every byte**: adds at most 1 extra query per byte but
  eliminates all false positives, avoiding costly backtracking.
- **Fixed prefix bytes (0x41)**: bytes before the target position are set to a
  non-special value to minimize accidental valid padding patterns.
- **Rate-limit handling**: automatic retry with 0.3s backoff on HTTP 429.
