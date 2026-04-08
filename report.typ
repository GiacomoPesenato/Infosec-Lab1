#set page(margin: (x: 2.5cm, y: 2.2cm))
#set text(font: "New Computer Modern", size: 10.5pt)
#set par(justify: true, leading: 0.65em)
#set heading(numbering: "1.")

#show heading.where(level: 1): it => {
  v(0.8em)
  text(weight: "bold", size: 12pt, it)
  v(0.3em)
}
#show heading.where(level: 2): it => {
  v(0.5em)
  text(weight: "bold", size: 10.5pt, it)
  v(0.2em)
}

// ── Title block ──────────────────────────────────────────────────────────────
#align(center)[
  #text(size: 16pt, weight: "bold")[Symmetric Ciphers and Oracle Attacks — Lab 1]
  #v(0.4em)
  #text(size: 11pt)[Group *SOSEMANUK* — Giacomo Pesenato, Konstantin, Aliza]
  #v(0.2em)
  #text(size: 10pt, fill: gray)[April 2026]
]
#v(0.6em)
#line(length: 100%, stroke: 0.5pt)
#v(0.4em)

// ── 1. Tasks 1–3 and 5 ───────────────────────────────────────────────────────
= Tasks 1–3 and 5: Implementations

== Task 1 — Trivium Stream Cipher

Trivium [De Cannière–Preneel, 2005] is implemented as a Python class with an 80-bit key and an 80-bit IV (10 bytes each). The 288-bit internal state is stored as a flat list of integers. The key is loaded into positions $s_1$–$s_93$ (reversed, LSB-first per byte) and the IV into $s_94$–$s_177$; the last three bits are set to 1. After a 1152-step warm-up the cipher produces keystream via `keystream_bytes(n)`, which collects bits from `_next_keystream_bit()` and packs them LSB-first. All six test vectors pass.

*Design choices.* Using a Python list for the state rather than an integer bitmask keeps the indexing identical to the specification, avoiding off-by-one errors. Bit reversal on load correctly maps the spec's 1-indexed notation $(k_80, dots, k_1)$ to a 0-indexed array.

== Task 2 — GGM Pseudorandom Function

The GGM tree PRF is implemented as class `GGM_PRF`. The underlying PRG $G$ expands a 10-byte seed via Trivium (zero IV) into 20 bytes, split as $(r_0, r_1)$. Starting from the key as the root seed, the evaluator traverses one level per input bit (MSB-first per byte), selecting $r_0$ or $r_1$ at each node and returning the 10-byte leaf. The static helper `hex_to_bitstring` converts inputs using `f"{b:08b}"` to enforce MSB-first ordering, which matches the test vectors.

== Task 3 — Luby-Rackoff Block Cipher (4 rounds)

The 4-round Feistel cipher uses the GGM PRF as its round function $F$. A 40-byte key is split into four 10-byte subkeys; each round maps $(L, R) arrow.r (R, L plus.o F(k_i, R))$. Decryption applies the subkeys in reverse and inverts each round as $(L, R) arrow.r (R plus.o F(k_i, L), L)$. All six test vectors pass for both directions.

== Task 5 — CBC Mode with ISO/IEC 7816-4 Padding

`pad_iso7816(data, block_size)` appends `0x80` followed by zero bytes to reach the next block boundary; if the input is already aligned a full extra block is added. `unpad_iso7816` scans from the end, skips `0x00` bytes, and expects `0x80`, raising `ValueError` on failure.

`cbc_encrypt(key, iv, plaintext)` returns *ciphertext only* (IV excluded), computing $x_i = E_k (u_i plus.o x_(i-1))$ with $x_0 = "iv"$. `cbc_decrypt(key, iv, ciphertext)` reverses the chain and removes padding. This separation of IV from ciphertext simplifies the encryption oracle in Task 7. All six test vectors pass.

// ── 2. Task 4 ─────────────────────────────────────────────────────────────────
= Task 4: 3-Round Luby-Rackoff Distinguisher

== Theoretical Analysis

The Luby-Rackoff theorem guarantees that $F^((3))$ is a secure PRP under CPA, but *not* a strong PRP: an adversary with both encryption and decryption oracles can distinguish it from a random permutation with advantage 1 using only 4 queries.

*Key structural invariant.* For two plaintexts $(L || R)$ and $(L' || R)$ sharing the same right half, define $delta = L plus.o L'$ and let $A = L plus.o F(k_1, R)$, $A' = L' plus.o F(k_1, R)$, so $A plus.o A' = delta$. The 3-round encryption produces:
$ c_L = R plus.o F(k_2, A), quad c_R = A plus.o F(k_3, c_L) $

Construct modified ciphertexts $c_1^* = (c_(1,L), c_(1,R) plus.o delta)$ and $c_2^* = (c_(2,L), c_(2,R) plus.o delta)$. Tracing through the inverse rounds:
$ "right"("Dec"(c_1^*)) = R plus.o F(k_2,A) plus.o F(k_2,A') = "right"("Dec"(c_2^*)) $
by commutativity of XOR. This equality holds *always* for $F^((3))$, and with probability $2^(-80)$ for a random permutation.

== Distinguisher Code

```python
def distinguisher_3round(enc_oracle, dec_oracle) -> str:
    L, L_prime = os.urandom(10), os.urandom(10)
    R = os.urandom(10)
    # 2 encryption queries
    c1 = enc_oracle(L + R)
    c2 = enc_oracle(L_prime + R)
    # XOR delta into the right half of each ciphertext
    delta = xor_bytes(L, L_prime)
    c1_star = c1[:10] + xor_bytes(c1[10:], delta)
    c2_star = c2[:10] + xor_bytes(c2[10:], delta)
    # 2 decryption queries
    m1_star = dec_oracle(c1_star)
    m2_star = dec_oracle(c2_star)
    # Invariant: right halves always match for F^(3)
    return "feistel" if m1_star[10:] == m2_star[10:] else "random"
```

Empirical verification (3 trials each) confirms: the distinguisher always outputs `"feistel"` against a 3-round cipher and always `"random"` against the 4-round cipher — consistent with the Luby-Rackoff theorem.

// ── 3. Tasks 6 and 7 ──────────────────────────────────────────────────────────
= Tasks 6 and 7: Oracle Attack Results

== Task 6 — Padding Decryption Oracle Attack

*Setup.* The remote endpoint `https://interrato.dev/infosec/lab1` decrypts a submitted CBC token and returns HTTP 403 (valid padding) or 422 (invalid padding), acting as a padding oracle. The SOSEMANUK token is 100 bytes (5 blocks: 1 IV + 4 ciphertext).

*Approach.* For each ciphertext block $x_i$, the intermediate value $I_i = D_k (x_i)$ is recovered byte by byte. A crafted 2-block probe `mask || x_i` is sent to the oracle. The suffix of `mask` is set so that already-known bytes decrypt to `0x00`; the target byte is brute-forced until the oracle confirms valid ISO 7816-4 padding (i.e. $I_i [j] plus.o "mask"[j] = mono("0x80")$). A false-positive check (flipping the preceding mask byte) eliminates ambiguous cases. Once all bytes of $I_i$ are known, $u_i = I_i plus.o x_(i-1)$.

*Result.* Recovered plaintext:
#block(fill: luma(240), inset: 8pt, radius: 4pt,
  raw(`{"group":"SOSEMANUK","privileged":false,"token-id":"20427f44eec58dce"}`.text)
)

Total oracle queries: ~10 200 across 4 blocks. Wall time: ~5 minutes. A persistent `requests.Session()` reuses the TCP/TLS connection, significantly reducing per-query latency.

== Task 7 — Padding Encryption Oracle Attack

*Approach* [Rizzo-Duong, 2010]. The decryption oracle is turned into an encryption oracle by constructing the ciphertext backwards. Given target plaintext padded into $n = 4$ blocks $u_1, dots, u_4$:

+ Pick $x_4$ uniformly at random.
+ For $i = 4$ down to $1$: recover $D_k (x_i)$ via the oracle (same byte-by-byte technique), then set $x_(i-1) = u_i plus.o D_k (x_i)$.
+ Output $x_0 || x_1 || dots.c || x_4$ (where $x_0$ acts as the IV).

Correctness: CBC decryption of the output yields $D_k (x_i) plus.o x_(i-1) = D_k (x_i) plus.o u_i plus.o D_k (x_i) = u_i$.

*Target.* The token from Task 6 with `"privileged"` flipped to `true`:
#block(fill: luma(240), inset: 8pt, radius: 4pt,
  raw(`{"group":"SOSEMANUK","privileged":true,"token-id":"20427f44eec58dce"}`.text)
)

The forged 100-byte token is submitted to the endpoint. The server returns HTTP 200, granting privileged access — confirming the attack succeeds with advantage 1.

// ── 4. Task 8 ─────────────────────────────────────────────────────────────────
= Task 8: Countermeasures

A padding oracle attack exploits the error messages or timing differences returned by a server when a ciphertext with incorrect padding is decrypted. In CBC mode with standard padding, this single leaked bit allows an attacker to decrypt arbitrary data or forge ciphertexts without knowing the key.

== 1. Primary Prevention: Authenticated Encryption (AEAD)

The most effective countermeasure is moving away from unauthenticated encryption toward *Authenticated Encryption with Associated Data* (AEAD).

- *Mechanism:* Schemes such as *AES-GCM* or *AES-CCM* combine encryption and authentication into a single operation.
- *Why it works:* The system verifies a Message Authentication Code (MAC) _before_ attempting to decrypt or check the padding. If the tag is invalid, the process stops immediately — the oracle is never triggered.
- *Trade-offs:* High performance; mathematically eliminates padding oracles; ensures integrity and confidentiality. However, nonce reuse in GCM is catastrophic, and legacy systems require migration effort.

== 2. Protocol-Level Mitigation: Encrypt-then-MAC (EtM)

If AEAD cannot be used, the order of operations must be *Encrypt-then-MAC*.

- *Mechanism:* The plaintext is encrypted first; a MAC is then computed over the resulting ciphertext.
- *Why it works:* The receiver verifies the MAC before any decryption attempt. An attacker cannot modify the ciphertext (including its padding) without being detected, so the padding-check code path is never reached for invalid inputs.
- *Trade-offs:* Very secure if implemented correctly. It is often implemented incorrectly as MAC-then-Encrypt (as in older TLS versions), which leaves the system vulnerable.

== 3. Implementation Mitigation: Error Uniformity and Constant-Time Processing

This approach hides the oracle behaviour by making all decryption failures look identical.

- *Mechanism:* The application always returns a generic error (e.g. "Decryption failed") regardless of whether the failure is due to a bad MAC or bad padding. Processing must also be *constant-time* to eliminate timing side-channels.
- *Trade-offs:* Extremely fragile. The Lucky Thirteen attack (2013) demonstrated that even with identical error strings, subtle CPU-level timing differences during record processing can be measured remotely to reconstruct the oracle signal. A single code change can re-introduce the vulnerability.

== 4. Comparison

#table(
  columns: (1.55fr, 0.9fr, 1fr, 2.3fr),
  inset: 6pt,
  align: (left, center, center, left),
  stroke: 0.4pt,
  [*Countermeasure*],        [*Strategy*],   [*Effectiveness*],  [*Trade-offs*],
  [AEAD (AES-GCM / CCM)],   [Prevention],   [Absolute],         [Nonce reuse catastrophic; protocol migration required],
  [Encrypt-then-MAC],        [Prevention],   [High],             [Requires correct key/order management],
  [Generic error messages],  [Mitigation],   [Low–Moderate],     [Timing side-channels remain (Lucky Thirteen)],
  [Remove padding entirely], [Prevention],   [High (niche)],     [Only for fixed-length or stream-based schemes],
)

== Conclusion

While *mitigation* (generic errors, constant-time checks) provides a temporary patch for legacy systems, it is rarely sufficient due to side-channel persistence. *Prevention* via AEAD or Encrypt-then-MAC is the industry standard. The transition cost from older standards (TLS 1.0/1.1, legacy CBC) to modern protocols (TLS 1.3) that eliminate padding-based vulnerabilities by design represents a one-time migration effort with lasting security benefits.
