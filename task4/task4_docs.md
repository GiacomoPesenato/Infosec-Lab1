# Task 4 — Break a 3-round Luby-Rackoff block cipher

## Goal

Devise a distinguisher between a 3-round Feistel cipher F^(3) and an ideal
random permutation, using both an encryption oracle and a decryption oracle.

---

## Background: Feistel round

One Feistel round with key k maps a 20-byte block (left || right) as:

```
(L, R) → (R,  L XOR F(k, R))
```

where F is the GGM PRF (built on Trivium). Each half is 10 bytes (80 bits).

---

## Step 1 — 2-round warm-up (encryption oracle only)

Encrypting two plaintexts that share the **same right half** R:

```
Enc(L , R) → (L  XOR F(k1, R),  ...)
Enc(L', R) → (L' XOR F(k1, R),  ...)
```

The XOR of the two left ciphertext halves always equals `L XOR L'`.
A random permutation satisfies this with probability 1/2^80 — negligible.

**Distinguisher:** encrypt `(L||R)` and `(L'||R)`, check `c_L XOR c_L' == L XOR L'`.

---

## Step 2 — 3-round attack (both oracles needed)

The Luby-Rackoff theorem guarantees F^(3) is a secure PRP under CPA, but
**not** a strong PRP: both oracles together reveal a structural weakness.

### Notation

For plaintext `(L, R)`, let `A = L XOR F(k1, R)`. The 3-round output is:

```
c_L = R  XOR F(k2, A)
c_R = A  XOR F(k3, c_L)
```

For `(L', R)` with the same R, define `A' = L' XOR F(k1, R)`, so `A XOR A' = L XOR L' = delta`.

### Algorithm (4 oracle queries total)

```
1. Pick random L, L' (distinct), R  — all 10 bytes
2. c1 = Enc(L  || R)
   c2 = Enc(L' || R)
3. delta = L XOR L'
4. c1* = (c1_left,  c1_right XOR delta)
   c2* = (c2_left,  c2_right XOR delta)
5. m1* = Dec(c1*)
   m2* = Dec(c2*)
6. If right_half(m1*) == right_half(m2*)  →  output "feistel"
   Else                                   →  output "random"
```

### Why it works

Tracing Dec(c1\*) through the 3 inverse rounds:

- **Undo round 3:** `c1_R XOR delta XOR F(k3, c1_L) = A XOR delta = A'`
- **Undo round 2:** gives right half `R XOR F(k2, A) XOR F(k2, A')`
- **Undo round 1:** right half is preserved as `R XOR F(k2, A) XOR F(k2, A')`

Tracing Dec(c2\*) symmetrically (A and A' swap roles):

- Final right half = `R XOR F(k2, A') XOR F(k2, A)`

Since XOR is **commutative**, both right halves are always identical:

```
R XOR F(k2, A) XOR F(k2, A')  =  R XOR F(k2, A') XOR F(k2, A)
```

For a random permutation the two right halves match with probability 1/2^80.

| Target       | Distinguisher output | Always? |
|---|---|---|
| 3-round Feistel | `feistel` | Yes (advantage = 1) |
| 4-round Feistel | `random`  | Yes (strong PRP by Luby-Rackoff) |

---

## Supporting code (Tasks 2-3)

The distinguisher is oracle-agnostic; it only calls `enc()` and `dec()`.
To empirically verify it we need working oracles, which require:

| Component | Source | Role |
|---|---|---|
| `Trivium` | `trivium.py` (Task 1) | Stream cipher / PRG |
| `ggm_prf` | `task4.py` | Round function F (GGM tree on Trivium) |
| `feistel_encrypt/decrypt` | `task4.py` | 3/4-round Feistel oracles |

**GGM PRF note:** input bits are traversed **MSB-first** within each byte.
This matches the test vectors in `lab1task2.json` and `lab1task3.json`.

---

## Running

```bash
python task4.py
```

Output confirms:
- GGM PRF: all 6 test vectors pass
- 4-round Feistel enc/dec: all 6 test vectors pass
- 2-round distinguisher: correctly detects F^(2), outputs random on F^(4)
- 3-round distinguisher: correctly detects F^(3), outputs random on F^(4)
