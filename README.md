# Infosec-Lab1

| Task | Owner | Status |
|------|-------|--------|
| Task 1 | Giacomo | ✅ |
| Task 2 | Konstantin | ✅ |
| Task 3 | Aliza | ✅ |
| Task 4 | Giacomo | ✅ |
| Task 5 | Konstantin | ✅ |
| Task 6 | Giacomo | ✅ |
| Task 7 | Aliza | ✅ |
| Task 8 | Giacomo | ✅ |

---

## How to run each task

All commands must be run from the **project root** (the `lab1/` directory).

### Task 1 — Trivium stream cipher

```bash
python -m task1.trivium
```

Runs the test vectors in `lab1vectors/lab1task1.json`.

### Task 2 — GGM PRF

```bash
python -m task2.test_prf
```

Runs the test vectors in `lab1vectors/lab1task2.json`.

### Task 3 — Luby-Rackoff block cipher (4 rounds)

```bash
python -m task3.luby_rackoff
```

Verifies encryption and decryption against `lab1vectors/lab1task3.json`.

### Task 4 — 3-round Luby-Rackoff distinguisher

```bash
python -m task4.task4
```

Runs sanity checks against Task 2 and Task 3 vectors, then empirically demonstrates the 2-round and 3-round distinguishers.

### Task 5 — CBC mode with ISO/IEC 7816-4 padding

```bash
python -m task5.cbc
```

Verifies encryption and decryption against `lab1vectors/lab1task5.json`.

### Task 6 — Padding decryption oracle attack (Vaudenay, 2002)

```bash
python -m task6.task6
```

Attacks the remote endpoint `https://interrato.dev/infosec/lab1` to decrypt the SOSEMANUK group token. Requires internet connection. Estimated time: ~5 minutes.

### Task 7 — Padding encryption oracle attack (Rizzo-Duong, 2010)

```bash
python -m task7.task7
```

Forges a token with `"privileged":true` by turning the decryption oracle into an encryption oracle. Requires internet connection. Estimated time: ~5 minutes.

### Task 8 — Countermeasures (discussion)

Written discussion in `task8/padding_oracle.md`.
