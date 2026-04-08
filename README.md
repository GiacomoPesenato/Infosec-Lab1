# Infosec-Lab1
## Come avviare ogni task

Tutti i comandi vanno eseguiti dalla **root del progetto** (la cartella `lab1/`).

### Task 1 — Trivium stream cipher

```bash
python -m task1.trivium
```

Verifica i test vector in `lab1vectors/lab1task1.json`.

### Task 2 — GGM PRF

```bash
python -m task2.test_prf
```

Verifica i test vector in `lab1vectors/lab1task2.json`.

### Task 3 — Luby-Rackoff block cipher (4 round)

```bash
python -m task3.luby_rackoff
```

Verifica encrypt e decrypt contro `lab1vectors/lab1task3.json`.

### Task 4 — Distinguisher 3-round Luby-Rackoff

```bash
python -m task4.task4
```

Esegue i sanity check su task2 e task3, poi dimostra empiricamente il distinguisher a 2 e 3 round.

### Task 5 — CBC mode con padding ISO/IEC 7816-4

```bash
python -m task5.cbc
```

Verifica encrypt e decrypt contro `lab1vectors/lab1task5.json`.

### Task 6 — Padding decryption oracle attack (Vaudenay, 2002)

```bash
python -m task6.task6
```

Attacca l'endpoint remoto `https://interrato.dev/infosec/lab1` per decifrare il token del gruppo SOSEMANUK. Richiede connessione internet. Tempo stimato: ~5 minuti.

### Task 7 — Padding encryption oracle attack (Rizzo-Duong, 2010)

```bash
python -m task7.task7
```

Forgia un token con `"privileged":true` usando l'oracle di decifratura come encryption oracle. Richiede connessione internet. Tempo stimato: ~5 minuti.

### Task 8 — Countermeasures (discussione)

Documento testuale in `task8/padding_oracle.md`.
