import json
import os

def bytes_to_bits(data: bytes) -> list[int]:
    """
    Converte una sequenza di byte in una lista di bit.
    Il primo bit è il bit meno significativo (LSB) del primo byte.
    Restituisce [k_1, k_2, ..., k_n].
    """
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits: list[int]) -> bytes:
    """
    Converte una lista di bit in una sequenza di byte.
    Ricostruisce i byte inserendo il primo bit come LSB.
    """
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        val = 0
        for j, b in enumerate(chunk):
            val |= (b << j)
        out.append(val)
    return bytes(out)

class Trivium:
    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 10:
            raise ValueError("La chiave deve essere esattamente di 10 byte (80 bit)")
        if len(iv) != 10:
            raise ValueError("L'IV deve essere esattamente di 10 byte (80 bit)")
        
        # Estraiamo i bit: key_bits = [k_1, ..., k_80]
        key_bits = bytes_to_bits(key)
        iv_bits = bytes_to_bits(iv)
        
        # Invertiamo l'ordine dei bit come specificato: (k_80, ..., k_1)
        key_bits.reverse()
        iv_bits.reverse()
        
        # Inizializzazione dello stato a 288 bit
        self.state = [0] * 288
        
        # Caricamento della chiave -> indici 0-79
        self.state[0:80] = key_bits
        
        # Caricamento dell'IV -> indici 93-172
        self.state[93:173] = iv_bits
        
        # Gli ultimi tre bit vengono impostati a 1
        self.state[285] = 1
        self.state[286] = 1
        self.state[287] = 1
        
        # Fase di warm-up: 4 cicli completi (4 * 288 = 1152 rotazioni)
        for _ in range(1152):
            self._next_keystream_bit()

    def _next_keystream_bit(self) -> int:
        """
        Esegue un singolo step di aggiornamento dello stato interno.
        Restituisce il bit z calcolato in GF(2) dove '+' è XOR e '*' è AND.
        """
        s = self.state
        
        # Indici nell'array (s_N nel testo corrisponde all'indice N-1)
        t1 = s[65] ^ s[92]
        t2 = s[161] ^ s[176]
        t3 = s[242] ^ s[287]
        
        z = t1 ^ t2 ^ t3
        
        t1 = t1 ^ (s[90] & s[91]) ^ s[170]
        t2 = t2 ^ (s[174] & s[175]) ^ s[263]
        t3 = t3 ^ (s[285] & s[286]) ^ s[68]
        
        # Aggiornamento e rotazione dello stato
        s[1:93] = s[0:92]
        s[0] = t3
        
        s[94:177] = s[93:176]
        s[93] = t1
        
        s[178:288] = s[177:287]
        s[177] = t2
        
        return z

    def keystream_bytes(self, num_bytes: int) -> bytes:
        """
        Genera un numero specificato di byte di keystream.
        """
        stream_bits = []
        for _ in range(num_bytes * 8):
            stream_bits.append(self._next_keystream_bit())
        return bits_to_bytes(stream_bits)

# Blocco di esecuzione per i test
if __name__ == "__main__":
    try:
        json_path = os.path.join(os.path.dirname(__file__), "..", "lab1vectors", "lab1task1.json")
        with open(json_path, "r") as f:
            test_vectors = json.load(f)
            
        print("Esecuzione dei Test Vector per la Task 1...")
        for tv in test_vectors:
            key = bytes.fromhex(tv["key"])
            iv = bytes.fromhex(tv["iv"])
            expected_stream = tv["stream"]
            
            # Istanzia il cifrario
            cipher = Trivium(key, iv)
            
            # Genera i primi 32 byte di keystream
            stream = cipher.keystream_bytes(32)
            stream_hex = stream.hex()
            
            if stream_hex == expected_stream:
                print(f"Test {tv['number']}: PASSATO")
            else:
                print(f"Test {tv['number']}: FALLITO")
                print(f"  Atteso:    {expected_stream}")
                print(f"  Calcolato: {stream_hex}")
    except FileNotFoundError:
        print("Il file lab1task1.json non è stato trovato. Assicurati che si trovi nella stessa cartella dello script.")