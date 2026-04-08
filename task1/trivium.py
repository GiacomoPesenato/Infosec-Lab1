import json
import os


def bytes_to_bits(data: bytes) -> list[int]:
    """
    Convert a byte sequence to a list of bits.
    The first bit is the least significant bit (LSB) of the first byte.
    Returns [k_1, k_2, ..., k_n].
    """
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """
    Convert a list of bits to a byte sequence.
    Reconstructs each byte with the first bit as LSB.
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
            raise ValueError("Key must be exactly 10 bytes (80 bits)")
        if len(iv) != 10:
            raise ValueError("IV must be exactly 10 bytes (80 bits)")

        # Extract bits: key_bits = [k_1, ..., k_80]
        key_bits = bytes_to_bits(key)
        iv_bits = bytes_to_bits(iv)

        # Reverse bit order as specified: (k_80, ..., k_1)
        key_bits.reverse()
        iv_bits.reverse()

        # Initialize the 288-bit state
        self.state = [0] * 288

        # Load key into indices 0-79
        self.state[0:80] = key_bits

        # Load IV into indices 93-172
        self.state[93:173] = iv_bits

        # Set the last three bits to 1
        self.state[285] = 1
        self.state[286] = 1
        self.state[287] = 1

        # Warm-up phase: 4 full cycles (4 * 288 = 1152 rotations)
        for _ in range(1152):
            self._next_keystream_bit()

    def _next_keystream_bit(self) -> int:
        """
        Perform one state update step.
        Returns keystream bit z computed in GF(2) where '+' is XOR and '*' is AND.
        Array indices: s_N in the spec corresponds to index N-1.
        """
        s = self.state

        t1 = s[65] ^ s[92]
        t2 = s[161] ^ s[176]
        t3 = s[242] ^ s[287]

        z = t1 ^ t2 ^ t3

        t1 = t1 ^ (s[90] & s[91]) ^ s[170]
        t2 = t2 ^ (s[174] & s[175]) ^ s[263]
        t3 = t3 ^ (s[285] & s[286]) ^ s[68]

        # State update and rotation
        s[1:93] = s[0:92]
        s[0] = t3

        s[94:177] = s[93:176]
        s[93] = t1

        s[178:288] = s[177:287]
        s[177] = t2

        return z

    def keystream_bytes(self, num_bytes: int) -> bytes:
        """Generate the specified number of keystream bytes."""
        stream_bits = []
        for _ in range(num_bytes * 8):
            stream_bits.append(self._next_keystream_bit())
        return bits_to_bytes(stream_bits)


if __name__ == "__main__":
    json_path = os.path.join(
        os.path.dirname(__file__), "..", "lab1vectors", "lab1task1.json"
    )
    try:
        with open(json_path, "r") as f:
            test_vectors = json.load(f)
    except FileNotFoundError:
        print(f"Error: test vector file not found at {json_path}")
        raise SystemExit(1)

    print("Running Trivium test vectors...")
    all_pass = True
    for tv in test_vectors:
        key = bytes.fromhex(tv["key"])
        iv = bytes.fromhex(tv["iv"])
        expected = tv["stream"]

        stream = Trivium(key, iv).keystream_bytes(32).hex()

        if stream == expected:
            print(f"Test {tv['number']}: PASS")
        else:
            all_pass = False
            print(f"Test {tv['number']}: FAIL")
            print(f"  Expected: {expected}")
            print(f"  Got:      {stream}")

    print(f"\n{'All tests passed!' if all_pass else 'Some tests FAILED.'}")
