from trivium import Trivium


class GGM_PRF:
    """
    GGM Pseudorandom Function (PRF) built on top of Trivium.

    Implements the GGM tree construction using Trivium as the underlying PRG.
    Given a 10-byte key k and a bitstring u, evaluates F(k, u) by traversing
    a binary tree: at each level, the current seed is expanded via G into two
    children (r0, r1), and the next seed is chosen based on the current bit of u.
    """

    def __init__(self, key: bytes, u: str):
        """
        Initialize the PRF with a key and input bitstring, and evaluate immediately.

        key: 10-byte secret key
        u:   bitstring (e.g. '10101') representing the input to the PRF
        """
        if len(key) != 10:
            raise ValueError("Key must be exactly 10 bytes (80 bits)")
        for bit in u:
            if bit not in ("0", "1"):
                raise ValueError(f"Invalid character in bitstring: '{bit}'")

        self.key = key
        self.u = u
        self.result = self._evaluate()

    def _G(self, s: bytes) -> tuple[bytes, bytes]:
        """
        PRG step: expands a 10-byte seed into two 10-byte outputs (r0, r1).

        Uses Trivium with the seed as the key and a zero IV.
        Generates 20 bytes of keystream and splits them into two halves.
        """
        cipher = Trivium(s, b"\x00" * 10)  # fixed zero IV
        out = cipher.keystream_bytes(20)
        return out[:10], out[10:]

    def _evaluate(self) -> bytes:
        """
        Traverse the GGM tree along the path defined by self.u.

        Starting from the key as the root seed, at each level:
          - expand the current seed via G into (r0, r1)
          - follow r0 if the current bit is '0', r1 if '1'
        Returns the final 10-byte leaf value.
        """
        s = self.key
        for bit in self.u:
            r0, r1 = self._G(s)
            s = r0 if bit == "0" else r1
        return s

    @staticmethod
    def hex_to_bitstring(hex_str: str) -> str:
        """Convert a hex string to a bitstring (MSB first per byte)."""
        return "".join(f"{byte:08b}" for byte in bytes.fromhex(hex_str))
