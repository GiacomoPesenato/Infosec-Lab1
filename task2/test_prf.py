import json
import os

from task2.prf import GGM_PRF


def test_prf(json_path: str):
    with open(json_path, "r") as f:
        test_vectors = json.load(f)

    print("Running PRF tests...\n")

    for tv in test_vectors:
        num = tv["number"]
        key = bytes.fromhex(tv["key"])
        u = GGM_PRF.hex_to_bitstring(tv["in"])
        expected = tv["out"]

        prf = GGM_PRF(key, u)
        result_hex = prf.result.hex()

        if result_hex == expected:
            print(f"Test {num}: PASS")
        else:
            print(f"Test {num}: FAIL")
            print(f"  Expected: {expected}")
            print(f"  Got:      {result_hex}")


if __name__ == "__main__":
    json_path = os.path.join(os.path.dirname(__file__), "..", "lab1vectors", "lab1task2.json")
    test_prf(json_path)
