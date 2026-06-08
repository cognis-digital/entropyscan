"""Generate the deterministic demo input ``sample.bin``.

Layout: low-entropy ASCII banner + zero padding + a high-entropy (PRNG) tail
that mimics a packed/encrypted payload. Deterministic so the demo is stable.
"""
import os
import random

OUT = os.path.join(os.path.dirname(__file__), "sample.bin")


def build() -> bytes:
    banner = (b"ENTROPYSCAN-DEMO FIRMWARE v1 // config=default // "
              b"region=header // ascii-only // ") * 24  # low entropy, repetitive
    padding = b"\x00" * 2048  # near-zero entropy
    rng = random.Random(1337)  # deterministic
    payload = bytes(rng.randrange(256) for _ in range(4096))  # high entropy
    return banner + padding + payload


def main() -> None:
    data = build()
    with open(OUT, "wb") as fh:
        fh.write(data)
    print(f"wrote {OUT} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
