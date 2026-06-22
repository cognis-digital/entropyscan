"""Generate the deterministic input files for demos 04-10.

Every blob is built from the standard library only and seeded so the demos
are byte-stable across runs. Each scenario mimics a real, *authorized*
triage situation: you own the artifact (a build output, a sample you pulled
for analysis, a config you manage) and want ENTROPYSCAN to surface the
high-entropy region you care about.

Run:  python demos/_make_all.py
"""
from __future__ import annotations

import gzip
import os
import random
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def _rand(seed: int, n: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(n))


def _write(rel: str, data: bytes) -> None:
    path = os.path.join(HERE, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    print(f"wrote {rel} ({len(data)} bytes)")


# --- 04: UPX-style packed ELF (low-entropy stub + packed body) -------------
def make_04() -> None:
    # A real packed binary keeps a small readable loader/stub up front and a
    # large compressed body. We approximate the layout, not any real malware.
    elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    elf_header += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 64, 0,
                              0, 64, 56, 4, 64, 0, 0)
    stub = (b"UPX!" + b"\x00" * 4 + b"This file is packed with the UPX "
            b"executable packer http://upx.sf.net $\n" * 2)
    stub += (b"/lib64/ld-linux-x86-64.so.2\x00libc.so.6\x00"
             b"__libc_start_main\x00") * 8
    # Packed body: compress random data so it is genuinely high-entropy.
    body = zlib.compress(_rand(0x5A, 24000), level=9)
    blob = elf_header + stub + b"\x00" * 256 + body
    _write("04-packed-elf/sample.bin", blob)


# --- 05: Office doc carrying an encrypted/compressed OLE stream ------------
def make_05() -> None:
    # OLE2 / CFB magic, some directory-ish text, then a compressed macro-like
    # payload region. Mimics a macro-bearing document you pulled for review.
    ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16
    fat = (b"Root Entry\x00Workbook\x00\x01CompObj\x00"
           b"VBA\x00Module1\x00ThisDocument\x00") * 6
    fat += b"\x00" * 1024
    macro_payload = gzip.compress(_rand(0x4D, 18000))
    blob = ole_magic + fat + b"\x00" * 512 + macro_payload + b"PK\x00\x00" * 8
    _write("05-office-macro/sample.doc", blob)


# --- 06: PCAP with a TLS-encrypted flow (clear headers, ciphertext body) ---
def make_06() -> None:
    # libpcap global header (magic d4 c3 b2 a1, little-endian) + a couple of
    # plausible record headers, then a high-entropy "ciphertext" run that an
    # encrypted/exfil flow would produce.
    pcap_global = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # readable-ish packet metadata (low entropy) for several records
    meta = b""
    for i in range(6):
        meta += struct.pack("<IIII", 1700000000 + i, 0, 64, 64)
        meta += (b"GET / HTTP/1.1\r\nHost: update.example.internal\r\n"
                 b"User-Agent: corp-agent/1.0\r\n\r\n")
    # one big record whose payload is encrypted (random) -> high entropy
    cipher = _rand(0x7C, 20000)
    rec = struct.pack("<IIII", 1700000099, 0, len(cipher), len(cipher)) + cipher
    blob = pcap_global + meta + b"\x00" * 256 + rec
    _write("06-pcap-tls/capture.pcap", blob)


# --- 07: .env / config file with a leaked high-entropy secret blob ---------
def make_07() -> None:
    # A commit that bundled a readable config (low entropy) together with a
    # RAW binary keystore (encrypted private key material -> near-random
    # bytes). The raw keystore region flags as high/critical; base64 secrets,
    # by contrast, cap near 6.0 bits/byte (log2(64)) and would only reach
    # 'medium' - which is itself a useful teaching point in the scenario.
    # No real credentials are used: the keystore body is seeded PRNG bytes.
    head = (b"# config bundle committed by mistake (rotate + purge from git)\n"
            b"APP_ENV=production\n"
            b"LOG_LEVEL=info\n"
            b"DB_HOST=db.internal.example\n"
            b"DB_PORT=5432\n"
            b"FEATURE_FLAGS=alpha,beta,gamma\n"
            b"TIMEOUT_SECONDS=30\n"
            b"RETRIES=3\n"
            b"# ---- begin bundled keystore.p12 (binary) ----\n")
    # Encrypted PKCS#12-style keystore body: raw high-entropy bytes.
    keystore = _rand(0x11, 8000)
    tail = b"\n# ---- end keystore ----\n"
    _write("07-leaked-secret/config.bundle", head + keystore + tail)


# --- 08: Clean release tarball-ish artifact (should NOT flag at high) ------
def make_08() -> None:
    # A build artifact made of source text + tables: structured, medium-low
    # entropy throughout. ENTROPYSCAN should return exit 0 at --min-severity
    # high (no false positive). This is the negative-control demo.
    src = (b"def transform(records):\n"
           b"    out = []\n"
           b"    for r in records:\n"
           b"        out.append({'id': r['id'], 'value': r['value'] * 2})\n"
           b"    return out\n\n"
           b"# configuration table\n")
    csv = b"id,name,region,value\n"
    for i in range(400):
        csv += f"{i},item-{i:04d},us-east-{i % 3},{i * 7}\n".encode()
    blob = (src * 30) + csv
    _write("08-clean-release/artifact.txt", blob)


# --- 09: Steganographic carrier: clean PNG header + appended hidden blob ---
def make_09() -> None:
    # A minimal PNG (low-entropy structured header/chunks) with a high-entropy
    # blob appended after IEND - the classic "data hidden past end-of-image"
    # pattern. ENTROPYSCAN flags the tail.
    png_sig = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk (13 bytes payload) - values are plausible, CRC left zeroed.
    ihdr = struct.pack(">I", 13) + b"IHDR" + struct.pack(
        ">IIBBBBB", 64, 64, 8, 2, 0, 0, 0) + b"\x00\x00\x00\x00"
    # a low-entropy IDAT-ish run (flat color compresses tiny / repetitive)
    idat_body = zlib.compress(b"\x00" * 12000, level=1)  # very low entropy
    idat = struct.pack(">I", len(idat_body)) + b"IDAT" + idat_body + b"\x00" * 4
    iend = struct.pack(">I", 0) + b"IEND" + b"\xae\x42\x60\x82"
    hidden = gzip.compress(_rand(0x33, 16000))  # the smuggled payload
    blob = png_sig + ihdr + idat + iend + hidden
    _write("09-stego-carrier/photo.png", blob)


# --- 10: Memory dump with an injected high-entropy shellcode/key region ----
def make_10() -> None:
    # A process memory snapshot: mostly zeroed/structured pages with one
    # high-entropy region (an injected encrypted stage or an in-memory key).
    page_zero = b"\x00" * 4096
    stack_like = (b"\x90" * 64 + struct.pack("<Q", 0x7FFFFFFFE000) * 32)
    string_table = (b"C:\\Windows\\System32\\kernel32.dll\x00"
                    b"LoadLibraryA\x00GetProcAddress\x00"
                    b"VirtualAlloc\x00") * 12
    injected = _rand(0x6B, 12000)  # high-entropy injected region
    blob = (page_zero * 2 + stack_like + b"\x00" * 1024 + string_table
            + b"\x00" * 2048 + injected + page_zero)
    _write("10-memory-dump/process.dmp", blob)


def main() -> None:
    make_04()
    make_05()
    make_06()
    make_07()
    make_08()
    make_09()
    make_10()


if __name__ == "__main__":
    main()
