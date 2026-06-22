# Demo 04 — UPX-style packed executable

## Scenario

A binary landed in your build-artifact quarantine and the file size looks
wrong for the amount of code it claims to contain. You suspect it has been
run through an executable packer (UPX or similar), which leaves a small
readable loader stub up front and a large compressed body behind it.

`sample.bin` reproduces that layout (you own it; it contains no real
malware):

| Region            | Content                                   | Expected entropy |
|-------------------|-------------------------------------------|------------------|
| ELF header        | `\x7fELF` + program headers               | low              |
| Loader stub       | `UPX!` banner + interpreter/symbol strings| low / medium     |
| Packed body       | zlib-compressed payload                   | critical (>7.5)  |

## Run it

```sh
python -m entropyscan scan demos/04-packed-elf/sample.bin
python -m entropyscan scan demos/04-packed-elf/sample.bin --format json
```

## Expected outcome

- The packed body is flagged as one **CRITICAL** region; the ELF header and
  loader stub stay LOW/MEDIUM.
- Exit code `1` (a finding at the default `--min-severity high`).

## How to act

A readable stub in front of a high-entropy body is the classic packer
signature. Unpack with the matching tool (e.g. `upx -d`) in a sandbox you
own, then re-scan the decompressed binary — the high-entropy region should
disappear and real code structure should appear.

## Regenerate

```sh
python demos/_make_all.py
```
