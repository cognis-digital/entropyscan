# Demo 10 — Process memory dump with an injected region

## Scenario

You captured a memory snapshot of a process you own that an EDR alert tagged
for suspected code injection. A dump is mostly zeroed/structured pages —
stacks, string tables, imported function names — but an injected stage
(decrypted shellcode, an in-memory key, or an unpacked module) shows up as a
compact high-entropy region embedded in that low-entropy background.

`process.dmp` reproduces that picture (synthetic; the injected region is
seeded PRNG bytes):

| Region            | Content                                   | Expected entropy |
|-------------------|-------------------------------------------|------------------|
| Zeroed pages      | `\x00` runs                               | ~0               |
| Stack / strings   | NOP sled, `kernel32.dll`, `VirtualAlloc`… | low              |
| Injected region   | high-entropy stage                        | critical (>7.5)  |

## Run it

```sh
python -m entropyscan scan demos/10-memory-dump/process.dmp
python -m entropyscan scan demos/10-memory-dump/process.dmp --format json
```

## Expected outcome

- The injected region is flagged as one **CRITICAL** region surrounded by
  low-entropy pages. Exit code `1`.

## How to act

The flagged offset is your pivot point. Carve that region and examine it with
a disassembler / YARA in an isolated environment you control; map it back to
the owning memory region with your dump tool (Volatility, WinDbg) to identify
the process and allocation behind the injection.

## Regenerate

```sh
python demos/_make_all.py
```
