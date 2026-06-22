# Demo 05 — Office document with a compressed/obfuscated macro stream

## Scenario

A `.doc` arrived via a phishing report and your DFIR queue needs a fast
first-pass triage before detonation. Legacy Office files are OLE2 / Compound
File Binary (CFB) containers; a malicious one often hides a compressed or
obfuscated macro project inside an otherwise mundane directory structure.

`sample.doc` mimics that container (you own it; no live macro, no real IOCs):

| Region              | Content                              | Expected entropy |
|---------------------|--------------------------------------|------------------|
| OLE2 / CFB header   | `\xd0\xcf\x11\xe0` magic             | low              |
| Directory strings   | `VBA`, `Module1`, `ThisDocument` …   | low              |
| Macro payload       | gzip-compressed body                 | critical (>7.5)  |

## Run it

```sh
python -m entropyscan scan demos/05-office-macro/sample.doc
python -m entropyscan scan demos/05-office-macro/sample.doc --format json
```

## Expected outcome

- One **CRITICAL** region over the compressed macro payload; exit code `1`.

## How to act

Entropy only tells you *where* the opaque blob is. Pivot to a structural
tool — `oletools` (`olevba`, `oledump.py`) — to extract and read the macro
project from that offset. Treat the document as live until proven otherwise.

## Regenerate

```sh
python demos/_make_all.py
```
