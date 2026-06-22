# Demo 09 — Image with data hidden past end-of-file

## Scenario

An image attachment is larger than its dimensions justify. A common, low-
effort smuggling technique appends an extra payload **after** a valid image's
end-of-file marker: most viewers render the picture and ignore the trailing
bytes, but the data is still there.

`photo.png` is a minimal valid-looking PNG (low-entropy header + a flat,
highly compressible image body) with a gzip blob appended after the `IEND`
chunk (synthetic payload — seeded PRNG bytes):

| Region          | Content                          | Expected entropy |
|-----------------|----------------------------------|------------------|
| PNG signature   | `\x89PNG\r\n\x1a\n`              | low              |
| IHDR / IDAT     | header + flat-color image data   | low              |
| Appended payload| gzip blob after `IEND`           | critical (>7.5)  |

## Run it

```sh
python -m entropyscan scan demos/09-stego-carrier/photo.png
python -m entropyscan scan demos/09-stego-carrier/photo.png --format json
```

## Expected outcome

- The trailing blob is flagged as one **CRITICAL** region near the end of the
  file; the image chunks stay LOW. Exit code `1`.

## How to act

A high-entropy region positioned *after* a format's end marker is a strong
appended-data indicator. Locate `IEND`, carve everything after it
(`dd` / `binwalk -e`), and analyze the carved blob separately.

## Regenerate

```sh
python demos/_make_all.py
```
