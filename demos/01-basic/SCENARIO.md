# Demo 01 - Basic high-entropy region detection

## Scenario

You are triaging a firmware blob / dropped file you own and want to know
whether it contains a compressed or encrypted payload hidden inside otherwise
benign, low-entropy data (headers, text, padding).

`sample.bin` in this directory was built to mimic exactly that layout:

| Region            | Bytes        | Content                          | Expected entropy |
|-------------------|--------------|----------------------------------|------------------|
| Header / text     | 0x0000+      | Repeated ASCII banner            | low (< 5.5)      |
| Zero padding      | middle       | `0x00` run                       | low (~0.0)       |
| Packed payload    | tail         | Pseudo-random bytes (PRNG)       | critical (>7.5)  |

The pseudo-random tail simulates the entropy signature of an encrypted or
compressed/packed blob. ENTROPYSCAN should flag that tail as a CRITICAL region
while leaving the header and padding as LOW.

## Run it

```sh
# Human-readable block map + flagged regions
python -m entropyscan scan demos/01-basic/sample.bin --block-size 256

# Machine-readable for pipelines (exits 1 because a critical region is found)
python -m entropyscan scan demos/01-basic/sample.bin --block-size 256 --format json

# Shareable self-contained HTML report (the "UI")
python -m entropyscan scan demos/01-basic/sample.bin --block-size 256 \
    --format html --output report.html
```

## Expected outcome

- The high-entropy tail is reported as a CRITICAL flagged region.
- The header and zero-padding blocks are LOW.
- Exit code is `1` (a finding at or above the default `--min-severity high`),
  which lets CI / pipelines react to packed content.

## Regenerate the sample

```sh
python demos/01-basic/make_sample.py
```
