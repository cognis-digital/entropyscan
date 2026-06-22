# Demo 07 — Config bundle that leaked a binary keystore

## Scenario

A pre-merge secret-scan flagged a config bundle that someone committed to a
repo. Most of it is harmless plaintext settings, but a binary keystore
(encrypted private-key material, PKCS#12-style) got bundled in alongside it.
Encrypted key material is near-random, so it stands out sharply by entropy.

`config.bundle` reproduces that mistake (the keystore body is seeded PRNG
bytes — **no real credentials**):

| Region            | Content                              | Expected entropy |
|-------------------|--------------------------------------|------------------|
| Plaintext config  | `APP_ENV`, `DB_HOST`, flags …        | low              |
| Bundled keystore  | encrypted PKCS#12-style binary body  | critical (>7.5)  |

## Run it

```sh
python -m entropyscan scan demos/07-leaked-secret/config.bundle
python -m entropyscan scan demos/07-leaked-secret/config.bundle --format json
```

## Expected outcome

- The keystore body is flagged as one **CRITICAL** region; exit code `1`.

> **Teaching point:** a raw binary keystore flags high because its bytes are
> near-random. A *base64-encoded* secret, by contrast, tops out near
> **6.0 bits/byte** (log2(64)) and would only reach `medium` — so for
> base64-y blobs, scan with `--min-severity medium`.

## How to act

Treat any committed secret as compromised: rotate the key, purge it from
git history (`git filter-repo`), and add the path to your ignore + scanning
rules so it cannot recur.

## Regenerate

```sh
python demos/_make_all.py
```
