# Demo 08 — Clean release artifact (negative control)

## Scenario

This is the **negative control** for the demo set. Before trusting any
detector you should confirm it stays quiet on benign input. `artifact.txt`
is a normal build artifact: source code plus a CSV configuration table.
Structured text like this sits well below the flag thresholds, so a healthy
detector should produce **no findings**.

| Region        | Content                  | Expected entropy |
|---------------|--------------------------|------------------|
| Source text   | repeated Python function | low              |
| CSV table     | `id,name,region,value`   | low / medium     |

## Run it

```sh
python -m entropyscan scan demos/08-clean-release/artifact.txt
python -m entropyscan scan demos/08-clean-release/artifact.txt --format json
echo "exit: $?"   # expect 0
```

## Expected outcome

- **No** flagged regions at `--min-severity high`.
- Exit code `0` — safe to use as a CI gate that should pass on clean builds.

## How to act

Use this artifact as a regression check: if a future change makes
ENTROPYSCAN flag this file, the thresholds or windowing have drifted and the
false-positive rate has gone up.

## Regenerate

```sh
python demos/_make_all.py
```
