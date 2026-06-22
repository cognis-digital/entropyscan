# Demo 06 — Packet capture with an encrypted exfil flow

## Scenario

You captured traffic from a host that a detection rule flagged for beaconing.
The capture is a libpcap file: clear, low-entropy record headers and some
plaintext HTTP metadata, followed by one large record whose payload is
fully encrypted — the entropy signature of a TLS / custom-crypto data
channel (often where exfiltrated data hides).

`capture.pcap` reproduces that shape (synthetic; no real hosts or sessions):

| Region              | Content                                  | Expected entropy |
|---------------------|------------------------------------------|------------------|
| libpcap global hdr  | `\xd4\xc3\xb2\xa1` magic + link header   | low              |
| Per-packet metadata | timestamps + plaintext HTTP request line | low / medium     |
| Encrypted payload   | ciphertext record body                   | critical (>7.5)  |

## Run it

```sh
python -m entropyscan scan demos/06-pcap-tls/capture.pcap
python -m entropyscan scan demos/06-pcap-tls/capture.pcap --format json
```

## Expected outcome

- The ciphertext record body is one **CRITICAL** region; headers/metadata
  stay low. Exit code `1`.

## How to act

Entropy over a capture is a triage shortcut, not a substitute for protocol
analysis. Open the same file in Wireshark / `tshark`, jump to the flagged
offset, and confirm whether the high-entropy body is expected TLS to a known
endpoint or an unexplained encrypted channel worth escalating.

## Regenerate

```sh
python demos/_make_all.py
```
