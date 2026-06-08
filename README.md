# Postcard Encryption

In case I've ever sent you an encrypted postcard (first of all I'm glad to know you :) ), you can decrypt it with the help of this repo if you don't want to implement it yourself.
You can also encrypt postcards with this code.
For both functions you can either use the Python script, host the webpage locally or use this repo's GitHub pages.

This project was quickly vibe-coded on a vacation with the help of Claude Opus 4.7 - I acknowledge the use of AI in all my coding projects :)

## How it works: Encryption pipeline

```
plaintext  <->  zlib  <->  AES-256-GCM  <->  Reed–Solomon  <->  base64  <->  postcard ciphertext
```

| Stage | Why |
|---|---|
| zlib | Compresses natural-language redundancy to save handwritten chars
| AES-256-GCM | Encryption step |
| Reed–Solomon (255, 235) | 20 parity bytes per 255-byte block. Corrects up to **10 byte errors per block** - so that your decryption input ciphertext does not have to be 100% correct :) |
| Base64 | Hand-writeable charset (`A–Z a–z 0–9 + / =`), I hope you can read my handwriting. Probably the most information-dense encoding I can write on a postcard |

The 12-byte AES-GCM nonce is randomly generated per encryption and noted to the postcard in **hex** (24 chars).
It's public and skips RS protection.
A 24-char hex string is easy enough to manually check before transcribing that error correction adds little for the bytes/effort it costs.

## Postcard layout

The conventional postcard layout is the decryption one-liner (next section) carrying the nonce inline, followed by the base64 payload.
Line breaks and spaces don't matter, the decoder strips whitespace.

### Decryption help one-liner

A self-contained one-liner you can use to reconstruct the decrypt pipeline.
I hand-write this onto the postcard alongside the ciphertext, with the nonce filled in (so you don't need this code at all):

```
Decrypt: b64 -> Reed-Solomon(nsym=20) -> AES-256-GCM(nonce: <24 hex chars>, 32-byte b64 key via email) -> zlib -> UTF-8
```

## About the code

### Setup

This project uses [`uv`](https://docs.astral.sh/uv/).
Dependencies and the pinned Python version are declared in `pyproject.toml` / `.python-version`; the resolved lockfile is committed as `uv.lock`.
After cloning:

```sh
uv sync                    # creates .venv and installs locked deps
```

`uv run` is then how you invoke the script (it auto-syncs if needed).

### Usage

All artifacts share the `message` stem (configurable via `MSG` in the Makefile):

| File | Role |
|---|---|
| `message.txt` | plaintext draft (input to encrypt) |
| `message.key.txt` | 32-byte AES key, base64 |
| `message.enc.txt` | ciphertext, base64, line-breaks are ignored, feel free to adjust |
| `message.nonce.txt` | 12-byte GCM nonce, hex |

```sh
# 1. Generate a one-time key:
make keygen                # -> message.key.txt

# 2. Write your message into message.txt, then encrypt:
make encrypt               # -> message.enc.txt + message.nonce.txt

# 3. Then (with key + ciphertext + nonce) decrypt:
make decrypt               # -> stdout
```

Or call the script directly:

```sh
uv run postcard.py keygen  --out message.key.txt
uv run postcard.py encrypt --key message.key.txt --input message.txt \
                           --out message.enc.txt --nonce-out message.nonce.txt
uv run postcard.py decrypt --key message.key.txt --input message.enc.txt \
                           --nonce message.nonce.txt
```

End-to-end self-test (uses a temp directory, leaves your files alone):

```sh
make roundtrip
```

### Browser-based encrypt + decrypt

`web/` is a fully client-side page with both modes: Toggle at the top, switching preserves whatever you've typed.
Zero runtime dependencies by design, all browser-native APIs (Web Crypto, `Compression`/`DecompressionStream`, `atob`/`btoa`) plus a vendored Reed-Solomon codec.
`web/package.json` exists for project-metadata and Node-version pinning; no `package-lock.json` because there's nothing to lock.

- `web/index.html`: Two-mode UI (decrypt: key/nonce/ciphertext -> plaintext; encrypt: plaintext + optional key -> key/nonce/ciphertext with copy buttons)
- `web/decrypt.js`: Encrypt/decrypt pipelines
- `web/test.mjs`: Node.js cross-check covering `py-encrypt` -> `js-decrypt`, `js-encrypt` -> `js-decrypt`, and `js-encrypt` -> `py-decrypt` (the JS-side output is bit-for-bit compatible with the Python CLI)

```sh
make serve         # http://127.0.0.1:8000
make test-web      # node round-trips the JS decoder against the Python pipeline
```
