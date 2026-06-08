"""Encrypt and decrypt postcard messages.

Pipeline (encrypt): plaintext -> zlib -> AES-256-GCM -> Reed-Solomon -> base64
Pipeline (decrypt): base64 -> Reed-Solomon -> AES-256-GCM -> zlib -> plaintext

Nonce and ciphertext are kept in separate files; the script does not own a
postcard text format. Compose them onto the postcard however you like.
"""

import argparse
import base64
import secrets
import sys
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from reedsolo import RSCodec

KEY_SIZE: int = 32
NONCE_SIZE: int = 12
RS_PARITY: int = 20  # ~8% overhead; corrects up to 10 byte errors per 255-byte block
LINE_WIDTH: int = 50


def _strip_whitespace(text: str) -> str:
    return "".join(c for c in text if not c.isspace())


def _load_key(path: str) -> bytes:
    key = base64.b64decode(_strip_whitespace(Path(path).read_text()))
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    return key


def _wrap(text: str, width: int) -> str:
    return "\n".join(text[i:i + width] for i in range(0, len(text), width))


def encrypt_message(plaintext: str, key: bytes) -> tuple[str, str]:
    """Returns (nonce_hex, ciphertext_b64)."""
    compressed = zlib.compress(plaintext.encode("utf-8"), level=9)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, compressed, None)
    rs = RSCodec(RS_PARITY)
    return (
        nonce.hex(),
        base64.b64encode(bytes(rs.encode(ciphertext))).decode("ascii"),
    )


def decrypt_message(nonce_hex: str, ciphertext_b64: str, key: bytes) -> str:
    rs = RSCodec(RS_PARITY)
    nonce = bytes.fromhex(_strip_whitespace(nonce_hex).lower())
    ciphertext = bytes(rs.decode(base64.b64decode(_strip_whitespace(ciphertext_b64)))[0])
    compressed = AESGCM(key).decrypt(nonce, ciphertext, None)
    return zlib.decompress(compressed).decode("utf-8")


def cmd_keygen(args: argparse.Namespace) -> None:
    key_b64 = base64.b64encode(secrets.token_bytes(KEY_SIZE)).decode("ascii") + "\n"
    if args.out is None:
        sys.stdout.write(key_b64)
    else:
        Path(args.out).write_text(key_b64)


def cmd_encrypt(args: argparse.Namespace) -> None:
    key = _load_key(args.key)
    plaintext = Path(args.input).read_text()
    nonce_hex, ciphertext_b64 = encrypt_message(plaintext, key)
    Path(args.nonce_out).write_text(nonce_hex + "\n")
    Path(args.out).write_text(_wrap(ciphertext_b64, LINE_WIDTH) + "\n")


def cmd_decrypt(args: argparse.Namespace) -> None:
    key = _load_key(args.key)
    nonce_hex = Path(args.nonce).read_text()
    ciphertext_b64 = Path(args.input).read_text()
    plaintext = decrypt_message(nonce_hex, ciphertext_b64, key)
    if args.out is None:
        sys.stdout.write(plaintext)
    else:
        Path(args.out).write_text(plaintext)


def main() -> None:
    parser = argparse.ArgumentParser(description="Postcard encryption tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keygen", help="Generate a fresh AES-256 key (base64)")
    pk.add_argument("--out", help="write key here (default: stdout)")
    pk.set_defaults(func=cmd_keygen)

    pe = sub.add_parser("encrypt", help="Encrypt a message")
    pe.add_argument("--key", required=True, help="base64 key file")
    pe.add_argument("--input", required=True, help="plaintext input file")
    pe.add_argument("--out", required=True, help="ciphertext output file (base64)")
    pe.add_argument("--nonce-out", required=True, dest="nonce_out",
                    help="nonce output file (hex)")
    pe.set_defaults(func=cmd_encrypt)

    pd = sub.add_parser("decrypt", help="Decrypt a postcard message")
    pd.add_argument("--key", required=True, help="base64 key file")
    pd.add_argument("--input", required=True, help="ciphertext input file (base64)")
    pd.add_argument("--nonce", required=True, help="nonce input file (hex)")
    pd.add_argument("--out", help="output file (default: stdout)")
    pd.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
