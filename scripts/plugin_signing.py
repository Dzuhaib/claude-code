#!/usr/bin/env python3
import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:
    print(
        "plugin_signing.py requires cryptography. Install it with "
        "'python3 -m pip install -r scripts/requirements-signing.txt'.",
        file=sys.stderr,
    )
    sys.exit(2)

SIGNATURE_NAME = "signature.json"
SIGNATURE_VERSION = 1
SKIP_PARTS = {".git", ".pytest_cache", "__pycache__"}
SKIP_SUFFIXES = {".pyc", ".pyo"}


def plugin_files(plugin_dir):
    plugin_dir = Path(plugin_dir)
    files = []
    for path in plugin_dir.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(plugin_dir)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        if path.suffix in SKIP_SUFFIXES or relative.as_posix() == SIGNATURE_NAME:
            continue
        files.append((relative, path))
    return sorted(files, key=lambda item: item[0].as_posix())


def plugin_digest(plugin_dir):
    digest = hashlib.sha256()
    for relative, path in plugin_files(plugin_dir):
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def key_id(public_key):
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def load_private_key(path):
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("the private key must be Ed25519")
    return key


def load_public_key(path):
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("the public key must be Ed25519")
    return key


def generate_keypair(private_path, public_path, force=False):
    private_path = Path(private_path)
    public_path = Path(public_path)
    if not force and (private_path.exists() or public_path.exists()):
        raise FileExistsError("key file already exists; pass --force to overwrite")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    return key_id(public_key)


def sign_plugin(plugin_dir, private_key_path):
    plugin_dir = Path(plugin_dir)
    private_key = load_private_key(private_key_path)
    public_key = private_key.public_key()
    digest = plugin_digest(plugin_dir)
    signature = private_key.sign(digest.encode("ascii"))
    record = {
        "version": SIGNATURE_VERSION,
        "algorithm": "ed25519",
        "key_id": key_id(public_key),
        "digest": digest,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    (plugin_dir / SIGNATURE_NAME).write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    return record


def verify_plugin(plugin_dir, public_key_path=None, trusted_keys_dir=None):
    plugin_dir = Path(plugin_dir)
    signature_path = plugin_dir / SIGNATURE_NAME
    if not signature_path.is_file():
        raise ValueError(f"{signature_path} is missing")
    record = json.loads(signature_path.read_text(encoding="utf-8"))
    if record.get("version") != SIGNATURE_VERSION:
        raise ValueError("unsupported signature version")
    if record.get("algorithm") != "ed25519":
        raise ValueError("unsupported signature algorithm")
    digest = str(record.get("digest") or "")
    signature_text = str(record.get("signature") or "")
    signature_key_id = str(record.get("key_id") or "")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("signature digest is not a SHA-256 hex string")
    if not signature_text or not signature_key_id:
        raise ValueError("signature record is incomplete")
    if len(signature_key_id) != 16 or any(
        c not in "0123456789abcdef" for c in signature_key_id
    ):
        raise ValueError("signature key_id is not a 16-character hex string")

    if public_key_path:
        public_key = load_public_key(public_key_path)
    elif trusted_keys_dir:
        public_key = load_public_key(Path(trusted_keys_dir) / f"{signature_key_id}.pem")
    else:
        raise ValueError("pass --public-key or --trusted-keys")

    if key_id(public_key) != signature_key_id:
        raise ValueError("signature key_id does not match the trusted key")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("signature is not valid base64") from error
    try:
        public_key.verify(signature, digest.encode("ascii"))
    except InvalidSignature as error:
        raise ValueError("signature verification failed") from error

    actual_digest = plugin_digest(plugin_dir)
    if actual_digest != digest:
        raise ValueError("digest mismatch: plugin files changed after signing")
    return record


def build_parser():
    parser = argparse.ArgumentParser(description="Sign and verify Claude Code plugins.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="generate an Ed25519 key pair")
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    keygen.add_argument("--force", action="store_true")

    sign = subparsers.add_parser("sign", help="write .claude-plugin/signature.json")
    sign.add_argument("plugin")
    sign.add_argument("--private-key", required=True)

    verify = subparsers.add_parser("verify", help="verify a plugin signature")
    verify.add_argument("plugin")
    verify.add_argument("--public-key")
    verify.add_argument("--trusted-keys")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "keygen":
            identifier = generate_keypair(
                args.private_key, args.public_key, force=args.force
            )
            print(f"OK: generated Ed25519 key pair; key_id={identifier}")
        elif args.command == "sign":
            record = sign_plugin(args.plugin, args.private_key)
            print(f"OK: signed {args.plugin}; key_id={record['key_id']}")
        else:
            record = verify_plugin(
                args.plugin,
                public_key_path=args.public_key,
                trusted_keys_dir=args.trusted_keys,
            )
            print(f"OK: verified {args.plugin}; key_id={record['key_id']}")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
