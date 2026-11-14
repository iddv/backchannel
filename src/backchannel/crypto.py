"""Device identity, signatures and the exact byte strings that get signed."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .config import PROTO


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def canonical_key(key: object) -> str | None:
    """Canonical base64 of a 32-byte Ed25519 public key, or None. Different base64 spellings of the same key
    must not become different identities."""
    if not isinstance(key, str) or len(key) > 64:
        return None
    try:
        raw = b64d(key)
    except (ValueError, TypeError):
        return None
    return b64e(raw) if len(raw) == 32 else None


def fingerprint(pub_b64: str) -> str:
    h = base64.b32encode(hashlib.sha256(b64d(pub_b64)).digest()).decode()[:16]  # 80 bits
    return "-".join(h[i : i + 4] for i in range(0, 16, 4))


def norm_fp(ref: str) -> str:
    return ref.replace("-", "").replace(" ", "").upper()


def verify(pub_b64: str, sig_b64: str, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64d(pub_b64)).verify(b64d(sig_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class Identity:
    def __init__(self, path: Path):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            for attempt in range(20):  # another session may be mid-way through writing it
                try:
                    raw = b64d(json.loads(path.read_text())["private"])
                    break
                except (ValueError, KeyError):
                    if attempt == 19:
                        raise
                    time.sleep(0.05)
            self.key = Ed25519PrivateKey.from_private_bytes(raw)
        else:  # first run: we won the race to create it
            self.key = Ed25519PrivateKey.generate()
            raw = self.key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
            )
            with os.fdopen(fd, "w") as f:
                json.dump({"private": b64e(raw)}, f)
        self.pub = b64e(self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.fp = fingerprint(self.pub)

    def sign(self, data: bytes) -> str:
        return b64e(self.key.sign(data))


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def hello_payload(nonce: str, name: str, port: int, boot: str) -> bytes:
    return f"{PROTO}-HELLO\n{nonce}\n{name}\n{port}\n{boot}".encode()


def request_payload(host_key: str, boot: str, method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    # bound to one host and one host process lifetime: no cross-host forwarding, no replay after restart
    return f"{PROTO}-REQ\n{host_key}\n{boot}\n{method}\n{path}\n{ts}\n{nonce}\n{sha(body)}".encode()


def response_payload(host_key: str, req_nonce: str, status: int, body: bytes) -> bytes:
    return f"{PROTO}-RESP\n{host_key}\n{req_nonce}\n{status}\n{sha(body)}".encode()
