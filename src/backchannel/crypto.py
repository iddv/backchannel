"""Device identity, signatures, the exact byte strings that get signed, and end-to-end sealing of messages."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import MAX_BODY, MAX_RECIPIENTS, MAX_SEALED, PROTO, SEALED_PREFIX, BCError


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
        # the same key in its X25519 form, for decrypting: the first half of SHA-512(seed) is the Ed25519 scalar
        self.xkey = X25519PrivateKey.from_private_bytes(hashlib.sha512(raw).digest()[:32])

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


# ---------------------------------------------------------------- end-to-end sealing
#
# A sealed message is readable only by the people it is addressed to and provably written by its sender, so
# whatever relays or stores it (the host today) can neither read nor alter it. Everyone's existing Ed25519
# identity key doubles as their encryption key (converted to X25519), so there is nothing extra to exchange.
#
#   head   = "BC1-MSG" / room (the host's key) / sender key / to / time / one-time public key
#   ct     = ChaCha20-Poly1305(random message key, nonce, text, aad=head)
#   keys   = for each reader (and the sender): the message key, encrypted to them (X25519 + HKDF), aad=head
#   sig    = Ed25519 signature by the sender over head and the hash of nonce+ct
#
# Binding head into every encryption means a message can't be re-signed under another name, moved to another
# recipient or replayed into another backchannel without failing to open.

_P = 2**255 - 19


class SealError(BCError):
    """A sealed message that can't be opened or doesn't check out. The text is shown in place of the message."""


def _x_public(ed_pub: str) -> X25519PublicKey:
    """The X25519 form of an Ed25519 public key (RFC 7748 birational map: u = (1+y)/(1-y))."""
    y = int.from_bytes(b64d(ed_pub), "little") & ((1 << 255) - 1)
    if y >= _P or y == 1:
        raise ValueError("not a usable key")
    return X25519PublicKey.from_public_bytes(((1 + y) * pow(1 - y, -1, _P) % _P).to_bytes(32, "little"))


def _raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _wrap_key(shared: bytes, eph: bytes, reader: str) -> ChaCha20Poly1305:
    info = f"{PROTO}-WRAP\n".encode() + eph + b64d(reader)
    return ChaCha20Poly1305(HKDF(hashes.SHA256(), 32, None, info).derive(shared))


def _head(room: str, sender: str, to: str, ts: str, eph: str) -> bytes:
    return f"{PROTO}-MSG\n{room}\n{sender}\n{to}\n{ts}\n{eph}".encode()


def is_sealed(body: object) -> bool:
    return isinstance(body, str) and body.startswith(SEALED_PREFIX)


def seal(ident: Identity, room: str, to: str, readers: list[str], text: str) -> str:
    """Encrypt `text` for `readers` (public keys) and sign it. The sender can always read their own message."""
    if len(text.encode()) > MAX_BODY:
        raise BCError(f"Message too long (max {MAX_BODY // 1024} KiB).")
    readers = sorted({*readers, ident.pub})
    if len(readers) > MAX_RECIPIENTS:
        raise BCError(f"Too many recipients to encrypt for (max {MAX_RECIPIENTS}).")
    one_time = X25519PrivateKey.generate()
    eph_raw = _raw(one_time.public_key())
    ts, eph, nonce, key = str(int(time.time() * 1000)), b64e(eph_raw), os.urandom(12), os.urandom(32)
    head = _head(room, ident.pub, to, ts, eph)
    ct = ChaCha20Poly1305(key).encrypt(nonce, text.encode(), head)
    keys = {}
    for r in readers:
        try:
            wrap = _wrap_key(one_time.exchange(_x_public(r)), eph_raw, r)
        except ValueError:
            raise BCError("One of the recipients has a key that can't be encrypted to.") from None
        keys[r] = b64e(wrap.encrypt(bytes(12), key, head))  # each wrapping key is used exactly once
    env = {
        "v": 1,
        "from": ident.pub,
        "to": to,
        "ts": ts,
        "eph": eph,
        "n": b64e(nonce),
        "ct": b64e(ct),
        "keys": keys,
        "sig": ident.sign(head + b"\n" + sha(nonce + ct).encode()),
    }
    return SEALED_PREFIX + json.dumps(env, separators=(",", ":"))


def unseal(ident: Identity, room: str, body: str) -> dict:
    """Open a sealed message: {"sender": key, "to": ..., "ts": seconds, "text": ...}. The caller still has to
    check that the sender key is who the message claims to be from. Raises SealError."""
    try:
        if len(body) > MAX_SEALED:
            raise ValueError
        env = json.loads(body[len(SEALED_PREFIX) :])
        sender, to, ts, eph = canonical_key(env["from"]), env["to"], env["ts"], env["eph"]
        if env["v"] != 1 or not sender or not all(isinstance(v, str) for v in (to, ts, eph, env["sig"])):
            raise ValueError
        if not ts.isdigit() or len(ts) > 15 or not isinstance(env["keys"], dict):
            raise ValueError
        nonce, ct, eph_raw = b64d(env["n"]), b64d(env["ct"]), b64d(eph)
        mine = env["keys"].get(ident.pub)
        wrapped = b64d(mine) if isinstance(mine, str) else None
    except (ValueError, KeyError, TypeError, RecursionError):
        raise SealError("it is malformed") from None
    head = _head(room, sender, to, ts, eph)
    if not verify(sender, env["sig"], head + b"\n" + sha(nonce + ct).encode()):
        raise SealError("its signature is wrong")
    if wrapped is None:
        raise SealError("it wasn't encrypted for this device")
    try:
        shared = ident.xkey.exchange(X25519PublicKey.from_public_bytes(eph_raw))
        key = _wrap_key(shared, eph_raw, ident.pub).decrypt(bytes(12), wrapped, head)
        text = ChaCha20Poly1305(key).decrypt(nonce, ct, head).decode()
    except (InvalidTag, ValueError):
        raise SealError("it doesn't decrypt") from None
    return {"sender": sender, "to": to, "ts": int(ts) / 1000, "text": text}
