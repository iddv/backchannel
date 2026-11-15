"""Who is on the backchannel and which key is theirs: what a message is encrypted to, and what decides whether a
received one really came from the name on it."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import BCError, valid_name, write_private
from .crypto import Identity, SealError, canonical_key, fingerprint, is_sealed, unseal


@dataclass(frozen=True)
class Member:
    name: str
    key: str
    e2e: bool  # has a version that can read encrypted messages (0.7 or later)
    host: bool = False
    relay: bool = False  # a headless host: nobody reads messages there


def parse_roster(peers: object) -> dict[str, Member] | None:
    """The member list from a host, validated. None if the host is older than 0.7 and doesn't hand out keys."""
    out: dict[str, Member] = {}
    for p in peers if isinstance(peers, list) else []:
        if not isinstance(p, dict) or not valid_name(p.get("name")):
            continue
        key = canonical_key(p.get("key"))
        if not key:
            return None
        out[p["name"]] = Member(p["name"], key, p.get("e2e") is True, p.get("host") is True, p.get("relay") is True)
    return out or None


def readers(roster: dict[str, Member], me: str, to: str) -> list[Member]:
    """The people a message to `to` is for (not counting the sender)."""
    if to == "all":
        return [m for m in roster.values() if m.name != me and not m.relay]
    if to == me:
        raise BCError("That is your own name; pick someone else, or 'all'.")
    if to not in roster:
        others = sorted(n for n in roster if n != me)
        raise BCError(f"Unknown recipient '{to[:30]}'. Known: {', '.join(['all', *others])}.")
    if roster[to].relay:
        raise BCError(f"'{to}' is a headless host; nobody reads messages there.")
    return [roster[to]]


def behind(for_: list[Member], to: str) -> str:
    """What to tell a sender about a message that won't be read yet: nobody is there, or readers are still on a
    version that can't decrypt."""
    if to == "all" and not for_:
        return " Nobody else is on the backchannel yet, so nobody will get it."
    names = sorted(m.name for m in for_ if not m.e2e)
    return f" {', '.join(names)} can't read it until they update to backchannel 0.7." if names else ""


def describe(roster: dict[str, Member], me: str) -> str:
    lines = []
    for m in roster.values():
        tags = (" (host)" if m.host else "") + (" (you)" if m.name == me else "")
        state = ""
        if m.relay:
            state = ", relay only: reads nothing"
        elif not m.e2e and m.name != me:
            state = ", can't read messages until they update to backchannel 0.7"
        lines.append(f"{m.name}{tags} key {fingerprint(m.key)}{state}")
    return "\n".join(lines)


class Pins:
    """A client's own record of each member's key. The host hands out the keys, so this is what makes it visible
    if the host later swaps one."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self, room: str) -> dict[str, str]:
        with contextlib.suppress(OSError, ValueError, TypeError, AttributeError):
            d = json.loads(self.path.read_text())
            if d.get("host") == room and isinstance(d.get("peers"), dict):
                return {n: k for n, k in d["peers"].items() if valid_name(n) and canonical_key(k) == k}
        return {}

    def update(self, room: str, roster: dict[str, Member], me: str) -> list[str]:
        """Remember what the host says now; return what the user should hear about (keys that changed)."""
        pins, notes = self.load(room), []
        before = dict(pins)
        for m in roster.values():
            if m.name == me:
                continue
            old = pins.get(m.name)
            if old and old != m.key:
                notes.append(
                    f"NOTE: {m.name} now has a different key ({fingerprint(m.key)}, was {fingerprint(old)}). "
                    f"That is normal if they reinstalled or moved to a new machine. If they didn't, someone else "
                    f"may be using their name: check with them before trusting messages from {m.name}."
                )
            pins[m.name] = m.key
        if pins != before:
            with contextlib.suppress(OSError):
                write_private(self.path, json.dumps({"host": room, "peers": pins}))
        return notes


def open_rows(ident: Identity, room: str, me: str, rows: list[dict], key_of: Callable[[str], str | None]) -> list[dict]:
    """Decrypt and check `rows`. Only a message that was end-to-end encrypted and checks out is shown; the text of
    anything else is replaced by the reason."""
    out = []
    for m in rows:
        try:
            if not is_sealed(m["body"]):
                raise SealError(
                    f"it was not end-to-end encrypted, so it was sent from a backchannel older than 0.7 or didn't "
                    f"come from {m['sender']} at all"
                )
            o = unseal(ident, room, m["body"])
            if o["sender"] != (ident.pub if m["sender"] == me else key_of(m["sender"])):
                raise SealError(f"it was signed by a key that isn't {m['sender']}'s current one")
            if o["to"] != m["recipient"] or (o["to"] not in ("all", me) and m["sender"] != me):
                raise SealError("it was addressed to someone else")
            out.append({**m, "ts": o["ts"], "body": o["text"], "ok": True})
        except SealError as e:
            out.append({**m, "body": f"[This message is not shown: {e}.]", "ok": False})
    return out
