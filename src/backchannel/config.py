"""Limits, configuration, errors and small helpers shared by every module."""

from __future__ import annotations

import contextlib
import getpass
import ipaddress
import json
import logging
import os
import re
import secrets
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("backchannel")

PROTO = "BC1"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,23}")
FP_LIKE_RE = re.compile(r"[a-z2-7]{4}-?[a-z2-7]{4}-?[a-z2-7]{4}-?[a-z2-7]{4}")
MAX_BODY = 8 * 1024  # one message body
MAX_REQUEST = 32 * 1024  # one HTTP request body
SEALED_PREFIX = "bc1e:"  # a message body that starts with this is end-to-end encrypted
MAX_SEALED = 24 * 1024  # one sealed body: the text in base64 plus a wrapped key per reader
MAX_RECIPIENTS = 64  # readers one sealed message can be encrypted for
CHECK_MAX_MESSAGES = 20  # per check_messages call
CHECK_MAX_BYTES = 24 * 1024
SEND_PER_MINUTE = 20
SEND_PER_DAY = 300
PAIR_PER_MINUTE_PER_IP = 5
MAX_PENDING = 10
PENDING_TTL = 600
CLOCK_SKEW_MS = 120_000
NONCE_TTL = 300
NONCE_MAX = 20_000
RETENTION_DAYS = 14
RETENTION_MAX = 5000
WAIT_HOLD = 45  # seconds one long-poll is held open
WAIT_PER_PEER = 4  # concurrent long-polls per key (one per watching session)
WAIT_TOTAL = 32
SCAN_EVERY = 600  # at most one address sweep per process in this many seconds
REBIND_EVERY = 15  # how often the host looks for changed interfaces / a freed port
HEARTBEAT = 60  # every session tells the host it is still open this often
SESSION_TTL = 180  # a session silent for this long is treated as closed
BROADCAST_TTL = 3600  # a message to "all" stays new for each open session this long, not just the first reader
SID_RE = re.compile(r"[0-9a-f]{12}")
CONV_RE = re.compile(r"[0-9a-f]{8}")  # a conversation's id; its messages are addressed to "#<id>"
CONV_MINUTES = 30  # how long a conversation lasts unless its starter says otherwise
CONV_MAX_MINUTES = 240
CONV_MAX_MEMBERS = 16
CONV_PAGE = 30  # messages one say/listen hands over
CONV_MAX_OPEN = 20  # conversations one person can have going at once
OVERLAY_PREFIXES = ("zt", "feth", "tailscale")
CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _env(name: str, default: str = "") -> str:
    v = os.environ.get(name, "").strip()
    # an unset plugin userConfig value can arrive as the literal placeholder
    return default if not v or v.startswith("${") else v


def _settings() -> dict:
    """Settings from ~/.config/backchannel/config.json, for apps whose plugins can't ask the user for any
    (role, name, port, bind). The environment wins over the file."""
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    with contextlib.suppress(OSError, ValueError):
        d = json.loads((base / "backchannel" / "config.json").read_text())
        if isinstance(d, dict):
            return {k: str(v) for k, v in d.items() if isinstance(v, (str, int))}
    return {}


def valid_name(n: object) -> bool:
    return isinstance(n, str) and bool(NAME_RE.fullmatch(n)) and n != "all" and not FP_LIKE_RE.fullmatch(n)


def as_conv(v: object) -> str:
    """A conversation id from the network or the agent ('#' in front is fine), or ''."""
    v = v.strip().lstrip("#").lower() if isinstance(v, str) else ""
    return v if CONV_RE.fullmatch(v) else ""


def as_sid(v: object) -> str:
    """A session id from the network, or '' (older clients have none and behave as one shared session)."""
    return v if isinstance(v, str) and SID_RE.fullmatch(v) else ""


def _norm_name(raw: str) -> str:
    n = re.sub(r"[^a-z0-9-]+", "-", raw.strip().lower()).strip("-")[:24]
    return n if valid_name(n) else "anon"


@dataclass(frozen=True)
class Config:
    """Everything that comes from the environment, read once at startup and passed to whoever needs it."""

    role: str
    name: str
    port: int
    bind: str  # overlay | private | comma-separated IPs
    data: Path
    session: str  # one id per Claude Code session (each runs its own copy of the server); the watcher inherits it
    wake: bool = True  # may the app's hooks wake this session, or keep it going, when something arrives?

    @classmethod
    def from_env(cls) -> Config:
        sid, saved = _env("BACKCHANNEL_SESSION"), _settings()
        try:
            port = int(_env("BACKCHANNEL_PORT", saved.get("port", "8787")))
        except ValueError:
            raise SystemExit("BACKCHANNEL_PORT must be a number") from None
        home = str(Path.home() / ".local/share/backchannel")
        return cls(
            role=_env("BACKCHANNEL_ROLE", saved.get("role", "client")).lower(),
            name=_norm_name(_env("BACKCHANNEL_NAME", saved.get("name") or getpass.getuser())),
            port=port,
            bind=_env("BACKCHANNEL_BIND", saved.get("bind", "overlay")),
            data=Path(_env("BACKCHANNEL_DATA", _env("CLAUDE_PLUGIN_DATA", home))),
            session=sid if SID_RE.fullmatch(sid) else secrets.token_hex(6),
            wake=_env("BACKCHANNEL_WAKE", saved.get("wake", "on")).lower() not in ("off", "no", "false", "0"),
        )


class BCError(Exception):
    """An error whose message is meant for the user. `code` is the machine-readable reason, when the caller
    needs to branch on it: never match on the message text."""

    def __init__(self, message: str, code: str = "") -> None:
        super().__init__(message)
        self.code = code


class StaleHost(BCError):
    """The host process changed between our hello and our request; a fresh hello fixes it."""


class Reject(Exception):
    """Host side: refuse a request before it is authenticated. Only the short code goes back, unsigned."""

    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code, self.status = code, status


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("backchannel: %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False


def prepare_data_dir(data: Path) -> None:
    # process-wide on purpose: SQLite creates its -wal and -shm files itself, and they must be private from birth
    os.umask(0o077)
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    with contextlib.suppress(OSError):
        os.chmod(data, 0o700)


def write_private(path: Path, text: str) -> None:
    """Atomic write, mode 0600."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
