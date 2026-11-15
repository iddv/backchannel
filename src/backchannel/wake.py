"""Being told when something arrives without asking: the wait behind the watcher, a registry that lets a hook
find the session it belongs to, and the hooks each client (Claude Code, Codex, Gemini) can run."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import psutil

from .client import Client
from .config import PENDING_TTL, WAIT_HOLD, BCError, Config, StaleHost, log, valid_name, write_private
from .crypto import Identity
from .store import Store

CHECK = "Tell your user; the backchannel check_messages tool shows it."

# ---------------------------------------------------------------- the registry
#
# A hook is a separate process started by the agent's app. It knows nothing about the backchannel server that
# the same app started, yet has to act for that exact session. Each server therefore leaves a note here saying
# who it is and which processes it descends from; a hook finds the server it shares its closest ancestor with
# (the app itself).


def registry() -> Path:
    """A directory only this user can touch: the per-user runtime directory where there is one, else one under
    the temp directory, which is refused if someone else got there first."""
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    d = Path(runtime) / "backchannel" if runtime else Path(tempfile.gettempdir()) / f"backchannel-{os.getuid()}"
    d.mkdir(mode=0o700, exist_ok=True)
    st = d.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise OSError(f"{d} is not private to this user")
    return d


def _ancestors(limit: int = 12) -> list[int]:
    out: list[int] = []
    with contextlib.suppress(psutil.Error):
        for p in psutil.Process().parents()[:limit]:
            if p.pid > 1:
                out.append(p.pid)
    return out


def register(cfg: Config) -> Path:
    """Called by a session's server when it starts."""
    path = registry() / f"{os.getpid()}.json"
    entry = {
        "pid": os.getpid(),
        "ancestors": _ancestors(),
        "config": {"role": cfg.role, "name": cfg.name, "port": cfg.port, "bind": cfg.bind, "data": str(cfg.data)},
        "wake": cfg.wake,
        "session": cfg.session,
    }
    write_private(path, json.dumps(entry))
    return path


def entries() -> list[dict]:
    out = []
    for f in registry().glob("*.json"):
        try:
            e = json.loads(f.read_text())
            if psutil.pid_exists(e["pid"]) and isinstance(e["ancestors"], list) and isinstance(e["config"], dict):
                out.append({**e, "path": f})
                continue
        except (OSError, ValueError, KeyError, TypeError):
            pass
        with contextlib.suppress(OSError):
            f.unlink()  # its server is gone
    return out


def find(patience: float = 0) -> dict | None:
    """The entry of the server that belongs to the same session as this process, waiting up to `patience` seconds
    for it to appear (a hook can run before the server has started)."""
    mine, deadline = _ancestors(), time.monotonic() + patience
    while True:
        best, depth = None, 99
        for e in entries():
            # the app is at most a wrapper or two above its server, and a few above its hook
            shared = [i for i, pid in enumerate(mine[:5]) if pid in e["ancestors"][:3]]
            if shared and shared[0] < depth:
                best, depth = e, shared[0]
        if best or time.monotonic() >= deadline:
            return best
        time.sleep(0.5)


def note(entry: dict, **fields) -> None:
    """Add to a session's entry (which client can wake it, what it has been told about)."""
    with contextlib.suppress(OSError, ValueError):
        current = json.loads(entry["path"].read_text())
        write_private(entry["path"], json.dumps({**current, **fields}))
        entry.update(fields)


def config_of(entry: dict) -> Config:
    c = entry["config"]
    return Config(c["role"], c["name"], int(c["port"]), c["bind"], Path(c["data"]), entry["session"])


# ---------------------------------------------------------------- waiting for something to arrive


def _line(unread: int, who: list[str], requests: int = 0) -> str:
    bits = []
    if unread:
        bits.append(f"{unread} new message(s){' from ' + ', '.join(who) if who else ''}")
    if requests:
        bits.append(f"{requests} request(s) to join")
    return " and ".join(bits)


async def host_activity(cfg: Config, alive: Callable[[], bool], after: int = 0, once: bool = False):
    """Host side: watch the local store for unread messages and new join requests. Returns (code, text, latest
    message id); code 0 means something arrived. With `once`, look a single time and return."""
    store = Store(cfg.data / "backchannel.db")
    told_file = cfg.data / "announced.json"  # each join request wakes a watcher once, however long it stays pending

    def fresh_requests() -> list[str]:
        told: list = []
        with contextlib.suppress(OSError, ValueError):
            told = json.loads(told_file.read_text())
        told = told if isinstance(told, list) else []
        now = [f"{p.key}:{p.updated}" for p in store.peers("pending") if time.time() - p.updated < PENDING_TTL]
        new = [t for t in now if t not in told]
        if new and not once:
            with contextlib.suppress(OSError):
                write_private(told_file, json.dumps(now))
        return new

    def poll(touch: bool) -> tuple[dict, list[str]]:
        if touch:
            store.touch(cfg.name, cfg.session)
        waiting = store.waiting(cfg.name, after, sid=cfg.session)
        conv = store.conv_unread(cfg.name, cfg.session, after=after)
        waiting["unread"] += conv["count"]
        waiting["from"] = sorted({*waiting["from"], *conv["from"]})
        waiting["latest"] = max(waiting["latest"], conv["latest"])
        return waiting, fresh_requests()

    touched = float("-inf")
    try:
        while alive():
            touch = not once and time.monotonic() - touched >= 20
            if touch:
                touched = time.monotonic()
            waiting, fresh = await asyncio.to_thread(poll, touch)
            if waiting["unread"] or fresh:
                return 0, _line(waiting["unread"], waiting["from"], len(fresh)), waiting["latest"]
            if once:
                break
            await asyncio.sleep(2)
        return 1, "", 0
    finally:
        store.db.close()


async def client_activity(cfg: Config, ident: Identity, alive: Callable[[], bool], after: int = 0, once: bool = False):
    """Client side: long-poll the pinned host. Never looks for a host by sweeping addresses. Returns like
    host_activity; code 2 or 3 means watching can't work, with the reason as text."""
    client = Client(ident, cfg.name, cfg.data, cfg.port, cfg.session)
    try:
        if not client.known():
            return 2, "not connected to a host yet, so there is nothing to watch. Check messages first.", 0
        delay, host = 5, None
        while alive():
            try:
                host = host or await client.ensure_host(sweep=False)
                hold = 0 if once else WAIT_HOLD
                seen = max(client.seen(host["key"]), after)
                r = await client.post(host, "wait", {"after": seen, "timeout": hold}, timeout=hold + 15)
            except StaleHost:
                host = None
                continue
            except BCError as e:
                host = None
                if e.code == "unknown_op":
                    return (
                        3,
                        "this host runs an older backchannel without push. Fall back to checking on an interval.",
                        0,
                    )
                if e.code in ("declined", "host_key_changed"):
                    return 2, str(e), 0
                if once:
                    break
                # offline, not accepted yet, rate limited, too many watchers: quietly try again later
                await asyncio.sleep(delay)
                delay = min(delay * 2, 120)
                continue
            delay = 5
            if isinstance(r.get("unread"), int) and r["unread"] > 0:
                who = [n for n in r.get("from") or [] if valid_name(n)] if isinstance(r.get("from"), list) else []
                return 0, _line(r["unread"], who), r["latest"] if isinstance(r.get("latest"), int) else 0
            if once:
                break
        return 1, "", 0
    finally:
        await client.aclose()


async def activity(cfg: Config, ident: Identity, alive: Callable[[], bool], after: int = 0, once: bool = False):
    if cfg.role == "host":
        return await host_activity(cfg, alive, after, once)
    return await client_activity(cfg, ident, alive, after, once)


# ---------------------------------------------------------------- what the app's hooks run


def _stdin() -> dict:
    with contextlib.suppress(ValueError, OSError):
        if not sys.stdin.isatty():
            d = json.loads(sys.stdin.read() or "{}")
            return d if isinstance(d, dict) else {}
    return {}


def _alive(entry: dict) -> Callable[[], bool]:
    parent = os.getppid()
    return lambda: psutil.pid_exists(entry["pid"]) and os.getppid() == parent


async def hook(event: str, app: str) -> int:
    """`backchannel hook <event> <app>`: run by Claude Code, Codex or Gemini at points in a session. A hook must
    never get in the user's way, so anything unexpected ends quietly."""
    given = _stdin()
    silent = "{}" if app == "gemini" else ""  # Gemini wants JSON back even when there is nothing to say
    entry = find(patience=8 if event in ("session-start", "wake") else 0)
    if entry is None:
        print(silent, end="")
        return 0
    if entry.get("wake") is False and event != "session-start":  # the user turned waking off; still say what waits
        print(silent, end="")
        return 0
    cfg = config_of(entry)
    ident = Identity(cfg.data / "identity.json")
    after = entry.get("announced") if isinstance(entry.get("announced"), int) else 0

    if event == "wake":
        # Claude Code: runs in the background and, by exiting with code 2, wakes the session even when it is idle
        lock = entry["path"].with_suffix(".waker")
        with contextlib.suppress(OSError, ValueError):
            if psutil.pid_exists(int(lock.read_text())):
                return 0  # this session already has one
        write_private(lock, str(os.getpid()))
        note(entry, wakes=app)
        await asyncio.sleep(3)  # at session start the other hook is just now saying what is already waiting
        with contextlib.suppress(OSError, ValueError, TypeError):
            after = max(after, int(json.loads(entry["path"].read_text()).get("announced") or 0))
        try:
            code, text, latest = await activity(cfg, ident, _alive(entry), after)
        finally:
            with contextlib.suppress(OSError):
                lock.unlink()
        if code != 0:
            return 0
        note(entry, announced=max(after, latest))
        print(f"backchannel: {text}. {CHECK}", file=sys.stderr)
        return 2

    code, text, latest = await asyncio.wait_for(activity(cfg, ident, lambda: True, after, once=True), 10)
    if event == "session-start":
        told = {"announced": max(after, latest)} if code == 0 else {}  # so the waker doesn't repeat it
        if app == "codex" and isinstance(given.get("session_id"), str):
            told |= {"wakes": "codex", "thread": given["session_id"]}  # the server wakes this thread itself
        if told:
            note(entry, **told)
        if code != 0:
            print(silent, end="")
            return 0
        said = f"backchannel: {text} waiting for you. {CHECK}"
        if app == "gemini":
            print(json.dumps({"injectSteps": [{"systemMessage": {"systemMessage": said}}]}))
        else:
            print(said)
        return 0

    if event == "stop":
        # Codex and Gemini: something arrived while the agent was working, so it hears before it goes quiet
        again = given.get("stop_hook_active") is True or given.get("continuation_active") is True
        if code != 0 or again or (isinstance(given.get("executionNum"), int) and given["executionNum"] > 2):
            print(silent, end="")
            return 0
        note(entry, announced=max(after, latest))
        reason = f"backchannel: {text} arrived while you were working. {CHECK}"
        print(json.dumps({"decision": "continue" if app == "gemini" else "block", "reason": reason}))
        return 0
    print(silent, end="")
    return 0


async def codex_waker(cfg: Config, ident: Identity, path: Path) -> None:
    """Codex can be handed a message from outside (`codex queue`), which starts a turn when the session is idle.
    Once the session-start hook has told us which thread this is, keep watch and do that."""
    after = 0
    while True:
        try:
            entry = json.loads(path.read_text())  # noqa: ASYNC240  (a few hundred bytes, every few seconds)
            thread = entry.get("thread") if entry.get("wakes") == "codex" and cfg.wake else None
            if not isinstance(thread, str):
                await asyncio.sleep(3)
                continue
            after = max(after, entry["announced"] if isinstance(entry.get("announced"), int) else 0)
            code, text, latest = await activity(cfg, ident, lambda: True, after)
            if code != 0:  # can't watch right now (not connected, host too old): look again later
                await asyncio.sleep(60)
                continue
            after = max(after, latest)
            note({"path": path}, announced=after)
            proc = await asyncio.create_subprocess_exec(
                "codex", "queue", "--thread", thread, "--message", f"backchannel: {text}. {CHECK}",
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )  # fmt: skip
            await asyncio.wait_for(proc.wait(), 30)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # never take the session's server down over a wake-up
            log.debug("codex wake-up skipped: %s", e)
            await asyncio.sleep(15)
