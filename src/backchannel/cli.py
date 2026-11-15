"""Entry points: the stdio MCP server, the headless host, the watcher and the pairing commands."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import time

import httpx
import psutil

from .client import Client
from .config import (
    HEARTBEAT,
    PENDING_TTL,
    WAIT_HOLD,
    BCError,
    Config,
    StaleHost,
    log,
    prepare_data_dir,
    setup_logging,
    valid_name,
    write_private,
)
from .crypto import Identity
from .host import Host
from .net import bind_interfaces
from .store import Store
from .tools import ClientBackend, HostBackend, build_mcp

USAGE = """\
backchannel: pass messages and instructions between friends' AI agents on a private network.

Everyone runs this same program as a local stdio MCP server. One person picks the `host` role: their copy also
runs a small signed JSON relay (HTTP) and answers UDP discovery broadcasts. `client` copies find the host
automatically, ask the user to confirm it, ask the host to pair, and sign every request with a per-device Ed25519
key. Every relay response is signed by the host key the client pinned. Messages are end-to-end encrypted between
members, so the host relays and stores only ciphertext. MCP itself never goes over the network.

    backchannel           stdio MCP server (role from BACKCHANNEL_ROLE)
    backchannel serve     headless host (e.g. a homelab box)
    backchannel peers [accept <fingerprint> <name> | revoke <name|fingerprint>]
    backchannel status
    backchannel wait      block until something new arrives, print one line, exit
"""


def make_host(cfg: Config, ident: Identity, relay: bool = False) -> Host:
    return Host(ident, Store(cfg.data / "backchannel.db"), cfg.name, cfg.port, cfg.bind, relay)


async def heartbeat(cfg: Config, host: Host | None, client: Client | None) -> None:
    """Tell the host this session is still open, so conversations locked to it are known to be reachable."""
    while True:
        try:
            if host:
                await host.db(host.store.touch, cfg.name, cfg.session)
            elif client and (kh := client.known()) and not kh["declined"]:
                info = await client.hello(kh["addr"], timeout=2.5)  # the pinned address only: never go looking
                if info and info["key"] == kh["key"]:
                    await client.post({**kh, "boot": info["boot"]}, "ping", {})
        except (BCError, httpx.HTTPError, OSError) as e:  # offline, not paired yet, an older host: all expected
            log.debug("heartbeat skipped: %s", e)
        except Exception:
            log.exception("heartbeat failed")
        await asyncio.sleep(HEARTBEAT)


async def run_stdio(cfg: Config, ident: Identity) -> None:
    """The MCP server Claude Code talks to, plus what runs beside it: the heartbeat and, for a host, the relay."""
    if cfg.role == "host":
        host = make_host(cfg, ident)
        mcp = build_mcp(cfg, ident, HostBackend(cfg, host))

        async def relay() -> None:
            try:
                await host.serve(install_signal_handlers=False)
            except Exception:  # keep the local MCP session alive even if hosting fails
                log.exception("relay stopped")

        async with asyncio.TaskGroup() as tg:
            tasks = [tg.create_task(relay()), tg.create_task(heartbeat(cfg, host, None))]
            await mcp.run_stdio_async()
            for task in tasks:
                task.cancel()
        return
    if cfg.role != "client":
        log.warning("unknown role '%s', acting as client", cfg.role)
    client = Client(ident, cfg.name, cfg.data, cfg.port, cfg.session)
    try:
        async with asyncio.TaskGroup() as tg:
            task = tg.create_task(heartbeat(cfg, None, client))
            await build_mcp(cfg, ident, ClientBackend(cfg, client)).run_stdio_async()
            task.cancel()
    finally:
        await client.aclose()


# ---------------------------------------------------------------- wait: the watcher


def _launcher() -> tuple[int, int]:
    """Who started this watcher: our parent (uv) and its parent (the agent's shell). If either changes, the
    session that wanted the watch is gone and the watcher should stop rather than linger."""
    parent = os.getppid()
    with contextlib.suppress(psutil.Error):
        return parent, psutil.Process(parent).ppid()
    return parent, 0


def _say(line: str) -> None:
    """The one line the agent reads when the watcher fires."""
    print(f"backchannel: {line}", flush=True)


async def wait_host(cfg: Config) -> int:
    """Host side of `wait`: watch the local store for unread messages and new join requests."""
    store = Store(cfg.data / "backchannel.db")
    told_file = cfg.data / "announced.json"  # each join request wakes a watcher once, however long it stays pending

    def fresh_requests() -> list[str]:
        told: list = []
        with contextlib.suppress(OSError, ValueError):
            told = json.loads(told_file.read_text())
        told = told if isinstance(told, list) else []
        now = [f"{p.key}:{p.updated}" for p in store.peers("pending") if time.time() - p.updated < PENDING_TTL]
        new = [t for t in now if t not in told]
        if new:
            with contextlib.suppress(OSError):
                write_private(told_file, json.dumps(now))
        return new

    def poll(touch: bool) -> tuple[dict, list[str]]:
        if touch:
            store.touch(cfg.name, cfg.session)
        return store.waiting(cfg.name, sid=cfg.session), fresh_requests()

    parent, touched = _launcher(), float("-inf")
    while _launcher() == parent:
        touch = time.monotonic() - touched >= 20
        if touch:
            touched = time.monotonic()
        waiting, fresh = await asyncio.to_thread(poll, touch)
        if waiting["unread"] or fresh:
            bits = []
            if waiting["unread"]:
                bits.append(f"{waiting['unread']} new message(s) from {', '.join(waiting['from'])}")
            if fresh:
                bits.append(f"{len(fresh)} request(s) to join")
            _say(f"{' and '.join(bits)}. Run /backchannel:check.")
            return 0
        await asyncio.sleep(2)
    return 0


async def wait_client(cfg: Config, ident: Identity) -> int:
    """Client side of `wait`: long-poll the pinned host. Never looks for a host by sweeping addresses."""
    client = Client(ident, cfg.name, cfg.data, cfg.port, cfg.session)
    try:
        if not client.known():
            _say("not connected to a host yet, so there is nothing to watch. Run /backchannel:check first.")
            return 2
        parent, delay, host = _launcher(), 5, None
        while _launcher() == parent:
            try:
                host = host or await client.ensure_host(sweep=False)
                r = await client.post(
                    host, "wait", {"after": client.seen(host["key"]), "timeout": WAIT_HOLD}, timeout=WAIT_HOLD + 15
                )
            except StaleHost:
                host = None
                continue
            except BCError as e:
                host = None
                if e.code == "unknown_op":
                    _say("this host runs an older backchannel without push. Fall back to checking on an interval.")
                    return 3
                if e.code in ("declined", "host_key_changed"):
                    _say(str(e))
                    return 2
                # offline, not accepted yet, rate limited, too many watchers: quietly try again later
                await asyncio.sleep(delay)
                delay = min(delay * 2, 120)
                continue
            delay = 5
            if isinstance(r.get("unread"), int) and r["unread"] > 0:
                who = [n for n in r.get("from") or [] if valid_name(n)] if isinstance(r.get("from"), list) else []
                _say(f"{r['unread']} new message(s){' from ' + ', '.join(who) if who else ''}. Run /backchannel:check.")
                return 0
        return 0
    finally:
        await client.aclose()


# ---------------------------------------------------------------- pairing commands for a headless host


def peers_command(cfg: Config, args: list[str]) -> None:
    usage = "usage: peers [accept <fingerprint> <name> | revoke <name|fingerprint>]"
    store = Store(cfg.data / "backchannel.db")
    if not args:
        for p in store.peers():
            print(f"{p.status:9} {p.name:24} {p.fp}  {p.addr}")
        return
    action, ref = args[0], args[1] if len(args) > 1 else ""
    if action == "accept" and len(args) >= 3:
        matches = store.by_fp(ref)
        if len(matches) != 1:
            sys.exit(f"no single key has fingerprint '{ref}'; run 'peers' to list everyone.")
        p = matches[0]
        if not store.accept(p.key, args[2].strip().lower(), ("pending", "revoked")):
            sys.exit(f"{p.fp} is asking to join as '{p.name}', not '{args[2]}'; run 'peers' again and check.")
        print(f"accepted {p.name} ({p.fp})")
    elif action == "revoke" and ref:
        matches = store.by_name_or_fp(ref)
        if not matches:
            sys.exit(f"nobody matches '{ref}'; run 'peers' to list everyone.")
        for p in matches:
            store.revoke(p.key)
            print(f"revoked {p.name} ({p.fp})")
    else:
        sys.exit(usage)


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    setup_logging()
    cfg = Config.from_env()
    prepare_data_dir(cfg.data)
    ident = Identity(cfg.data / "identity.json")
    command = argv[0] if argv else ""
    if not command:
        asyncio.run(run_stdio(cfg, ident))
    elif command == "serve":
        asyncio.run(make_host(cfg, ident, relay=True).serve(install_signal_handlers=True))
    elif command == "wait":
        sys.exit(asyncio.run(wait_host(cfg) if cfg.role == "host" else wait_client(cfg, ident)))
    elif command == "status":
        print(f"name {cfg.name}, key {ident.fp}, data {cfg.data}")
        for ifn, i in bind_interfaces(cfg.bind):
            print(f"  invite: bc1:{i.ip}:{cfg.port}:{ident.fp}  ({ifn})")
    elif command == "peers":
        peers_command(cfg, argv[1:])
    else:
        sys.exit(USAGE)
