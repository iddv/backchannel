"""Shared machinery for the tests: real backchannel processes, an MCP client to drive them, and a hand-rolled
signing client for the attacks the real client won't make."""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

from backchannel.crypto import Identity, fingerprint, request_payload
from backchannel.store import Store

ROOT = Path(__file__).resolve().parent.parent

BIND = os.environ.get("BACKCHANNEL_BIND", "127.0.0.1")
# the installed package in this environment; test_packaging.py covers the command line the plugin really uses
LAUNCH = [sys.executable, "-m", "backchannel"]
_ports = itertools.count(int(os.environ.get("BC_TEST_PORT", "18787")), 7)


def next_port() -> int:
    """Every test gets its own port, so nothing depends on what ran before it."""
    return next(_ports)


def env_for(role: str, name: str, port: int, data: Path) -> dict:
    return {
        **os.environ,
        "BACKCHANNEL_ROLE": role,
        "BACKCHANNEL_NAME": name,
        "BACKCHANNEL_PORT": str(port),
        "BACKCHANNEL_DATA": str(data),
        "CLAUDE_PLUGIN_DATA": str(data),
        "BACKCHANNEL_BIND": BIND,
    }


def hello(port: int, **kw) -> httpx.Response:
    return httpx.get(f"http://127.0.0.1:{port}/hello", params={"nonce": "xxxxxxxx"}, trust_env=False, **kw)


def wait_listening(port: int, timeout: float = 30) -> dict:
    deadline = time.time() + timeout
    while True:
        try:
            return hello(port).json()
        except httpx.HTTPError:
            if time.time() > deadline:
                raise
            time.sleep(0.2)


def has_lan_interface() -> bool:
    return BIND != "127.0.0.1"


class Agent:
    """One backchannel stdio server plus an MCP client session talking to it. `answers` are queued replies to
    popups ("accept", "decline", "cancel", or an async callable returning one of those)."""

    def __init__(self, stack, role: str, name: str, data: Path, port: int, popups: bool = True):
        self.stack, self.role, self.name, self.data, self.port, self.popups = stack, role, name, data, port, popups
        self.answers: list = []
        self.prompts: list[str] = []

    async def _elicit(self, context, params):
        self.prompts.append(params.message)
        a = self.answers.pop(0) if self.answers else "cancel"
        if callable(a):
            a = await a()
        if a == "accept":
            field = "accept" if "Let them join" in params.message else "ok"
            return types.ElicitResult(action="accept", content={field: True})
        return types.ElicitResult(action=a)

    async def start(self) -> Agent:
        params = StdioServerParameters(
            command=LAUNCH[0], args=LAUNCH[1:], env=env_for(self.role, self.name, self.port, self.data)
        )
        errlog = self.stack.enter_context(open(os.devnull, "w"))  # noqa: SIM115  (the stack closes it)
        r, w = await self.stack.enter_async_context(stdio_client(params, errlog=errlog))
        self.s = await self.stack.enter_async_context(
            ClientSession(r, w, elicitation_callback=self._elicit if self.popups else None)
        )
        await self.s.initialize()
        return self

    async def call(self, tool: str, **args) -> str:
        res = await self.s.call_tool(tool, args)
        return res.content[0].text if res.content else ""

    async def key(self) -> str:
        return (await self.call("status")).split("key ")[1].split(".")[0]


class World:
    """The processes of one test. Everything is torn down when the test's `async with world(...)` block ends."""

    def __init__(self, stack, tmp: Path):
        self.stack, self.tmp, self.port = stack, tmp, next_port()
        self.procs: list[subprocess.Popen] = []

    async def agent(
        self, role: str, name: str, data: str | None = None, popups: bool = True, wait: bool = True
    ) -> Agent:
        a = await Agent(self.stack, role, name, self.tmp / (data or name), self.port, popups).start()
        if role == "host" and wait:
            wait_listening(self.port)
        return a

    async def pair(self, host: Agent, client: Agent) -> None:
        client.answers.append("accept")
        await client.call("check_messages")
        host.answers.append("accept")
        await host.call("check_messages")
        out = await client.call("check_messages")
        assert "No new messages" in out, out

    def spawn(self, command: str | list[str], **kw) -> subprocess.Popen:
        """A helper process in its own group, so the whole tree can be stopped."""
        p = subprocess.Popen(
            command,
            shell=isinstance(command, str),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            **kw,
        )
        self.procs.append(p)
        return p

    def stop(self, p: subprocess.Popen) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(p.pid, signal.SIGTERM)
        with contextlib.suppress(subprocess.TimeoutExpired):
            p.wait(10)

    def host_fp(self) -> str:
        return fingerprint(hello(self.port).json()["key"])


@contextlib.asynccontextmanager
async def world(tmp: Path):
    async with contextlib.AsyncExitStack() as stack:
        w = World(stack, tmp)
        try:
            yield w
        finally:
            for p in w.procs:
                w.stop(p)


def finished(p: subprocess.Popen, within: float) -> str | None:
    """The process's output if it exits in time, else None (and it keeps running)."""
    try:
        return p.communicate(timeout=within)[0].decode()
    except subprocess.TimeoutExpired:
        return None


class Raw:
    """A client that signs requests itself, for the attacks the real client won't make."""

    def __init__(self, data: Path, port: int):
        data.mkdir(parents=True, exist_ok=True)
        self.ident, self.port = Identity(data / "identity.json"), port

    def post(
        self,
        op: str,
        payload: dict,
        key: str | None = None,
        headers_override: dict | None = None,
        reuse: dict | None = None,
        timeout: float = 20,
    ):
        url = f"http://127.0.0.1:{self.port}/api/{op}"
        with httpx.Client(trust_env=False, timeout=timeout) as c:
            if reuse:
                return c.post(url, content=reuse["body"], headers=reuse["headers"]), reuse
            h = hello(self.port).json()
            body = json.dumps(payload).encode()
            ts, nonce = str(int(time.time() * 1000)), secrets.token_urlsafe(16)
            sig = self.ident.sign(request_payload(h["key"], h["boot"], "POST", f"/api/{op}", ts, nonce, body))
            headers = {
                "content-type": "application/json",
                "x-bc-key": key or self.ident.pub,
                "x-bc-ts": ts,
                "x-bc-nonce": nonce,
                "x-bc-sig": sig,
                **(headers_override or {}),
            }
            return c.post(url, content=body, headers=headers), {"body": body, "headers": headers}


class Relay:
    """A headless host process, with direct access to its database for arranging state."""

    def __init__(self, tmp: Path, name: str = "relay"):
        self.data, self.port, self.name = tmp / "relay", next_port(), name
        self.proc = subprocess.Popen(
            [*LAUNCH, "serve"], env=env_for("host", name, self.port, self.data), stderr=subprocess.DEVNULL
        )
        self.hello = wait_listening(self.port)
        self.store = Store(self.data / "backchannel.db")
        self._n = 0

    def raw(self, tmp: Path) -> Raw:
        self._n += 1
        return Raw(tmp / f"raw{self._n}", self.port)

    def member(self, tmp: Path, name: str) -> Raw:
        """A client the host has already accepted."""
        r = self.raw(tmp)
        self.store.request_pairing(r.ident.pub, name, "127.0.0.1")
        assert self.store.accept(r.ident.pub, name)
        return r

    def stop(self) -> None:
        self.proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.proc.wait(10)


def respell(key: str) -> str:
    """Same 32 bytes, different base64 text (flip an unused padding bit)."""
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return key[:42] + alpha[alpha.index(key[42]) ^ 1] + key[43:]
