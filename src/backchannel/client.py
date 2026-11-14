"""The client side: finding and pinning a host, and signed requests to it."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import secrets
import subprocess
import time
from pathlib import Path

import httpx
from mcp.server.fastmcp import Context
from pydantic import BaseModel, Field

from .config import SCAN_EVERY, BCError, StaleHost, log, valid_name, write_private
from .crypto import (
    Identity,
    canonical_key,
    fingerprint,
    hello_payload,
    norm_fp,
    request_payload,
    response_payload,
    verify,
)
from .messages import clean
from .net import parse_address, private_interfaces


class Confirm(BaseModel):
    ok: bool = Field(default=False, title="Connect", description="Tick to connect to this host, then submit.")


def can_elicit(ctx: Context) -> bool:
    params = ctx.session.client_params
    return bool(params and params.capabilities and params.capabilities.elicitation is not None)


class Client:
    def __init__(self, ident: Identity, name: str, data_dir: Path, port: int, sid: str = ""):
        self.ident, self.name, self.port, self.sid = ident, name, port, sid
        self.hosts_file = data_dir / "known_host.json"
        self.seen_file = data_dir / "seen.json"
        self.last_scan = 0.0
        self._http: httpx.AsyncClient | None = None

    def http(self) -> httpx.AsyncClient:
        """One HTTP client for the life of this object. verify=False only skips loading the CA bundle: every URL
        here is plain http to a private address, and trust comes from the Ed25519 signatures, not TLS."""
        if self._http is None:
            self._http = httpx.AsyncClient(
                trust_env=False,
                follow_redirects=False,
                verify=False,  # noqa: S501  (plain http only; see the docstring)
                limits=httpx.Limits(max_connections=160, max_keepalive_connections=4, keepalive_expiry=3),
            )
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    def _seen(self, host_key: str) -> dict:
        with contextlib.suppress(OSError, ValueError, TypeError, AttributeError):
            d = json.loads(self.seen_file.read_text())
            if d.get("key") == host_key and isinstance(d.get("ids"), dict):
                return {k: v for k, v in d["ids"].items() if isinstance(v, int)}
        return {}

    def seen(self, host_key: str) -> int:
        """Highest message id this session has been shown by that host (the watcher process reads it too)."""
        return self._seen(host_key).get(self.sid, 0)

    def mark_seen(self, host_key: str, msg_id: int) -> None:
        ids = self._seen(host_key)
        if msg_id > ids.get(self.sid, 0):
            ids.pop(self.sid, None)
            ids[self.sid] = msg_id  # newest last; old sessions fall off the front
            with contextlib.suppress(OSError):
                write_private(self.seen_file, json.dumps({"key": host_key, "ids": dict(list(ids.items())[-32:])}))

    def known(self) -> dict | None:
        with contextlib.suppress(OSError, ValueError, KeyError, TypeError, AttributeError, BCError):
            kh = json.loads(self.hosts_file.read_text())
            ip, port = parse_address(kh["addr"], self.port)
            key = canonical_key(kh["key"])
            if key and valid_name(kh["name"]):
                return {
                    "addr": f"{ip}:{port}",
                    "key": key,
                    "name": kh["name"],
                    "fp": fingerprint(key),
                    "declined": bool(kh.get("declined")),
                }
        return None

    def pin(self, info: dict, declined: bool = False) -> None:
        write_private(
            self.hosts_file,
            json.dumps({"addr": info["addr"], "key": info["key"], "name": info["name"], "declined": declined}),
        )

    async def fetch(self, method: str, url: str, timeout: float, cap: int, **kw) -> tuple[int, dict, bytes]:
        """HTTP request whose reply is read with a hard size cap and an overall deadline, uncompressed, before
        anything is trusted: a fake host can't stream forever or send a decompression bomb."""

        async def go() -> tuple[int, dict, bytes]:
            headers = {**kw.pop("headers", {}), "accept-encoding": "identity"}
            async with self.http().stream(method, url, headers=headers, timeout=timeout, **kw) as r:
                if r.headers.get("content-encoding", "identity") != "identity":
                    raise BCError("compressed reply")
                chunks, size = [], 0
                async for chunk in r.aiter_raw():
                    size += len(chunk)
                    if size > cap:
                        raise BCError("reply too large")
                    chunks.append(chunk)
                return r.status_code, dict(r.headers), b"".join(chunks)

        return await asyncio.wait_for(go(), timeout * 2)

    async def hello(self, addr: str, timeout: float = 1.0) -> dict | None:
        nonce = secrets.token_urlsafe(12)
        try:
            _, _, content = await self.fetch("GET", f"http://{addr}/hello", timeout, 4096, params={"nonce": nonce})
            info = json.loads(content)
        except (httpx.HTTPError, ValueError, BCError, asyncio.TimeoutError, RecursionError):
            return None
        return self._checked(info, nonce, addr)

    def _checked(self, info: object, nonce: str, addr: str) -> dict | None:
        """Validate a signed hello. Every field ends up in text the agent reads, so nothing unvalidated passes."""
        if not isinstance(info, dict) or info.get("bc") != 1 or info.get("nonce") != nonce:
            return None
        key, name, port, boot = canonical_key(info.get("key")), info.get("name"), info.get("port"), info.get("boot")
        if not key or not valid_name(name) or not isinstance(port, int) or not 0 < port < 65536:
            return None
        if not isinstance(boot, str) or not re.fullmatch(r"[0-9a-f]{16}", boot):
            return None
        if key == self.ident.pub or not verify(key, str(info.get("sig", "")), hello_payload(nonce, name, port, boot)):
            return None
        return {"addr": addr, "key": key, "name": name, "fp": fingerprint(key), "boot": boot}

    async def broadcast(self, wait: float = 1.5) -> list[dict]:
        nonce = secrets.token_urlsafe(12)
        replies: list[tuple[bytes, tuple]] = []

        class Collector(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if len(replies) < 64 and len(data) <= 4096:
                    replies.append((data, addr))

        loop = asyncio.get_running_loop()
        t, _ = await loop.create_datagram_endpoint(Collector, local_addr=("0.0.0.0", 0), allow_broadcast=True)
        try:
            msg = json.dumps({"bc": 1, "q": "discover", "nonce": nonce}).encode()
            for dest in {str(i.network.broadcast_address) for _, i in private_interfaces()} | {"127.0.0.1"}:
                with contextlib.suppress(OSError):
                    t.sendto(msg, (dest, self.port))
            await asyncio.sleep(wait)
        finally:
            t.close()
        found = []
        for data, addr in replies:
            try:
                info = json.loads(data)
                port = info.get("port") if isinstance(info, dict) else None
                if isinstance(port, int) and 0 < port < 65536:
                    c = self._checked(info, nonce, f"{addr[0]}:{port}")
                    if c:
                        found.append(c)
            except (ValueError, TypeError, AttributeError, RecursionError):
                continue
        return found

    @staticmethod
    def tailscale_peers() -> list[str]:
        """Online Tailscale peers' IPv4 addresses (Tailscale doesn't carry broadcast)."""
        exe = next(
            (
                p
                for p in (
                    "/usr/bin/tailscale",
                    "/usr/local/bin/tailscale",
                    "/opt/homebrew/bin/tailscale",
                    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
                )
                if os.path.exists(p)
            ),
            None,
        )
        if not exe:
            return []
        try:
            out = subprocess.run([exe, "status", "--json"], capture_output=True, timeout=3, check=True).stdout
            peers = json.loads(out).get("Peer") or {}
            ips = []
            for p in peers.values():
                if isinstance(p, dict) and p.get("Online"):
                    ips += [ip for ip in p.get("TailscaleIPs") or [] if isinstance(ip, str) and "." in ip]
        except (OSError, subprocess.SubprocessError, ValueError, AttributeError, TypeError):
            return []
        return ips[:254]

    async def scan(self, subnets: bool = True) -> list[dict]:
        targets = [f"{ip}:{self.port}" for ip in await asyncio.to_thread(self.tailscale_peers)]
        for _, iface in private_interfaces() if subnets else []:
            if 24 <= iface.network.prefixlen < 31:
                targets += [f"{h}:{self.port}" for h in iface.network.hosts()]
        sem = asyncio.Semaphore(128)

        async def probe(addr):
            async with sem:
                return await self.hello(addr, timeout=0.5)

        return [r for r in await asyncio.gather(*(probe(a) for a in dict.fromkeys(targets))) if r]

    async def discover(self, sweep: bool = True) -> list[dict]:
        found = await self.broadcast()
        if not found:
            # sweeping every address is loud on a network that isn't yours: never from the background watcher,
            # and not back to back. Asking Tailscale for its peers is targeted, so that always runs.
            subnets = sweep and (not self.last_scan or time.monotonic() - self.last_scan > SCAN_EVERY)
            if subnets:
                self.last_scan = time.monotonic()
            found = await self.scan(subnets)
        by_key: dict[str, dict] = {}
        for f in found:  # prefer a non-loopback address for each host key
            if f["key"] not in by_key or by_key[f["key"]]["addr"].startswith("127."):
                by_key[f["key"]] = f
        return list(by_key.values())

    async def confirm_host(self, ctx: Context | None, info: dict, how: str, invite: bool = False) -> None:
        """First contact is trust-on-first-use: the user confirms the host, so a stranger on a shared network
        (say, café Wi-Fi) can't silently become your backchannel host."""
        check = "matches the invite code" if invite else "check it with them if unsure"
        question = (
            f"backchannel: {how} '{info['name']}' at {info['addr']}, host key {info['fp']} ({check}). "
            f"Connect and ask to join?"
        )
        if ctx is not None and can_elicit(ctx):
            try:
                r = await ctx.elicit(message=question, schema=Confirm)
            except Exception as e:
                log.warning("elicitation failed: %s", e)
            else:
                if r.action == "accept" and r.data.ok:
                    return
                raise BCError("Not connecting to that host.")
        if invite:  # no popup available: an explicit join with the matching invite code is the user's yes
            return
        raise BCError(
            f"{how.capitalize()} '{info['name']}' at {info['addr']} (host key {info['fp']}). Ask your user "
            f"whether to connect; if they agree, call join_host(address='bc1:{info['addr']}:{info['fp']}')."
        )

    async def ensure_host(self, ctx: Context | None = None, sweep: bool = True) -> dict:
        kh = self.known()
        if kh:
            info = await self.hello(kh["addr"], timeout=2.5)
            if info and info["key"] == kh["key"]:
                return {**kh, "boot": info["boot"]}
            if info:
                raise BCError(
                    f"The host at {kh['addr']} now has a different key ({info['fp']}, was {kh['fp']}). "
                    f"If you trust it, run /backchannel:join {kh['addr']}.",
                    code="host_key_changed",
                )
            for c in await self.discover(sweep):  # host moved (new IP)? the same key elsewhere is fine
                if c["key"] == kh["key"]:
                    self.pin(c, kh["declined"])
                    return {**c, "declined": kh["declined"]}
            raise BCError(f"{kh['name']}'s backchannel is offline (last known at {kh['addr']}).")
        found = await self.discover(sweep)
        if not found:
            raise BCError(
                "No backchannel host found on your networks. Ask the host for their invite code "
                "(/backchannel:status on their side) and run /backchannel:join <code>."
            )
        if len(found) > 1:
            listing = "; ".join(f"'{f['name']}' at {f['addr']} (key {f['fp']})" for f in found)
            raise BCError(f"Found more than one host: {listing}. Ask your user which one, then /backchannel:join it.")
        await self.confirm_host(ctx, found[0], "found")
        self.pin(found[0])
        return {**found[0], "declined": False}

    async def join(self, address: str, ctx: Context | None) -> str:
        address = address.strip()
        expect_fp = None
        if address.lower().startswith("bc1:"):  # invite code bc1:<ip>:<port>:<fingerprint>
            parts = address.split(":")
            if len(parts) != 4:
                raise BCError("Invite codes look like bc1:<ip>:<port>:<fingerprint>.")
            address, expect_fp = f"{parts[1]}:{parts[2]}", norm_fp(parts[3])
        ip, port = parse_address(address, self.port)
        info = await self.hello(f"{ip}:{port}", timeout=3)
        if not info:
            raise BCError(f"No backchannel host answered at {ip}:{port}.")
        if expect_fp and norm_fp(info["fp"]) != expect_fp:
            raise BCError(f"The host at {ip}:{port} doesn't match the invite code. Not joining.")
        kh = self.known()
        if not (kh and kh["key"] == info["key"]):  # new host: an invite proves the key, not that *you* want it
            how = "switching from " + f"'{kh['name']}' to" if kh else "connecting to"
            await self.confirm_host(ctx, info, how, invite=bool(expect_fp))
        self.pin(info)  # an explicit join also clears a previous "declined" mark
        return (await self.pair(info))[1]

    async def pair(self, host: dict) -> tuple[bool, str]:
        """Ask to join. Returns (already accepted?, what to tell the user)."""
        r = await self.post(host, "pair", {"name": self.name})
        if r.get("status") == "accepted":
            return True, f"Connected to {host['name']}'s backchannel as {self.name}."
        return False, (
            f"Pairing request sent to {host['name']} (their key {host['fp']}). Waiting for them to accept; "
            f"your key is {self.ident.fp}. Try again once they have."
        )

    _ERRORS = {
        "pending": "Still waiting for {host} to accept your pairing request (your key {fp}).",
        "name_taken": "The name '{me}' is taken on this backchannel; change your name in /plugin settings and restart.",
        "declined": "{host} declined or removed you from their backchannel. Ask them to let you back in "
        "(your key {fp}).",
        "busy": "{host}'s backchannel has too many pending join requests right now; try again in a few minutes.",
        "rate_limited": "Slow down: {host}'s backchannel is rate-limiting you.",
        "clock_skew": "Your clock and {host}'s differ by more than two minutes; fix the time on one of the machines.",
    }

    async def post(self, host: dict, op: str, payload: dict, timeout: float = 10) -> dict:
        """One signed request to the host. Raises BCError (with the host's error code in `.code`) on any failure."""
        body = json.dumps({**payload, "sid": self.sid} if self.sid else payload).encode()
        path, ts, nonce = f"/api/{op}", str(int(time.time() * 1000)), secrets.token_urlsafe(16)
        sig = self.ident.sign(request_payload(host["key"], host["boot"], "POST", path, ts, nonce, body))
        headers = {
            "content-type": "application/json",
            "x-bc-key": self.ident.pub,
            "x-bc-ts": ts,
            "x-bc-nonce": nonce,
            "x-bc-sig": sig,
        }
        try:
            status, rheaders, content = await self.fetch(
                "POST", f"http://{host['addr']}{path}", timeout, 512 * 1024, content=body, headers=headers
            )
        except (httpx.HTTPError, asyncio.TimeoutError) as e:
            raise BCError(f"Couldn't reach {host['name']}'s backchannel at {host['addr']} ({type(e).__name__}).") from e
        except BCError as e:
            raise BCError(f"Ignoring a bad reply from {host['addr']} ({e}).") from e
        rsig = rheaders.get("x-bc-sig", "")
        if not rsig and status == 400:
            # rejected before authentication; only well-known codes are shown, never free text
            with contextlib.suppress(ValueError, AttributeError, RecursionError):
                code = json.loads(content).get("error")
                if code == "clock_skew":
                    raise BCError(self._ERRORS["clock_skew"].format(host=host["name"]), code=code)
                if code == "bad_signature":  # the host restarted (or another session took over) since our hello
                    raise StaleHost(f"{host['name']}'s backchannel restarted mid-request; try again.", code=code)
        # nothing from the network is believed unless the pinned host key signed it for this exact request
        if not verify(host["key"], rsig, response_payload(host["key"], nonce, status, content)):
            raise BCError(
                f"Got an unsigned or forged reply from {host['addr']}; ignoring it. Someone may be "
                f"interfering with your connection to {host['name']}."
            )
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, RecursionError):
            raise BCError(f"{host['name']}'s backchannel sent a malformed reply.") from None
        err = data.get("error")
        if err:
            code = err if isinstance(err, str) and re.fullmatch(r"[a-z_]{1,32}", err) else ""
            if code in self._ERRORS:
                if code == "declined":
                    self.pin(host, declined=True)
                raise BCError(self._ERRORS[code].format(host=host["name"], fp=self.ident.fp, me=self.name), code=code)
            raise BCError(f"{host['name']}'s backchannel said: {clean(err, 200)}", code=code)
        return data

    async def call(self, ctx: Context | None, op: str, payload: dict | None = None) -> dict:
        """`post` to the pinned host, finding it first and asking to join if it doesn't know us yet."""
        host = await self.ensure_host(ctx)
        try:
            try:
                return await self.post(host, op, payload or {})
            except StaleHost:
                host = await self.ensure_host(ctx)
                return await self.post(host, op, payload or {})
        except BCError as e:
            if e.code != "not_paired":
                raise
        if host.get("declined"):  # don't nag a host who said no; the user can /backchannel:join explicitly
            raise BCError(
                self._ERRORS["declined"].format(host=host["name"], fp=self.ident.fp, me=self.name), code="declined"
            )
        connected, message = await self.pair(host)  # never asked yet (or the host forgot us): ask
        if connected:
            return await self.post(host, op, payload or {})
        raise BCError(message, code="pending")
