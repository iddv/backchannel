"""The network-facing relay: signed JSON over HTTP, UDP discovery, long-polls."""

from __future__ import annotations

import asyncio
import collections
import contextlib
import functools
import ipaddress
import json
import math
import secrets
import socket
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from uvicorn.protocols.http.h11_impl import H11Protocol

from .config import (
    CGNAT,
    CLOCK_SKEW_MS,
    CONV_MAX_MEMBERS,
    CONV_MAX_MINUTES,
    CONV_MAX_OPEN,
    CONV_MINUTES,
    CONV_PAGE,
    MAX_BODY,
    MAX_PENDING,
    MAX_REQUEST,
    MAX_SEALED,
    NONCE_MAX,
    NONCE_TTL,
    PAIR_PER_MINUTE_PER_IP,
    REBIND_EVERY,
    SEND_PER_DAY,
    SEND_PER_MINUTE,
    WAIT_HOLD,
    WAIT_PER_PEER,
    WAIT_TOTAL,
    BCError,
    Reject,
    as_conv,
    as_sid,
    log,
    valid_name,
)
from .crypto import (
    Identity,
    canonical_key,
    fingerprint,
    hello_payload,
    is_sealed,
    request_payload,
    response_payload,
    verify,
)
from .messages import clean
from .net import Limiter, bind_interfaces
from .store import Peer, Store


class NonceCache:
    def __init__(self, limit: int = NONCE_MAX) -> None:
        self.limit = limit
        self.seen: collections.OrderedDict[str, float] = collections.OrderedDict()

    def add(self, nonce: str) -> bool:
        """False if seen (replay) or the cache is full of still-live nonces (refuse rather than forget)."""
        now = time.time()
        while self.seen and next(iter(self.seen.values())) < now - NONCE_TTL:
            self.seen.popitem(last=False)
        if nonce in self.seen or len(self.seen) >= self.limit:
            return False
        self.seen[nonce] = now
        return True


NEEDS_UPDATE = (
    "This backchannel only carries end-to-end encrypted messages, which needs backchannel 0.7 or later. Update "
    "the plugin (/plugin) and start a new session."
)
UNREADABLE = (
    "[This message is end-to-end encrypted, and this session runs a backchannel from before 0.7 that can't "
    "read it. Update the plugin and start a new session, then look in history.]"
)


class Host:
    """Message store plus the network-facing relay. `name` is the host user's own name. `relay` means nobody
    reads messages here (a headless host), so nothing is encrypted for it."""

    def __init__(self, ident: Identity, store: Store, name: str, port: int, bind: str = "overlay", relay: bool = False):
        self.ident, self.store, self.name, self.port, self.bind = ident, store, name, port, bind
        self.relay = relay
        # every touch of the store happens on this one thread: the event loop never waits on the disk, and
        # requests stay serialised exactly as they were when they ran on the loop
        self._db = ThreadPoolExecutor(max_workers=1, thread_name_prefix="backchannel-db")
        self._touched: dict[tuple[str, str], float] = {}
        self.boot = secrets.token_hex(8)
        self.limiter = Limiter()
        self.nonces = NonceCache()
        self.stranger_nonces = NonceCache(limit=2_000)
        self.nets: list[ipaddress.IPv4Network] = []
        self.serving = False  # is *this* process the one holding the port?
        self.waits: dict[str, int] = defaultdict(int)
        self.listening: dict[tuple[str, str], int] = defaultdict(int)  # (conversation, member): open waits
        self.arriving: dict[tuple[str, str], float] = {}  # said something and is about to wait: until when
        self.bell: asyncio.Event | None = None  # rung on every send, so long-polls answer at once
        self.app = Starlette(
            routes=[
                Route("/hello", self.http_hello, methods=["GET"]),
                Route("/api/{op}", self.http_api, methods=["POST"]),
            ]
        )

    async def db(self, fn, *args, **kwargs):
        """Run a blocking store operation on the database thread."""
        return await asyncio.get_running_loop().run_in_executor(self._db, functools.partial(fn, *args, **kwargs))

    def ring(self) -> None:
        """Wake every long-poll now (event loop only)."""
        if self.bell:
            self.bell.set()
            self.bell = None

    async def post(self, sender: str, to: str, body: str, sid: str = "") -> str:
        """`send` for callers on the event loop: store the message, then wake the watchers."""
        out = await self.db(self.send, sender, to, body, sid)
        self.ring()
        return out

    # shared operations (blocking: call them through `db` from the event loop)
    def known_names(self) -> set[str]:
        return self.store.accepted_names() | {self.name}

    def send(self, sender: str, to: str, body: str, sid: str = "") -> str:
        to = to.strip().lower()
        if to != "all" and to not in self.known_names():
            raise BCError(f"Unknown recipient '{clean(to, 30)}'. Known: all, {', '.join(sorted(self.known_names()))}.")
        if not body.strip():
            raise BCError("Message is empty.")
        if len(body.encode()) > (MAX_SEALED if is_sealed(body) else MAX_BODY):
            raise BCError(f"Message too long (max {MAX_BODY // 1024} KiB).")
        self._may_send(sender)
        # if this session is already in a conversation with one of their sessions, the message goes to that one;
        # if that session has closed, this starts a new conversation for whichever of their sessions reads it
        target = self.store.linked(sender, sid, to) if sid and to != "all" else ""
        if target and target not in self.store.live_sessions(to):
            target = ""
        with self.store.tx():
            self.store.record_send(sender)
            self.store.touch(sender, sid)
            msg_id = self.store.add(sender, to, body, sid, target)
        return f"Sent message #{msg_id} to {to}."

    def _may_send(self, sender: str) -> None:
        if not self.limiter.ok(f"send:{sender}", SEND_PER_MINUTE, 60):
            raise BCError(f"Rate limit: at most {SEND_PER_MINUTE} messages a minute.")
        if self.store.sent_since(sender, 86400) >= SEND_PER_DAY:
            raise BCError(f"Daily limit reached ({SEND_PER_DAY} messages).")

    # conversations (blocking, like the operations above)
    def _conv(self, conv: object, user: str, sid: str = "", joined: bool = True) -> dict:
        """The conversation, if `user` may act in it. Not being a member looks the same as it not existing."""
        c = self.store.conv(as_conv(conv))
        me = c["members"].get(user) if c else None
        if not me or me["state"] == "left":
            raise BCError("There is no such conversation, or you aren't part of it.")
        if c["ended"]:
            raise BCError("That conversation has ended.")
        if joined and me["state"] != "joined":
            raise BCError("You have been invited to that conversation but haven't joined it yet.")
        if joined and me["sid"] != sid:
            raise BCError("That conversation is open in another of your sessions.")
        return c

    def _heard(self, conv: str) -> set[str]:
        """Who is listening in the conversation: an open wait, or one that is just about to open."""
        now = time.monotonic()
        soon = {u for (c, u), until in list(self.arriving.items()) if c == conv and until > now}
        return {u for c, u in list(self.listening) if c == conv} | soon

    def _conv_view(self, conv: str, user: str, after: int = 0, fetch: bool = True) -> dict:
        """What a member gets back from every conversation call: what others said since `after`, and who is
        where. Handing messages over marks them seen, so a watcher doesn't announce them a second time."""
        rows = self.store.conv_messages(conv, after, user, CONV_PAGE) if fetch else []
        self.store.conv_seen(conv, user, rows[-1]["id"] if rows else after)
        c, heard, now = self.store.conv(conv), self._heard(conv), time.time()
        members = [
            {"name": n, "state": m["state"], "listening": n in heard, "quiet": int(now - m["updated"])}
            for n, m in sorted(c["members"].items())
        ]
        return {"messages": rows, "rev": c["rev"], "ended": c["ended"], "left": int(c["expires"] - now)} | {
            "members": members
        }

    def conv_op(self, op: str, user: str, sid: str, data: dict) -> dict:
        """One conversation request from `user`'s session `sid`."""
        after = data.get("after")
        after = after if isinstance(after, int) and not isinstance(after, bool) and after > 0 else 0
        if op == "list":
            return {"conversations": self.store.convs_for(user)}
        if not sid:
            raise BCError("Conversations need backchannel 0.8 or later.")
        if op == "start":
            conv, names = as_conv(data.get("conv")), data.get("members")
            if not conv or not isinstance(names, list) or not all(isinstance(n, str) for n in names):
                raise ValueError
            names = sorted({n.strip().lower() for n in names} - {user})
            able = self.known_names() - ({self.name} if self.relay else set())
            unknown = [clean(n, 30) for n in names if n not in able]
            if unknown or not names:
                raise BCError(f"Can't start a conversation with: {', '.join(unknown) or 'nobody'}.")
            if len(names) >= CONV_MAX_MEMBERS:
                raise BCError(f"A conversation can have at most {CONV_MAX_MEMBERS} members.")
            if sum(c["by"] == user for c in self.store.convs_for(user)) >= CONV_MAX_OPEN:
                raise BCError(f"You already have {CONV_MAX_OPEN} conversations going; leave some first.")
            minutes = data.get("minutes", CONV_MINUTES)
            if isinstance(minutes, bool) or not isinstance(minutes, (int, float)) or math.isnan(minutes):
                minutes = CONV_MINUTES
            if not self.store.conv_create(conv, user, sid, names, min(max(minutes, 1), CONV_MAX_MINUTES)):
                raise BCError("That conversation id is already used; start it again.")
            return self._conv_view(conv, user)
        if op == "join":
            c = self._conv(data.get("conv"), user, joined=False)
            me = c["members"][user]
            if me["state"] == "joined" and me["sid"] != sid and me["sid"] in self.store.live_sessions(user):
                raise BCError("That conversation is open in another of your sessions.")
            self.store.conv_set(c["id"], user, "joined", sid)
            return self._conv_view(c["id"], user, fetch=False)
        if op == "leave":
            c = self._conv(data.get("conv"), user, joined=False)
            self.store.conv_set(c["id"], user, "left")
            return {"ok": True}
        if op == "read":
            # looking back: open to anyone who was in it, also after it ended. Someone who left sees what was
            # said up to then, not what the others went on to say
            c = self.store.conv(as_conv(data.get("conv")))
            me = c["members"].get(user) if c else None
            if not me or me["state"] == "invited":
                raise BCError("There is no such conversation, or you aren't part of it.")
            until = me["updated"] if me["state"] == "left" else None
            rows = self.store.conv_transcript(c["id"], after, CONV_PAGE, until)
            members = [{"name": n, "state": m["state"]} for n, m in sorted(c["members"].items())]
            return {"messages": rows, "ended": c["ended"], "members": members}
        if op == "say":
            c, body, sent = self._conv(data.get("conv"), user, sid), data.get("body"), 0
            if body is not None:
                if not is_sealed(body) or len(body) > MAX_SEALED:
                    raise BCError("That message isn't a valid encrypted message.")
                self._may_send(user)
                with self.store.tx():
                    self.store.record_send(user)
                    sent = self.store.add(user, f"#{c['id']}", body, sid)
                if data.get("wait") is True:  # they will be listening by the time anyone reads this
                    self.arriving[(c["id"], user)] = time.monotonic() + 3
            return self._conv_view(c["id"], user, after) | {"sent": sent}
        raise BCError("Unknown conversation request.")

    def _conv_wait_poll(self, user: str, sid: str, conv: object, after: int) -> dict:
        c = self._conv(conv, user, sid)
        self.store.touch(user, sid)
        return self._conv_view(c["id"], user, after)

    async def conv_wait(self, user: str, sid: str, conv: object, after: int, rev: object, hold: float, alive=None):
        """Hold until someone says something in the conversation, joins or leaves it, it ends, or `hold` seconds
        pass. While this is open the member shows as listening. Raises BCError if they may not."""
        key, deadline = (as_conv(conv), user), time.monotonic() + hold
        self.listening[key] += 1
        try:
            while True:
                out = await self.db(self._conv_wait_poll, user, sid, conv, after)
                done = out["messages"] or out["rev"] != rev or out["ended"] or time.monotonic() >= deadline
                if done or (alive is not None and not await alive()):
                    return out
                self.bell = self.bell or asyncio.Event()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self.bell.wait(), 1)
        finally:
            self.listening[key] -= 1
            if self.listening[key] <= 0:
                self.listening.pop(key, None)

    def peer_list(self) -> list[dict]:
        """Everyone on the backchannel, with their keys. `e2e` says whether they have a version that can read
        encrypted messages (0.7 or later); nobody reads messages on a headless relay."""
        out = [
            {"name": self.name, "fp": self.ident.fp, "host": True, "key": self.ident.pub, "e2e": not self.relay}
            | ({"relay": True} if self.relay else {})
        ]
        for p in self.store.peers("accepted"):
            out.append({"name": p.name, "fp": p.fp, "host": False, "key": p.key, "e2e": bool(p.e2e)})
        return out

    def inbox(self, user: str, sid: str, hold: bool = False, ack: object = None) -> dict:
        self.store.ack(user, ack, sid)
        rows, more = self.store.unread(user, hold=hold, sid=sid)
        # conversations this session should hear about: invitations, and its own with something unheard
        convs = [
            {k: c[k] for k in ("id", "state", "with", "by", "unread")}
            for c in self.store.convs_for(user)
            if c["state"] == "invited" or (c["sid"] == sid and c["unread"])
        ]
        return {"messages": rows, "more": more, "stranded": self.store.stranded(user, sid, note=True)} | {
            "conversations": convs
        }

    def maintain(self) -> None:
        self.store.prune()
        self.store.expire_pending()
        self.store.lock_down()
        self.limiter.gc()
        self.arriving = {k: t for k, t in self.arriving.items() if t > time.monotonic()}
        cutoff = time.monotonic() - 3600
        self._touched = {k: t for k, t in self._touched.items() if t > cutoff}

    # HTTP
    def allowed_source(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.is_loopback or any(a in n for n in self.nets)

    def hello(self, nonce: str) -> dict:
        nonce = nonce[:64]
        return {
            "bc": 1,
            "name": self.name,
            "key": self.ident.pub,
            "port": self.port,
            "boot": self.boot,
            "nonce": nonce,
            "sig": self.ident.sign(hello_payload(nonce, self.name, self.port, self.boot)),
        }

    def _gate(self, req: Request, rate_key: str, n: int) -> str | None:
        ip = req.client.host if req.client else ""
        if not self.allowed_source(ip):
            return "forbidden"
        host_header = req.headers.get("host", "").rsplit(":", 1)[0].strip("[]")
        try:  # only IP literals: defeats DNS rebinding from a browser on this machine
            ipaddress.ip_address(host_header)
        except ValueError:
            return "forbidden"
        if not self.limiter.ok(f"{rate_key}:{ip}", n, 60):
            return "rate_limited"
        return None

    async def http_hello(self, req: Request) -> JSONResponse:
        err = self._gate(req, "hello", 120)
        if err:
            return JSONResponse({"error": err}, 403 if err == "forbidden" else 429)
        return JSONResponse(self.hello(req.query_params.get("nonce", "")))

    async def _read_body(self, req: Request) -> bytes:
        cl = req.headers.get("content-length")
        if cl is not None and (not cl.isdigit() or int(cl) > MAX_REQUEST):
            raise Reject("too_large", 413)
        chunks, size = [], 0

        async def read() -> None:
            nonlocal size
            async for chunk in req.stream():
                size += len(chunk)
                if size > MAX_REQUEST:
                    raise Reject("too_large", 413)
                chunks.append(chunk)

        try:
            await asyncio.wait_for(read(), timeout=10)
        except asyncio.TimeoutError:
            raise Reject("timeout") from None
        return b"".join(chunks)

    def _verify(self, req: Request, body: bytes) -> tuple[str, str]:
        """Check the request signature. Pure computation: returns (key, nonce) or raises Reject."""
        h = req.headers
        key = canonical_key(h.get("x-bc-key", ""))
        ts, nonce, sig = h.get("x-bc-ts", ""), h.get("x-bc-nonce", ""), h.get("x-bc-sig", "")
        if not key or not (ts.isdigit() and len(ts) <= 15) or not (8 <= len(nonce) <= 64) or not (0 < len(sig) <= 100):
            raise Reject("unsigned")
        if abs(time.time() * 1000 - int(ts)) > CLOCK_SKEW_MS:
            raise Reject("clock_skew")  # unsigned, but safe to report so a friend can fix their clock
        if not verify(key, sig, request_payload(self.ident.pub, self.boot, req.method, req.url.path, ts, nonce, body)):
            raise Reject("bad_signature")
        return key, nonce

    def _admit(self, key: str, nonce: str) -> None:
        """Replay check (database thread, which also owns the nonce caches)."""
        peer = self.store.peer(key)
        cache = self.nonces if peer and peer.status == "accepted" else self.stranger_nonces
        if not cache.add(f"{key}:{nonce}"):
            raise Reject("replay")

    def _signed(self, nonce: str, data: dict, status: int = 200) -> Response:
        body = json.dumps(data).encode()
        sig = self.ident.sign(response_payload(self.ident.pub, nonce, status, body))
        return Response(body, status, media_type="application/json", headers={"x-bc-sig": sig})

    async def http_api(self, req: Request) -> Response:
        err = self._gate(req, "api", 120)
        if err:
            return JSONResponse({"error": err}, 403 if err == "forbidden" else 429)
        try:
            body = await self._read_body(req)
            key, nonce = self._verify(req, body)
            await self.db(self._admit, key, nonce)
        except Reject as e:
            return JSONResponse({"error": e.code}, e.status)
        try:
            data = json.loads(body or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, RecursionError):
            return self._signed(nonce, {"error": "bad_request"}, 400)
        op, sid = req.path_params["op"], as_sid(data.get("sid"))
        if op == "wait":
            return await self._wait(req, nonce, key, data, sid)
        if op == "conv_wait":
            return await self._conv_wait_http(req, nonce, key, data, sid)
        status, payload = await self.db(self._handle, op, key, data, req.client.host, sid)
        if op in ("send", "conv") and status == 200:
            self.ring()
        return self._signed(nonce, payload, status)

    @staticmethod
    def _standing(peer: Peer | None) -> tuple[int, dict] | None:
        """Why this key may not use the backchannel, or None if it may."""
        if not peer:
            return 403, {"error": "not_paired"}
        if peer.status == "revoked":
            return 403, {"error": "declined"}
        if peer.status != "accepted":
            return 401, {"error": "pending"}
        return None

    def _handle(self, op: str, key: str, data: dict, ip: str, sid: str) -> tuple[int, dict]:
        """One authenticated request, start to finish, on the database thread."""
        peer = self.store.peer(key)
        try:
            if op == "pair":
                return self._pair(key, peer, data, ip)
            if op == "whoami":
                return 200, {
                    "status": peer.status if peer else "unknown",
                    "host": self.name,
                    "name": peer.name if peer else None,
                }
            denied = self._standing(peer)
            if denied:
                return denied
            handler = self._OPS.get(op)
            if handler is None:
                return 404, {"error": "unknown_op"}
            self.store.touch(peer.name, sid)
            if data.get("e2e") is True and not peer.e2e:
                self.store.set_e2e(key)
            return 200, handler(self, peer, data, sid)
        except BCError as e:
            return 422, {"error": str(e)}
        except (TypeError, ValueError, OverflowError):
            return 400, {"error": "bad_request"}

    def _op_send(self, peer: Peer, data: dict, sid: str) -> dict:
        body = str(data.get("body", ""))
        if not is_sealed(body):  # a client from before 0.7; nobody on 0.7 would show its message anyway
            raise BCError(NEEDS_UPDATE)
        return {"result": self.send(peer.name, str(data.get("to", "")), body, sid)}

    @staticmethod
    def _readable(data: dict, rows: list[dict]) -> list[dict]:
        """What a client older than 0.7 gets in place of a message it can't decrypt."""
        if data.get("e2e") is True:
            return rows
        return [{**m, "body": UNREADABLE} if is_sealed(m["body"]) else m for m in rows]

    def _op_check(self, peer: Peer, data: dict, sid: str) -> dict:
        # v0.3 clients send {} and are marked read at once; newer ones hold and acknowledge
        box = self.inbox(peer.name, sid, hold=data.get("hold") is True, ack=data.get("ack"))
        return {**box, "messages": self._readable(data, box["messages"])}

    def _op_ack(self, peer: Peer, data: dict, sid: str) -> dict:
        self.store.ack(peer.name, data.get("id"), sid)
        return {"ok": True}

    def _op_ping(self, peer: Peer, data: dict, sid: str) -> dict:
        return {"ok": True}

    def _op_history(self, peer: Peer, data: dict, sid: str) -> dict:
        w = data.get("with")
        rows = self.store.history(peer.name, int(data.get("limit", 20)), str(w).lower() if w else None)
        return {"messages": self._readable(data, rows)}

    def _op_peers(self, peer: Peer, data: dict, sid: str) -> dict:
        return {"peers": self.peer_list()}

    def _op_conv(self, peer: Peer, data: dict, sid: str) -> dict:
        return self.conv_op(str(data.get("op", "")), peer.name, sid, data)

    _OPS = {
        "conv": _op_conv,
        "send": _op_send,
        "check": _op_check,
        "ack": _op_ack,
        "ping": _op_ping,
        "history": _op_history,
        "peers": _op_peers,
    }

    def _wait_poll(self, key: str, after: object, sid: str) -> tuple[int, dict]:
        peer = self.store.peer(key)
        denied = self._standing(peer)
        if denied:
            return denied
        now = time.monotonic()
        if now - self._touched.get((peer.name, sid), float("-inf")) >= 20:  # a watcher is alive; say so sparingly
            self._touched[(peer.name, sid)] = now
            self.store.touch(peer.name, sid)
        out = self.store.waiting(peer.name, after, sid)
        # conversation messages this session isn't already listening for wake it too
        listening = tuple(c for c, u in list(self.listening) if u == peer.name)
        newer = after if isinstance(after, int) and not isinstance(after, bool) else 0
        conv = self.store.conv_unread(peer.name, sid, listening, newer)
        out["unread"] += conv["count"]
        out["from"] = sorted({*out["from"], *conv["from"]})[:10]
        out["latest"] = max(out["latest"], conv["latest"])
        return 200, out

    async def _wait(self, req: Request, nonce: str, key: str, data: dict, sid: str) -> Response:
        """Long-poll: answer as soon as this session has unread messages newer than `after`, or after WAIT_HOLD
        seconds. Nothing is marked read. This is what lets a watching agent sleep instead of polling."""
        if self.waits[key] >= WAIT_PER_PEER or sum(self.waits.values()) >= WAIT_TOTAL:
            return self._signed(nonce, {"error": "too_many_waits"}, 429)
        hold = data.get("timeout", WAIT_HOLD)
        if isinstance(hold, bool) or not isinstance(hold, (int, float)) or math.isnan(hold):
            hold = WAIT_HOLD
        deadline = time.monotonic() + min(max(hold, 0), WAIT_HOLD)
        self.waits[key] += 1
        try:
            while True:
                status, payload = await self.db(self._wait_poll, key, data.get("after"), sid)
                if (
                    status != 200
                    or payload["unread"]
                    or time.monotonic() >= deadline
                    or not self.serving
                    or await req.is_disconnected()
                ):
                    return self._signed(nonce, payload, status)
                # woken at once by a send in this process; the timeout catches sends by another host session
                self.bell = self.bell or asyncio.Event()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self.bell.wait(), 1)
        finally:
            self.waits[key] -= 1
            if self.waits[key] <= 0:
                self.waits.pop(key, None)

    async def _conv_wait_http(self, req: Request, nonce: str, key: str, data: dict, sid: str) -> Response:
        """The long-poll behind a blocking say or listen."""
        status, payload = await self.db(self._handle, "ping", key, data, req.client.host, sid)  # standing, heartbeat
        if status != 200:
            return self._signed(nonce, payload, status)
        name = (await self.db(self.store.peer, key)).name
        hold, after = data.get("timeout", WAIT_HOLD), data.get("after")
        if isinstance(hold, bool) or not isinstance(hold, (int, float)) or math.isnan(hold):
            hold = WAIT_HOLD
        after = after if isinstance(after, int) and not isinstance(after, bool) and after > 0 else 0

        async def alive() -> bool:
            return self.serving and not await req.is_disconnected()

        # nothing may be awaited between counting the open waits and adding this one to them
        if self.waits[key] >= WAIT_PER_PEER or sum(self.waits.values()) >= WAIT_TOTAL:
            return self._signed(nonce, {"error": "too_many_waits"}, 429)
        self.waits[key] += 1
        try:
            out = await self.conv_wait(
                name, sid, data.get("conv"), after, data.get("rev"), min(max(hold, 0), WAIT_HOLD), alive
            )
            return self._signed(nonce, out)
        except BCError as e:
            return self._signed(nonce, {"error": str(e)}, 422)
        finally:
            self.waits[key] -= 1
            if self.waits[key] <= 0:
                self.waits.pop(key, None)

    def _pair(self, key: str, peer: Peer | None, data: dict, ip: str) -> tuple[int, dict]:
        if peer and peer.status == "accepted":
            return 200, {"status": "accepted", "host": self.name}
        if peer and peer.status == "revoked":  # declined or removed: only the host can let them back in
            return 403, {"error": "declined"}
        if not self.limiter.ok(f"pair:{ip}", PAIR_PER_MINUTE_PER_IP, 60):
            return 429, {"error": "rate_limited"}
        name = data.get("name")
        if not valid_name(name):
            return 400, {"error": "bad_name"}
        if name == self.name:
            return 409, {"error": "name_taken"}
        self.store.expire_pending()
        if not peer and self.store.pending_count() >= MAX_PENDING:
            return 429, {"error": "busy"}
        self.store.request_pairing(key, name, ip)
        log.info("pairing request from %s (%s) at %s", name, fingerprint(key), ip)
        return 202, {"status": "pending", "host": self.name}

    # serving
    def _sockets(self) -> tuple[list[socket.socket], list[str]]:
        ifaces = bind_interfaces(self.bind)
        # Tailscale gives each node a /32; its peers are elsewhere in 100.64.0.0/10
        self.nets = [CGNAT if i.ip in CGNAT and i.network.prefixlen >= 31 else i.network for _, i in ifaces]
        socks, bound = [], []
        try:
            for ip in ["127.0.0.1"] + [str(i.ip) for _, i in ifaces]:
                # naming the protocol matters: asyncio only turns off Nagle's algorithm on sockets that do, and
                # with it on every reply waits ~40 ms for the client's delayed ACK
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                socks.append(s)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.bind((ip, self.port))
                s.listen(64)
                s.setblocking(False)
                bound.append(ip)
        except OSError:
            for s in socks:
                s.close()
            raise
        return socks, bound

    async def serve(self, install_signal_handlers: bool) -> None:
        """Hold the relay port for as long as this process lives. If another session on this machine already has
        it, keep trying so this one takes over when that one ends; if the network interfaces change (overlay came
        up, laptop woke with a new address), re-listen on the new set."""
        told = False
        while True:
            try:
                if not await self._serve_once(install_signal_handlers):
                    return
                told = False
            except OSError as e:
                if not told:
                    log.info(
                        "port %s is busy (%s); another backchannel session on this machine is probably hosting. "
                        "This one will take over if that one stops.",
                        self.port,
                        e.strerror,
                    )
                    told = True
            await asyncio.sleep(5 if told else 1)

    async def _serve_once(self, install_signal_handlers: bool) -> bool:
        """Serve until the interface set changes (returns True: serve again) or the server is told to stop."""
        socks, bound = self._sockets()  # raises OSError if the port is taken
        loop = asyncio.get_running_loop()
        host = self

        class Responder(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.t = transport

            def datagram_received(self, data, addr):
                if (
                    len(data) > 512
                    or not host.allowed_source(addr[0])
                    or not host.limiter.ok("udp", 50, 1)
                    or not host.limiter.ok(f"udp:{addr[0]}", 5, 1)
                ):
                    return
                try:
                    q = json.loads(data)
                except (ValueError, RecursionError):
                    return  # anyone on the network can send junk here
                if isinstance(q, dict) and q.get("bc") == 1 and q.get("q") == "discover":
                    self.t.sendto(json.dumps(host.hello(str(q.get("nonce", "")))).encode(), addr)

        try:
            udp, _ = await loop.create_datagram_endpoint(
                Responder, local_addr=("0.0.0.0", self.port), allow_broadcast=True
            )
        except OSError:
            for s in socks:
                s.close()
            raise
        config = uvicorn.Config(
            self.app,
            http=GuardedH11,
            log_level="warning",
            lifespan="off",
            proxy_headers=False,
            limit_concurrency=64,
            timeout_keep_alive=5,
            server_header=False,
            date_header=False,
            timeout_graceful_shutdown=2,
        )
        server = uvicorn.Server(config)
        if not install_signal_handlers:
            server.capture_signals = contextlib.nullcontext  # let the stdio side own process lifetime

        rebind = False

        async def maintenance():
            nonlocal rebind
            ticks = 0
            while True:
                try:
                    if ticks % max(1, 300 // REBIND_EVERY) == 0:
                        await self.db(self.maintain)
                    ticks += 1
                    await asyncio.sleep(REBIND_EVERY)
                    if sorted(str(i.ip) for _, i in bind_interfaces(self.bind)) != sorted(bound[1:]):
                        log.info("network interfaces changed; re-listening")
                        rebind = server.should_exit = True
                        return
                except Exception:  # a failed pass must not end maintenance, but it must be visible
                    log.exception("maintenance pass failed")
                    await asyncio.sleep(REBIND_EVERY)

        log.info(f"hosting as {self.name} (key {self.ident.fp}) on port {self.port}: {', '.join(bound)}")
        task = asyncio.create_task(maintenance())
        self.serving = True
        try:
            await server.serve(sockets=socks)
        finally:
            self.serving = False
            task.cancel()
            udp.close()
            for s in socks:
                with contextlib.suppress(OSError):
                    s.close()
        return rebind


class GuardedH11(H11Protocol):
    """uvicorn's h11 protocol, plus: at most 8 connections per IP, and a connection that hasn't started a request
    within 10 s is closed. uvicorn's own timeouts only start after a first request."""

    per_ip: dict[str, int] = defaultdict(int)

    def connection_made(self, transport) -> None:
        super().connection_made(transport)
        self._ip = self.client[0] if self.client else "?"
        self._idle = None
        if GuardedH11.per_ip[self._ip] >= 8:
            self._ip = None
            transport.close()
            return
        GuardedH11.per_ip[self._ip] += 1
        self._idle = self.loop.call_later(10, self._idle_check)

    def _idle_check(self) -> None:
        if self.cycle is None and not self.transport.is_closing():
            self.transport.close()

    def connection_lost(self, exc) -> None:
        if self._idle:
            self._idle.cancel()
        if self._ip is not None:
            GuardedH11.per_ip[self._ip] -= 1
            if GuardedH11.per_ip[self._ip] <= 0:
                GuardedH11.per_ip.pop(self._ip, None)
        super().connection_lost(exc)
