"""Load test: how the host behaves with every limit a small group could reach, and what sealing costs.

    uv run python scripts/loadtest.py

Starts its own host on loopback (port 18900) with rate limits switched off, so it measures capacity rather than the
limiter. Linux only: each simulated member connects from its own 127.0.1.x address. Takes about two minutes.
Figures from past runs are in scripts/README.md.
"""

import asyncio, json, secrets, subprocess, sys, tempfile, time
from pathlib import Path
import httpx, psutil

PORT = 18900
MODE = sys.argv[1] if len(sys.argv) > 1 else "run"
DATA = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(tempfile.mkdtemp(prefix="bc-bench-"))
import types
import backchannel.host as bhost
from backchannel.config import prepare_data_dir
from backchannel.crypto import Identity, request_payload, seal, unseal
from backchannel.host import Host
from backchannel.store import Store

bc = types.SimpleNamespace(Store=Store, Identity=Identity, request_payload=request_payload)

if MODE == "server":
    prepare_data_dir(DATA)
    host = Host(Identity(DATA / "identity.json"), Store(DATA / "backchannel.db"), "relay", PORT, "127.0.0.1")
    host.limiter.ok = lambda *a, **k: True  # measure capacity, not the rate limiter
    bhost.SEND_PER_DAY = 10**9
    asyncio.run(host.serve(install_signal_handlers=True))
    sys.exit()


def pct(xs, p):
    return sorted(xs)[min(len(xs) - 1, int(len(xs) * p))] * 1000


def line(label, lat, wall):
    print(
        f"  {label:34} {len(lat) / wall:8.0f} req/s   p50 {pct(lat, 0.5):6.1f} ms  p95 {pct(lat, 0.95):6.1f}  p99 {pct(lat, 0.99):6.1f}"
    )


# ---------------- 1. store micro-benchmarks
def store_bench():
    print("1. Store (SQLite), no network")
    st = bc.Store(DATA / "micro.db")
    users = [f"u{i}" for i in range(10)]
    t = time.perf_counter()
    for i in range(5000):
        st.add(users[i % 10], users[(i + 1) % 10] if i % 5 else "all", "x" * 200, "a" * 12, "")
    dt = time.perf_counter() - t
    print(f"  insert 5000 messages               {5000 / dt:8.0f} /s      ({dt / 5000 * 1e6:.0f} us each)")
    for label, fn in [
        ("waiting() - cursor at 0, 5000 rows", lambda: st.waiting("u3", sid="b" * 12)),
        ("unread_count() same", lambda: st.unread_count("u3", "b" * 12)),
        ("waiting() for a user with no mail", lambda: st.waiting("nobody", sid="b" * 12)),
    ]:
        t = time.perf_counter()
        n = 200
        for _ in range(n):
            fn()
        print(f"  {label:34} {(time.perf_counter() - t) / n * 1e3:8.2f} ms each")
    t = time.perf_counter()
    n = 0
    while st.unread("u3", sid="b" * 12)[0]:
        n += 1
    print(f"  drain inbox: {n} check calls (20 msgs each) {(time.perf_counter() - t) / n * 1e3:6.2f} ms each")
    t = time.perf_counter()
    for _ in range(200):
        st.waiting("u3", sid="b" * 12)
    print(f"  waiting() - inbox read, cursor current {(time.perf_counter() - t) / 200 * 1e3:6.3f} ms each")
    t = time.perf_counter()
    st.prune()
    print(f"  prune()                            {(time.perf_counter() - t) * 1e3:8.1f} ms")


def seal_bench():
    print("\n0. Sealing (client side, per message)")
    ids = [Identity(DATA / f"seal{i}.json") for i in range(10)]
    for label, readers, text in [
        ("200 B to 1 person", ids[1:2], "x" * 200),
        ("200 B to 9 people", ids[1:], "x" * 200),
        ("8 KiB to 9 people", ids[1:], "x" * 8000),
    ]:
        t = time.perf_counter()
        n = 300
        for _ in range(n):
            body = seal(ids[0], "room", "all", [i.pub for i in readers], text)
        s = (time.perf_counter() - t) / n
        t = time.perf_counter()
        for _ in range(n):
            unseal(ids[1], "room", body)
        print(
            f"  {label:20} seal {s * 1e3:6.2f} ms   open {(time.perf_counter() - t) / n * 1e3:6.2f} ms   {len(body):6} bytes on the wire"
        )


# ---------------- network side
class Peer:
    def __init__(self, i):
        self.name, self.ip = f"p{i}", f"127.0.1.{i + 1}"
        self.ident = bc.Identity(DATA / f"peer{i}.json")

    def headers(self, hello, op, body):
        ts, nonce = str(int(time.time() * 1000)), secrets.token_urlsafe(16)
        sig = self.ident.sign(bc.request_payload(hello["key"], hello["boot"], "POST", f"/api/{op}", ts, nonce, body))
        return {
            "content-type": "application/json",
            "x-bc-key": self.ident.pub,
            "x-bc-ts": ts,
            "x-bc-nonce": nonce,
            "x-bc-sig": sig,
        }

    def client(self, conns=8):
        return httpx.AsyncClient(
            trust_env=False,
            timeout=70,
            transport=httpx.AsyncHTTPTransport(local_address=self.ip, limits=httpx.Limits(max_connections=conns)),
        )

    async def post(self, c, hello, op, payload):
        body = json.dumps(payload).encode()
        return await c.post(f"http://127.0.0.1:{PORT}/api/{op}", content=body, headers=self.headers(hello, op, body))


async def blast(label, n, conc, fn):
    lat, sem, bad = [], asyncio.Semaphore(conc), 0

    async def one(i):
        nonlocal bad
        async with sem:
            t = time.perf_counter()
            r = await fn(i)
            lat.append(time.perf_counter() - t)
            bad += r.status_code != 200

    t = time.perf_counter()
    await asyncio.gather(*(one(i) for i in range(n)))
    wall = time.perf_counter() - t
    line(label + (f" [{bad} errors]" if bad else ""), lat, wall)


def cpu(proc, secs):
    proc.cpu_percent(None)
    time.sleep(secs)
    return proc.cpu_percent(None)


async def waiters(peers, hello, sessions_each, hold):
    clients = [p.client() for p in peers]

    async def w(p, c, k):
        t = time.perf_counter()
        r = await p.post(c, hello, "wait", {"after": 0, "timeout": hold, "sid": f"{k:012x}"})
        return time.perf_counter() - t, r.status_code, r.json()

    tasks = [asyncio.create_task(w(p, c, k)) for p, c in zip(peers, clients) for k in range(sessions_each)]
    return tasks, clients


async def net_bench(server):
    proc = psutil.Process(server.pid)
    peers = [Peer(i) for i in range(10)]
    async with httpx.AsyncClient(trust_env=False) as c:
        hello = (await c.get(f"http://127.0.0.1:{PORT}/hello", params={"nonce": "x" * 8})).json()
    print(f"\n2. Long-poll watchers (host RSS at start {proc.memory_info().rss / 2**20:.0f} MB)")
    print(f"  host CPU, idle, no watchers        {await asyncio.to_thread(cpu, proc, 8):8.1f} % of one core")
    tasks, clients = await waiters(peers[2:], hello, 4, 45)
    await asyncio.sleep(2)
    print(f"  host CPU, 32 watchers, empty DB    {await asyncio.to_thread(cpu, proc, 10):8.1f} %")
    extra = peers[1].client()
    r = await peers[1].post(extra, hello, "wait", {"after": 0, "timeout": 5, "sid": "f" * 12})
    print(f"  33rd watcher                       HTTP {r.status_code} {r.json()}")
    t0 = time.perf_counter()
    await peers[0].post(
        extra,
        hello,
        "send",
        {"to": "all", "body": seal(peers[0].ident, hello["key"], "all", [p.ident.pub for p in peers], "wake up")},
    )
    res = await asyncio.gather(*tasks)
    lat = [time.perf_counter() - t0 for _ in res]
    woke = sum(1 for _, s, j in res if s == 200 and j.get("unread"))
    print(f"  broadcast -> {woke}/32 watchers woke; all answered within {max(lat) * 1000:.0f} ms")
    for c in clients:
        await c.aclose()

    print("\n3. Request throughput, rate limits off")
    c0 = peers[0].client()
    await blast(
        "GET /hello, 1 connection",
        300,
        1,
        lambda i: c0.get(f"http://127.0.0.1:{PORT}/hello", params={"nonce": f"s{i:07d}"}),
    )

    async def fresh(i):
        async with httpx.AsyncClient(trust_env=False, verify=False) as c:
            return await c.get(f"http://127.0.0.1:{PORT}/hello", params={"nonce": f"f{i:07d}"})

    await blast("GET /hello, new connection each", 300, 1, fresh)
    print("  -- 8 connections --")
    await blast(
        "GET /hello (signs a reply)",
        3000,
        8,
        lambda i: c0.get(f"http://127.0.0.1:{PORT}/hello", params={"nonce": f"n{i:07d}"}),
    )
    sealed = seal(peers[0].ident, hello["key"], "p1", [peers[1].ident.pub], "x" * 200)
    await blast(
        "send sealed 200 B (p0 -> p1)",
        3000,
        8,
        lambda i: peers[0].post(c0, hello, "send", {"to": "p1", "body": sealed, "sid": "a" * 12}),
    )
    c9 = peers[9].client()
    await blast(
        "check, empty inbox", 3000, 8, lambda i: peers[9].post(c9, hello, "check", {"hold": True, "sid": "c" * 12})
    )
    await blast("wait timeout=0", 3000, 8, lambda i: peers[9].post(c9, hello, "wait", {"timeout": 0, "sid": "c" * 12}))
    await blast("ping (heartbeat)", 3000, 8, lambda i: peers[9].post(c9, hello, "ping", {"sid": "c" * 12}))
    c1 = peers[1].client()
    await blast("check, 3000 unread (20/page)", 150, 1, lambda i: peers[1].post(c1, hello, "check", {"sid": "d" * 12}))

    print("\n4. Watchers again, now with 3000 messages in the store that aren't theirs")
    tasks, clients = await waiters(peers[2:], hello, 4, 20)
    await asyncio.sleep(2)
    print(f"  host CPU, 32 watchers              {await asyncio.to_thread(cpu, proc, 10):8.1f} %")
    for t in tasks:
        t.cancel()
    for c in clients + [extra, c0, c9, c1]:
        await c.aclose()
    print(f"  host RSS at end                    {proc.memory_info().rss / 2**20:8.0f} MB")


prepare_data_dir(DATA)
seal_bench()
store_bench()
st = bc.Store(DATA / "backchannel.db")
for i in range(10):
    p = Peer(i)
    st.request_pairing(p.ident.pub, p.name, "")
    st.accept(p.ident.pub, p.name)
st.db.close()
server = subprocess.Popen([sys.executable, __file__, "server", str(DATA)], stderr=subprocess.DEVNULL)
time.sleep(2.5)
try:
    asyncio.run(net_bench(server))
finally:
    server.terminate()
