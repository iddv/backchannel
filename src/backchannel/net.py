"""Network interfaces, address validation and rate limiting."""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections import defaultdict, deque

import psutil

from .config import CGNAT, OVERLAY_PREFIXES, BCError, log
from .messages import clean


def is_overlay(ifname: str, ip: ipaddress.IPv4Address) -> bool:
    return ifname.startswith(OVERLAY_PREFIXES) or ip in CGNAT


def private_interfaces() -> list[tuple[str, ipaddress.IPv4Interface]]:
    """(interface name, address) for each private/overlay IPv4 address, overlay interfaces first."""
    out = []
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            ip = ipaddress.ip_address(a.address)
            if ip.is_loopback or not (ip.is_private or ip in CGNAT):
                continue
            out.append((ifname, ipaddress.IPv4Interface(f"{a.address}/{a.netmask}")))
    out.sort(key=lambda x: (not is_overlay(x[0], x[1].ip), x[0]))
    return out


def bind_interfaces(bind: str) -> list[tuple[str, ipaddress.IPv4Interface]]:
    """`bind` is overlay, private, or a comma-separated list of local IPs."""
    ifaces = private_interfaces()
    if bind == "private":
        return ifaces
    if bind == "overlay":
        overlay = [x for x in ifaces if is_overlay(x[0], x[1].ip)]
        if not overlay:
            log.info("no ZeroTier/Tailscale interface found; listening on all private interfaces")
        return overlay or ifaces
    wanted = {s.strip() for s in bind.split(",") if s.strip()}
    return [x for x in ifaces if str(x[1].ip) in wanted]


def parse_address(address: str, default_port: int) -> tuple[str, int]:
    """Validate a user/peer supplied 'ip[:port]': IPv4 literal on a private, overlay or loopback network only."""
    host, _, port = address.strip().partition(":")
    try:
        ip = ipaddress.IPv4Address(host)
        p = int(port) if port else default_port
    except ValueError:
        raise BCError(f"'{clean(address, 60)}' isn't an IP address (like 10.0.0.5 or 10.0.0.5:8787).") from None
    if not (ip.is_private or ip.is_loopback or ip in CGNAT) or not 0 < p < 65536:
        raise BCError(f"{ip} isn't a private-network address; backchannel only connects within your private network.")
    return str(ip), p


class Limiter:
    """Sliding-window rate limiter. Used from the event loop and the database thread, hence the lock."""

    def __init__(self) -> None:
        self.hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def ok(self, key: str, n: int, per: float) -> bool:
        with self._lock:
            return self._ok(key, n, per)

    def _ok(self, key: str, n: int, per: float) -> bool:
        if key not in self.hits and len(self.hits) >= 50_000:  # spoofed sources can't grow this forever
            self._gc(per)
            if len(self.hits) >= 50_000:
                return False
        now, d = time.monotonic(), self.hits[key]
        while d and now - d[0] > per:
            d.popleft()
        if len(d) >= n:
            return False
        d.append(now)
        return True

    def gc(self, max_age: float = 86400) -> None:
        with self._lock:
            self._gc(max_age)

    def _gc(self, max_age: float) -> None:
        now = time.monotonic()
        for k in [k for k, d in self.hits.items() if not d or now - d[-1] > max_age]:
            del self.hits[k]
