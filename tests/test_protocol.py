"""Raw signed requests against a headless host: the wire protocol, and the attacks the real client won't make."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from harness import hello, respell

from backchannel.config import SEALED_PREFIX


def url(relay, path):
    return f"http://127.0.0.1:{relay.port}{path}"


def test_names_that_could_mislead_are_rejected(relay, tmp_path):
    mal = relay.raw(tmp_path)
    assert mal.post("pair", {"name": "sam\n"})[0].json()["error"] == "bad_name"
    assert mal.post("pair", {"name": "abcd-efgh-ijkl-mnop"})[0].json()["error"] == "bad_name"  # looks like a key
    assert mal.post("pair", {"name": relay.name})[0].json()["error"] == "name_taken"
    assert mal.post("pair", {"name": "all"})[0].json()["error"] == "bad_name"


def test_a_stranger_can_ask_to_pair_but_not_use_the_relay(relay, tmp_path):
    guest = relay.raw(tmp_path)
    r, _ = guest.post("send", {"to": relay.name, "body": "hi"})
    assert (r.status_code, r.json()["error"]) == (403, "not_paired")
    assert guest.post("pair", {"name": "guest"})[0].status_code == 202
    r, _ = guest.post("check", {})
    assert (r.status_code, r.json()["error"]) == (401, "pending")
    assert guest.post("whoami", {})[0].json()["status"] == "pending"


def test_pairing_requests_are_rate_limited_and_capped(relay, tmp_path):
    codes = [relay.raw(tmp_path).post("pair", {"name": f"g{i}"})[0].status_code for i in range(7)]
    assert codes[:5] == [202] * 5 and set(codes[5:]) == {429}, codes


def test_respelling_a_declined_key_does_not_make_a_new_identity(relay, tmp_path):
    mal = relay.raw(tmp_path)
    mal.post("pair", {"name": "guest"})
    relay.store.revoke(mal.ident.pub)
    r, _ = mal.post("pair", {"name": "guest2"}, key=respell(mal.ident.pub))
    assert r.json()["error"] == "declined"


def test_a_replayed_request_is_rejected(relay, tmp_path):
    raw = relay.raw(tmp_path)
    r, sent = raw.post("whoami", {})
    assert r.status_code == 200
    assert raw.post("whoami", {}, reuse=sent)[0].json()["error"] == "replay"


def test_malformed_and_unsigned_requests_get_a_plain_400(relay, tmp_path):
    raw = relay.raw(tmp_path)
    r, _ = raw.post("whoami", {}, headers_override={"x-bc-ts": "9" * 400})
    assert (r.status_code, r.json()["error"]) == (400, "unsigned")
    r, _ = raw.post("whoami", {}, headers_override={"x-bc-sig": "AAAA"})
    assert (r.status_code, r.json()["error"]) == (400, "bad_signature")
    r, _ = raw.post("whoami", {}, headers_override={"x-bc-ts": str(int(time.time() * 1000) - 600_000)})
    assert r.json()["error"] == "clock_skew"
    r = httpx.post(url(relay, "/api/check"), content=b"{}", trust_env=False)
    assert r.json()["error"] == "unsigned"
    assert "x-bc-sig" not in r.headers


def test_bodies_that_are_not_what_they_claim_do_not_crash_the_host(relay, tmp_path):
    sam = relay.member(tmp_path, "sam")
    for payload in ([1, 2], "text", None, 7):
        r, _ = sam.post("check", payload)
        assert (r.status_code, r.json()["error"]) == (400, "bad_request"), payload
    assert sam.post("history", {"limit": "many"})[0].status_code == 400
    assert sam.post("history", {"limit": 10**30, "with": {"a": 1}})[0].status_code == 200
    assert sam.post("send", {"to": ["all"], "body": {"x": 1}})[0].status_code == 422  # refused, as text
    assert sam.post("wait", {"timeout": 0, "after": "x", "sid": {"no": 1}})[0].status_code == 200
    assert sam.post("ack", {"id": "9"})[0].status_code == 200
    assert sam.post("../hello", {})[0].status_code == 405  # normalised to POST /hello, which doesn't exist
    assert sam.post("nope", {})[0].json()["error"] == "unknown_op"
    assert hello(relay.port).json()["name"] == relay.name


def test_oversized_request_is_refused_before_it_is_read(relay):
    with socket.create_connection(("127.0.0.1", relay.port), timeout=5) as s:
        s.sendall(
            f"POST /api/check HTTP/1.1\r\nHost: 127.0.0.1:{relay.port}\r\nContent-Length: 999999999\r\n\r\nx".encode()
        )
        assert b" 413 " in s.recv(200)


def test_non_ip_host_header_is_refused(relay):
    """Defeats DNS rebinding from a browser on the host's machine."""
    assert hello(relay.port, headers={"host": "evil.example"}).status_code == 403


def test_idle_connections_are_capped_per_address(relay):
    conns = [socket.create_connection(("127.0.0.1", relay.port), timeout=5) for _ in range(8)]
    ninth = socket.create_connection(("127.0.0.1", relay.port), timeout=5)
    assert ninth.recv(1) == b""  # closed straight away
    for c in [*conns, ninth]:
        c.close()
    time.sleep(0.2)
    assert hello(relay.port).json()["name"] == relay.name


def test_a_v03_style_check_marks_messages_read(relay, tmp_path):
    old = relay.member(tmp_path, "oldie")
    relay.store.add(relay.name, "oldie", "one")
    assert len(old.post("check", {})[0].json()["messages"]) == 1
    assert old.post("check", {})[0].json()["messages"] == []


def test_wait_reports_unread_without_reading(relay, tmp_path):
    sam = relay.member(tmp_path, "sam")
    relay.store.add(relay.name, "sam", "two")
    r = sam.post("wait", {"after": 0, "timeout": 0})[0].json()
    assert (r["unread"], r["from"]) == (1, [relay.name])
    assert len(sam.post("check", {})[0].json()["messages"]) == 1


def test_held_messages_are_redelivered_until_acknowledged(relay, tmp_path):
    sam = relay.member(tmp_path, "sam")
    relay.store.add(relay.name, "sam", "one")
    first = sam.post("check", {"hold": True})[0].json()["messages"][0]["id"]
    assert sam.post("check", {"hold": True})[0].json()["messages"][0]["id"] == first
    sam.post("ack", {"id": 10**9})
    assert sam.post("check", {"hold": True})[0].json()["messages"] == []
    relay.store.add(relay.name, "sam", "two")
    assert len(sam.post("check", {})[0].json()["messages"]) == 1  # the huge ack didn't swallow it


def test_wait_holds_then_reports_nothing_new(relay, tmp_path):
    sam = relay.member(tmp_path, "sam")
    t0 = time.time()
    r = sam.post("wait", {"after": 0, "timeout": 2})[0].json()
    assert r["unread"] == 0 and 1.5 < time.time() - t0 < 6


def test_wait_answers_as_soon_as_a_message_is_sent(relay, tmp_path):
    sam, bob = relay.member(tmp_path, "sam"), relay.member(tmp_path, "bob")
    with ThreadPoolExecutor() as pool:
        waiting = pool.submit(lambda: (sam.post("wait", {"after": 0, "timeout": 20})[0].json(), time.time()))
        time.sleep(1.5)
        sent = time.time()
        assert bob.send("sam", "now").status_code == 200
        answer, at = waiting.result(10)
    assert answer["unread"] == 1 and at - sent < 1.0, at - sent


def test_long_polls_are_capped_per_key(relay, tmp_path):
    sam = relay.member(tmp_path, "sam")
    with ThreadPoolExecutor(8) as pool:
        held = [pool.submit(lambda: sam.post("wait", {"after": 0, "timeout": 4})[0].status_code) for _ in range(4)]
        time.sleep(1.5)
        r, _ = sam.post("wait", {"after": 0, "timeout": 4})
        assert (r.status_code, r.json()["error"]) == (429, "too_many_waits")
        assert [h.result(15) for h in held] == [200] * 4


def test_a_removed_member_is_cut_off_mid_wait(relay, tmp_path):
    sam = relay.member(tmp_path, "sam")
    with ThreadPoolExecutor() as pool:
        waiting = pool.submit(lambda: sam.post("wait", {"after": 0, "timeout": 20})[0])
        time.sleep(1.5)
        relay.store.revoke(sam.ident.pub)
        r = waiting.result(10)
    assert (r.status_code, r.json()["error"]) == (403, "declined")
    assert sam.send(relay.name, "x").json()["error"] == "declined"


def test_send_limits(relay, tmp_path):
    sam = relay.member(tmp_path, "sam")
    assert "too long" in sam.post("send", {"to": relay.name, "body": SEALED_PREFIX + "x" * 25000})[0].json()["error"]
    assert "Unknown recipient" in sam.send("nobody", "x").json()["error"]
    assert "needs backchannel 0.7" in sam.post("send", {"to": relay.name, "body": "in the clear"})[0].json()["error"]
    codes = [sam.send(relay.name, "x").status_code for _ in range(22)]
    assert codes[:20] == [200] * 20 and codes[20:] == [422, 422], codes
