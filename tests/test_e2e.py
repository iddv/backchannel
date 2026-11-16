"""End-to-end encryption: the host relays and stores messages it can neither read nor alter."""

import json
import sqlite3

import pytest
from harness import world

from backchannel.config import SEALED_PREFIX, BCError
from backchannel.crypto import Identity, SealError, seal, unseal
from backchannel.host import UNREADABLE
from backchannel.roster import Member, Pins, open_rows

pytestmark = pytest.mark.anyio


@pytest.fixture
def people(tmp_path):
    return [Identity(tmp_path / f"{n}.json") for n in ("ann", "ben", "cat")]


def tampered(body: str, **changes) -> str:
    return SEALED_PREFIX + json.dumps({**json.loads(body[len(SEALED_PREFIX) :]), **changes})


def test_only_the_people_it_is_for_can_read_a_sealed_message(people):
    ann, ben, cat = people
    body = seal(ann, "room", "ben", [ben.pub], "the plan")
    assert "the plan" not in body
    assert unseal(ben, "room", body) | {"ts": 0} == {"sender": ann.pub, "to": "ben", "ts": 0, "text": "the plan"}
    assert unseal(ann, "room", body)["text"] == "the plan"  # the sender can read their own history
    with pytest.raises(SealError, match="wasn't encrypted for this device"):
        unseal(cat, "room", body)


def test_a_sealed_message_cannot_be_altered_moved_or_claimed(people):
    ann, ben, cat = people
    body = seal(ann, "room", "ben", [ben.pub, cat.pub], "the plan")
    env = json.loads(body[len(SEALED_PREFIX) :])
    with pytest.raises(SealError):  # replayed into another backchannel
        unseal(ben, "other-room", body)
    for change in (
        {"to": "all"},
        {"ts": "1"},
        {"ct": env["ct"][:-4] + "AAA="},
        {"from": cat.pub},  # a member who can read it passes it off as their own...
        {"from": cat.pub, "sig": cat.sign(b"anything")},
    ):
        with pytest.raises(SealError):
            unseal(ben, "room", tampered(body, **change))
    for junk in ("", "{}", "[1]", '{"v":1}', "x" * 100_000):
        with pytest.raises(SealError, match="malformed"):
            unseal(ben, "room", SEALED_PREFIX + junk)
    with pytest.raises(BCError, match="too long"):
        seal(ann, "room", "ben", [ben.pub], "x" * 9000)


def test_a_name_on_a_message_must_match_the_key_that_signed_it(people):
    ann, ben, cat = people
    body = seal(ann, "room", "ben", [ben.pub], "zebra")
    row = {"id": 1, "ts": 0.0, "sender": "ann", "recipient": "ben", "body": body}
    keys = {"ann": ann.pub, "cat": cat.pub}
    assert open_rows(ben, "room", "ben", [row], keys.get)[0] | {"ts": 0} == {**row, "body": "zebra", "ok": True}
    # the host relabels it as coming from someone else, or hands it to someone it wasn't addressed to
    for wrong in ({"sender": "cat"}, {"recipient": "all"}):
        out = open_rows(ben, "room", "ben", [{**row, **wrong}], keys.get)[0]
        assert not out["ok"] and "zebra" not in out["body"]
    # and anything that isn't encrypted is never shown, whoever it claims to be from
    out = open_rows(ben, "room", "ben", [{**row, "body": "in the clear"}], keys.get)[0]
    assert not out["ok"] and "in the clear" not in out["body"] and "not end-to-end encrypted" in out["body"]


def test_a_changed_key_is_reported(people, tmp_path):
    ann, _, cat = people
    pins = Pins(tmp_path / "peers.json")
    assert pins.update("room", {"ann": Member("ann", ann.pub, True)}, "ben") == []
    assert pins.update("room", {"ann": Member("ann", ann.pub, True)}, "ben") == []
    notes = pins.update("room", {"ann": Member("ann", cat.pub, True)}, "ben")
    assert "ann now has a different key" in notes[0] and pins.load("room") == {"ann": cat.pub}
    assert pins.load("another-host") == {}


def stored(w, name="iddv") -> list[str]:
    db = sqlite3.connect(w.tmp / name / "backchannel.db")
    try:
        return [r[0] for r in db.execute("SELECT body FROM messages ORDER BY id")]
    finally:
        db.close()


async def test_the_host_stores_only_ciphertext(tmp_path):
    async with world(tmp_path) as w:
        host = await w.agent("host", "iddv")
        sam, bob = await w.agent("client", "sam"), await w.agent("client", "bob")
        await w.pair(host, sam)
        await w.pair(host, bob)

        assert (
            await sam.call("send_message", to="bob", message="bob only: the secret plan") == "Sent message #1 to bob."
        )
        assert "the secret plan" in await bob.call("check_messages")
        assert "the secret plan" in await sam.call("history")  # the sender's own copy
        assert "the secret plan" not in await host.call("history")  # not addressed to the host: not even listed

        assert (await host.call("send_message", to="all", message="everyone: lunch")).startswith("Sent")
        assert "everyone: lunch" in await sam.call("check_messages")
        assert "everyone: lunch" in await bob.call("check_messages")
        assert (await bob.call("send_message", to="iddv", message="host: on my way")).startswith("Sent")
        assert "on my way" in await host.call("check_messages")

        bodies = stored(w)
        assert len(bodies) == 3 and all(b.startswith(SEALED_PREFIX) for b in bodies)
        assert not any(word in b for b in bodies for word in ("secret", "lunch", "on my way"))
        assert "can't read" not in await sam.call("list_peers")


async def test_what_the_host_changes_or_adds_is_not_shown(tmp_path):
    async with world(tmp_path) as w:
        host, sam, bob = await w.agent("host", "iddv"), await w.agent("client", "sam"), await w.agent("client", "bob")
        await w.pair(host, sam)
        await w.pair(host, bob)
        await sam.call("send_message", to="bob", message="first")
        await sam.call("send_message", to="bob", message="second")
        await sam.call("send_message", to="bob", message="third")
        db = sqlite3.connect(w.tmp / "iddv" / "backchannel.db")
        first = db.execute("SELECT body FROM messages WHERE id=1").fetchone()[0]
        db.execute("UPDATE messages SET body=? WHERE id=1", (tampered(first, ct="AAAA"),))
        db.execute("UPDATE messages SET sender='iddv' WHERE id=2")  # relabelled as coming from the host
        db.execute("INSERT INTO messages(ts,sender,recipient,body) VALUES(1,'sam','bob','forged, in the clear')")
        db.commit()
        db.close()
        out = await bob.call("check_messages")
        assert out.count("This message is not shown") == 3 and "third" in out
        assert not any(word in out for word in ("first", "second", "forged"))


async def test_a_member_who_has_not_updated_is_told_and_never_gets_plain_text(relay, tmp_path):
    """`old` signs requests the way 0.6 did (no e2e flag, plain bodies); sam is a real 0.7 client."""
    old = relay.member(tmp_path, "old")
    async with world(tmp_path) as w:
        w.port = relay.port
        sam = await w.agent("client", "sam", popups=False)
        await sam.call("join_host", address=f"bc1:127.0.0.1:{relay.port}:{w.host_fp()}")
        relay.store.accept(next(p.key for p in relay.store.peers("pending")), "sam")

        r = old.post("send", {"to": "sam", "body": "plain from old"})[0]
        assert r.status_code == 422 and "needs backchannel 0.7" in r.json()["error"]  # told why, nothing stored
        assert "No new messages" in await sam.call("check_messages")

        assert "old key" in await sam.call("list_peers") and "until they update" in await sam.call("list_peers")
        out = await sam.call("send_message", to="old", message="for old, later")
        assert out == "Sent message #1 to old. old can't read it until they update to backchannel 0.7."
        assert [m["body"] for m in old.post("check", {})[0].json()["messages"]] == [UNREADABLE]

        # old updates: the same key now reads what was waiting for it
        mine = old.post("history", {"e2e": True})[0].json()["messages"]
        assert unseal(old.ident, relay.hello["key"], mine[0]["body"])["text"] == "for old, later"
        assert "until they update" not in await sam.call("list_peers")

        # a headless host reads nothing: a message to everyone isn't encrypted for it, and it can't be written to
        assert await sam.call("send_message", to="all", message="everyone") == "Sent message #2 to all."
        sealed = old.post("check", {"e2e": True})[0].json()["messages"][-1]["body"]
        assert relay.hello["key"] not in json.loads(sealed[len(SEALED_PREFIX) :])["keys"]
        assert "nobody reads messages there" in await sam.call("send_message", to=relay.name, message="hello?")


async def test_a_broadcast_reaches_every_session_including_the_senders_others(tmp_path):
    async with world(tmp_path) as w:
        host = await w.agent("host", "hana")
        sam, sam2 = await w.agent("client", "sam"), await w.agent("client", "sam", data="sam")
        await w.pair(host, sam)
        assert "No new messages" in await sam2.call("check_messages")

        assert (await host.call("send_message", to="all", message="everyone: lunch")).startswith("Sent")
        for session in (sam, sam2):  # the first reader doesn't use it up
            assert "everyone: lunch" in await session.call("check_messages")
            assert "No new messages" in await session.call("check_messages")

        assert (await sam.call("send_message", to="all", message="from my other window")).startswith("Sent")
        assert "No new messages" in await sam.call("check_messages")  # not back to the session that sent it
        out = await sam2.call("check_messages")
        assert "from my other window" in out and "another session of your own user" in out
        assert "from my other window" in await host.call("check_messages")
