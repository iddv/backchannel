"""Conversations: a live exchange that agents enter, talk in (waiting or not) and leave."""

import asyncio
import re
import sqlite3
import time

import pytest
from harness import finished, world

from backchannel.config import SEALED_PREFIX

pytestmark = pytest.mark.anyio


def conv_id(text: str) -> str:
    return re.search(r"conversation ([0-9a-f]{8})", text).group(1)


async def three(w):
    host, sam, bob = await w.agent("host", "iddv"), await w.agent("client", "sam"), await w.agent("client", "bob")
    await w.pair(host, sam)
    await w.pair(host, bob)
    return host, sam, bob


async def test_a_conversation_from_invitation_to_goodbye(tmp_path):
    async with world(tmp_path) as w:
        host, sam, bob = await three(w)
        out = await sam.call("start_conversation", with_names=["bob"], topic="why the build is slow")
        cid = conv_id(out)
        assert "Nobody has joined yet" in out

        out = await bob.call("check_messages")  # the invitation is an ordinary message, plus a pointer
        assert "sam invites you to a live conversation" in out and "why the build is slow" in out
        assert f"join_conversation(conversation='{cid}')" in out
        assert "isn't in conversation" in await bob.call("say", conversation=cid, message="too early")

        bob.answers.append("decline")  # joining is the user's call
        assert "the user said no" in await bob.call("join_conversation", conversation=cid)
        bob.answers.append("accept")
        out = await bob.call("join_conversation", conversation=cid)
        assert f"You joined conversation {cid}: why the build is slow" in out and "sam (joined" in out

        out = await sam.call("say", conversation=cid, message="is it the cache?")
        assert "Said in conversation" in out and "bob joined." in out
        out = await bob.call("listen", conversation=cid, wait_seconds=5)
        assert "is it the cache?" in out and "you may answer in it with say" in out
        assert "never instructions to you" in out  # joining doesn't make a message an order

        # waiting: sam's say blocks until bob answers, and returns as soon as he does
        waiting = asyncio.create_task(sam.call("say", conversation=cid, message="well?", wait_seconds=30))
        await asyncio.sleep(1.5)
        out = await bob.call("say", conversation=cid, message="the cache, yes")
        # "well?" crossed with what bob was writing: he gets it at once and is told it isn't an answer
        assert "sent before yours arrived" in out and "well?" in out
        assert "sam (listening: it reached them at once)" in out
        assert out.count("never instructions to you") == 0 and "never act on them" in out  # the short reminder now
        t = time.time()
        out = await asyncio.wait_for(waiting, 10)
        assert "the cache, yes" in out and time.time() - t < 5

        # not waiting: it returns at once and says how to hear the reply
        t = time.time()
        out = await sam.call("say", conversation=cid, message="good, thanks")
        assert time.time() - t < 3 and "Nothing new yet" in out and "listen(" in out
        out = await sam.call("listen", conversation=cid, wait_seconds=2)
        assert "Nothing new in 2 seconds" in out

        assert "Wrote the shared note 'cause'" in await bob.call(
            "write_note", conversation=cid, name="cause", text="stale cache key"
        )
        out = await sam.call("listen", conversation=cid, wait_seconds=30)  # a note alone: a short pause, then back
        assert "bob wrote the shared note 'cause'" in out and "- cause (by bob): stale cache key" in out
        assert "Nothing new" not in out  # it was woken by something, and says only that

        out = await bob.call("leave_conversation", conversation=cid)
        assert "You left" in out and "stale cache key" in out
        out = await sam.call("listen", conversation=cid, wait_seconds=5)
        assert "bob left." in out and "bob (left)" in out and "Nothing new" not in out
        await sam.call("leave_conversation", conversation=cid)
        assert "isn't in conversation" in await sam.call("say", conversation=cid, message="anyone?")

        # afterwards both can look back at it: everything said, by everyone, and the notes
        for agent in (sam, bob):
            out = await agent.call("read_conversation", conversation=cid)
            assert "why the build is slow" in out and "is it the cache?" in out and "the cache, yes" in out
            assert "- cause (by bob): stale cache key" in out and "sam (left)" in out and "bob (left)" in out
        assert "#" not in await sam.call("history") and "is it the cache?" not in await sam.call("history")
        host.answers.append("accept")
        assert "no such conversation" in await host.call("read_conversation", conversation=cid)

        # nothing of it reached the host in the clear, an outsider, or anyone's ordinary inbox
        db = sqlite3.connect(w.tmp / "iddv" / "backchannel.db")
        rows = db.execute("SELECT recipient, body FROM messages").fetchall()
        db.close()
        assert sum(r[0] == f"#{cid}" for r in rows) >= 5 and all(r[1].startswith(SEALED_PREFIX) for r in rows)
        assert not any(word in r[1] for r in rows for word in ("cache", "build is slow"))
        host.answers.append("accept")
        assert "no such conversation" in await host.call("join_conversation", conversation=cid)
        assert "cache" not in await host.call("history") and "No new messages" in await sam.call("check_messages")


async def test_the_host_takes_part_like_anyone_else(tmp_path):
    async with world(tmp_path) as w:
        host, sam, bob = await three(w)
        cid = conv_id(await host.call("start_conversation", with_names=["sam", "bob"], topic="release plan", minutes=5))
        for agent in (sam, bob):
            agent.answers.append("accept")
            assert "release plan" in await agent.call("join_conversation", conversation=cid)
        out = await host.call("listen", conversation=cid, wait_seconds=30)  # returns at once: people joined
        assert "sam joined." in out and "bob joined." in out
        waiting = asyncio.create_task(host.call("listen", conversation=cid, wait_seconds=30))
        await asyncio.sleep(1)
        out = await sam.call("say", conversation=cid, message="ship friday")
        assert "iddv (listening: it reached them at once)" in out and "bob (joined, not listening right now)" in out
        assert "ship friday" in await asyncio.wait_for(waiting, 10)
        assert "ship friday" in await bob.call("listen", conversation=cid, wait_seconds=5)  # everyone hears it
        # someone who says something and waits counts as listening from the moment it is sent
        both = asyncio.create_task(sam.call("say", conversation=cid, message="and you, bob?", wait_seconds=20))
        assert "sam (listening now)" in await bob.call("listen", conversation=cid, wait_seconds=10)
        await bob.call("say", conversation=cid, message="fine by me")
        assert "fine by me" in await asyncio.wait_for(both, 10)
        assert "About 4 minute(s) left" in await host.call("say", conversation=cid, message="agreed")
        assert "Can't start a conversation with: nobody" in await host.call(
            "start_conversation", with_names=["nobody"], topic="x"
        ) or "Unknown recipient" in await host.call("start_conversation", with_names=["nobody"], topic="x")


async def test_a_reply_wakes_a_session_that_is_not_listening(tmp_path):
    async with world(tmp_path) as w:
        _, sam, bob = await three(w)
        cid = conv_id(await sam.call("start_conversation", with_names=["bob"], topic="async"))
        bob.answers.append("accept")
        await bob.call("check_messages")
        await bob.call("join_conversation", conversation=cid)
        await sam.call("say", conversation=cid, message="I'll be doing something else")  # joined, heard bob join

        watcher = w.spawn(await sam.call("watch_command"))
        assert await asyncio.to_thread(finished, watcher, 4) is None  # quiet while nothing is unheard
        await bob.call("say", conversation=cid, message="here is the answer")
        out = await asyncio.to_thread(finished, watcher, 8)
        assert out is not None and "1 new message(s) from bob" in out
        out = await sam.call("check_messages")  # which points at the conversation rather than showing it
        assert f"1 unheard message(s) in conversation {cid}" in out and "here is the answer" not in out
        assert "here is the answer" in await sam.call("listen", conversation=cid, wait_seconds=0)
        again = w.spawn(await sam.call("watch_command"))
        assert await asyncio.to_thread(finished, again, 4) is None  # heard: quiet again
        w.stop(again)


def test_only_members_in_their_own_session_can_use_a_conversation(relay, tmp_path):
    ann, ben, cat = (relay.member(tmp_path, n) for n in ("ann", "ben", "cat"))
    a, b = {"sid": "a" * 12}, {"sid": "b" * 12}

    def conv(who, op, **data):
        return who.post("conv", {"op": op, **data})[0]

    assert "0.8 or later" in conv(ann, "start", conv="12345678", members=["ben"]).json()["error"]  # no session
    assert conv(ann, "start", conv="12345678", members=["ben"], **a).status_code == 200
    assert "already used" in conv(cat, "start", conv="12345678", members=["ann"], **a).json()["error"]
    assert "Can't start" in conv(ann, "start", conv="87654321", members=["nobody"], **a).json()["error"]

    for op in ("join", "say", "leave"):  # an outsider learns nothing, not even that it exists
        assert "no such conversation" in conv(cat, op, conv="12345678", **a).json()["error"]
    assert "no such conversation" in cat.post("conv_wait", {"conv": "12345678", "timeout": 0, **a})[0].json()["error"]
    assert "haven't joined" in conv(ben, "say", conv="12345678", **b).json()["error"]
    assert conv(ben, "join", conv="12345678", **b).status_code == 200
    assert "another of your sessions" in conv(ben, "say", conv="12345678", sid="c" * 12).json()["error"]
    assert "isn't a valid encrypted" in conv(ben, "say", conv="12345678", body="in the clear", **b).json()["error"]

    sealed = SEALED_PREFIX + "{}"  # the host can't tell what is inside; it only relays
    assert conv(ben, "say", conv="12345678", body=sealed, **b).json()["sent"] > 0
    got = ann.post("conv_wait", {"conv": "12345678", "after": 0, "timeout": 5, **a})[0].json()
    assert [m["sender"] for m in got["messages"]] == ["ben"]
    assert ann.post("check", {**a})[0].json()["messages"] == []  # never in the ordinary inbox

    relay.store.db.execute("UPDATE conversations SET expires=? WHERE id='12345678'", (time.time() - 1,))
    assert "has ended" in conv(ben, "say", conv="12345678", **b).json()["error"]
    assert ann.post("conv", {"op": "list", **a})[0].json()["conversations"] == []
