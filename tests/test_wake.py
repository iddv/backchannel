"""Waking a session that isn't waiting: the hooks each app runs, and how they find their session."""

import asyncio
import json
import os
import subprocess
import sys
import time

import pytest
from harness import Agent, Relay, world

pytestmark = pytest.mark.anyio


def hook(event, app, given=None, env=None, timeout=30):
    return subprocess.run(
        [sys.executable, "-m", "backchannel", "hook", event, app],
        input=json.dumps(given or {}),
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    )


@pytest.fixture
def private_registry(tmp_path, monkeypatch):
    """Each test gets its own registry, and a stand-in `codex` that records how it was called."""
    runtime, bin_ = tmp_path / "run", tmp_path / "bin"
    runtime.mkdir(mode=0o700)
    bin_.mkdir()
    (bin_ / "codex").write_text(f'#!/bin/sh\necho "$@" >> {tmp_path}/codex-calls\n')
    (bin_ / "codex").chmod(0o755)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("PATH", f"{bin_}:{os.environ['PATH']}")
    return runtime / "backchannel"


async def session(w, relay, tmp_path) -> Agent:
    """One agent session, a member of `relay`."""
    w.port = relay.port
    agent = await w.agent("client", "cli", popups=False)
    await agent.call("join_host", address=f"bc1:127.0.0.1:{relay.port}:{w.host_fp()}")
    key = next(p.key for p in relay.store.peers("pending"))
    assert relay.store.accept(key, "cli")
    assert "accepted you" in await agent.call("check_messages")
    return agent


async def test_hooks_find_their_session_and_say_what_arrived(tmp_path, private_registry):
    relay = Relay(tmp_path)
    try:
        sam = relay.member(tmp_path, "sam")
        async with world(tmp_path) as w:
            agent = await session(w, relay, tmp_path)
            me = next(p.key for p in relay.store.peers("accepted") if p.name == "cli")
            assert "wait" in await agent.call("watch_command")  # nothing wakes this session yet

            # nothing waiting: a hook stays out of the way (Gemini still wants JSON back)
            assert hook("session-start", "claude").stdout == "" and hook("stop", "codex").stdout == ""
            assert hook("session-start", "gemini").stdout == "{}" and hook("stop", "gemini").stdout == "{}"

            sam.send("cli", "one", (me,))
            out = hook("session-start", "claude").stdout
            assert "1 new message(s) from sam waiting for you" in out and "one" not in out  # never the message itself
            assert hook("stop", "codex").stdout == ""  # already told about that one

            sam.send("cli", "two", (me,))
            said = json.loads(hook("stop", "codex").stdout)
            assert said["decision"] == "block" and "from sam arrived while you were working" in said["reason"]
            assert hook("stop", "codex").stdout == ""  # each arrival is announced once
            sam.send("cli", "three", (me,))
            assert hook("stop", "codex", {"stop_hook_active": True}).stdout == ""  # never loops
            said = json.loads(hook("stop", "gemini").stdout)
            assert said["decision"] == "continue" and "sam" in said["reason"]
            sam.send("cli", "four", (me,))
            step = json.loads(hook("session-start", "gemini").stdout)["injectSteps"][0]["systemMessage"]
            assert "from sam waiting for you" in step["systemMessage"]

            # Claude Code: a background hook that ends with code 2, which is what wakes an idle session
            waker = subprocess.Popen(
                [sys.executable, "-m", "backchannel", "hook", "wake", "claude"],
                stdin=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            await asyncio.sleep(6)
            assert waker.poll() is None  # quiet: everything so far has been announced
            assert hook("wake", "claude", timeout=20).returncode == 0  # a session only ever has one
            t = time.time()
            sam.send("cli", "five", (me,))
            assert await asyncio.to_thread(waker.wait, 15) == 2 and time.time() - t < 6
            assert "1 new message(s) from sam" in waker.stderr.read()
            assert "already woken automatically" in await agent.call("watch_command")

    finally:
        relay.stop()


async def test_waking_can_be_switched_off(tmp_path, private_registry, monkeypatch):
    relay = Relay(tmp_path)
    monkeypatch.setenv("BACKCHANNEL_WAKE", "off")
    try:
        sam = relay.member(tmp_path, "sam")
        async with world(tmp_path) as w:
            await session(w, relay, tmp_path)
            me = next(p.key for p in relay.store.peers("accepted") if p.name == "cli")
            sam.send("cli", "one", (me,))
            assert hook("stop", "codex").stdout == "" and hook("wake", "claude", timeout=20).returncode == 0
            assert "from sam waiting for you" in hook("session-start", "claude").stdout  # still told at the start
    finally:
        relay.stop()


async def test_codex_is_handed_the_news_by_the_server_itself(tmp_path, private_registry):
    relay = Relay(tmp_path)
    try:
        sam = relay.member(tmp_path, "sam")
        async with world(tmp_path) as w:
            agent = await session(w, relay, tmp_path)
            me = next(p.key for p in relay.store.peers("accepted") if p.name == "cli")
            # Codex's session-start hook says which thread this is; from then on the server wakes it
            assert hook("session-start", "codex", {"session_id": "thread-1234"}).stdout == ""
            entry = json.loads(next(private_registry.glob("*.json")).read_text())
            assert (entry["wakes"], entry["thread"]) == ("codex", "thread-1234")
            await asyncio.sleep(4)
            sam.send("cli", "wake up", (me,))
            calls = tmp_path / "codex-calls"
            for _ in range(40):
                if calls.exists():
                    break
                await asyncio.sleep(0.25)
            said = calls.read_text()
            assert said.startswith("queue --thread thread-1234 --message backchannel: 1 new message(s) from sam")
            await asyncio.sleep(3)
            assert calls.read_text() == said  # once per arrival
            assert "wake up" in await agent.call("check_messages")
    finally:
        relay.stop()


def test_a_hook_with_no_session_does_nothing_at_all(tmp_path, private_registry):
    home = tmp_path / "home"
    home.mkdir()
    for event, app in (("session-start", "claude"), ("stop", "gemini"), ("nonsense", "codex")):
        r = hook(event, app, env={"HOME": str(home)}, timeout=40)
        assert r.returncode == 0 and r.stdout in ("", "{}")
    assert list(home.iterdir()) == []  # no identity, no data directory, nothing


def test_the_registry_must_be_private(tmp_path, monkeypatch):
    from backchannel import wake

    shared = tmp_path / "run"
    shared.mkdir()
    (shared / "backchannel").mkdir(mode=0o777)
    (shared / "backchannel").chmod(0o777)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(shared))
    with pytest.raises(OSError, match="not private"):
        wake.registry()
