"""The store on its own: quotas, upgrades from older databases, and how conversations lock to sessions."""

import sqlite3
import time

import pytest
from harness import Identity, Store, respell

from backchannel.config import SESSION_TTL
from backchannel.host import Host

X, Y, S1, S2 = "a" * 12, "b" * 12, "c" * 12, "d" * 12  # two of ann's sessions, two of ben's


def test_pruning_messages_does_not_reset_the_daily_quota(tmp_path):
    st = Store(tmp_path / "unit.db")
    for _ in range(300):
        st.record_send("spammer")
        st.add("spammer", "all", "x")
    for _ in range(5100):
        st.add("other", "all", "y")
    st.prune()
    assert st.sent_since("spammer", 86400) == 300


def test_old_databases_are_revalidated_and_versioned(tmp_path):
    """A 0.2-style file: a bad name, a non-canonical key, and two accepted rows sharing a name."""
    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE peers (key TEXT PRIMARY KEY, name TEXT NOT NULL, fp TEXT NOT NULL, "
        "status TEXT NOT NULL, addr TEXT NOT NULL DEFAULT '', updated REAL NOT NULL)"
    )
    keys = [Identity(tmp_path / f"k{i}.json").pub for i in range(4)]
    rows = [
        (keys[0], "good", "accepted", 1),
        (keys[1], "bad\n", "accepted", 2),
        (respell(keys[2]), "badkey", "accepted", 3),
        (keys[2], "dup", "accepted", 4),
        (keys[3], "dup", "accepted", 5),
    ]
    db.executemany("INSERT INTO peers VALUES(?,?,'x',?,'',?)", rows)
    db.commit()
    db.close()

    st = Store(path)
    names = {(p.name, p.status) for p in st.peers()}
    assert ("good", "accepted") in names
    assert not any(n.startswith("bad") for n, _ in names)
    assert sum(1 for n, s in names if n == "dup" and s == "accepted") == 1
    assert st.db.execute("PRAGMA user_version").fetchone()[0] == 1
    st.db.close()
    again = Store(path)  # opening an up-to-date database changes nothing
    assert {(p.name, p.status) for p in again.peers()} == names


def test_a_fresh_database_starts_at_the_current_schema(tmp_path):
    st = Store(tmp_path / "new.db")
    assert st.db.execute("PRAGMA user_version").fetchone()[0] == len(Store._MIGRATIONS)
    assert st.unread("nobody")[0] == []


class Chat:
    """ann hosts, ben is a member; both have two sessions open."""

    def __init__(self, tmp):
        self.store = Store(tmp / "lock.db")
        self.host = Host(Identity(tmp / "ann.json"), self.store, "ann", 1)
        ben = Identity(tmp / "ben.json").pub
        self.store.request_pairing(ben, "ben", "")
        assert self.store.accept(ben, "ben")
        for user, sid in (("ann", X), ("ann", Y), ("ben", S1), ("ben", S2)):
            self.store.touch(user, sid)

    def say(self, sender, to, body, sid):
        self.host.send(sender, to, body, sid)

    def got(self, user, sid="", hold=False):
        return [m["body"] for m in self.store.unread(user, hold, sid)[0]]

    def close(self, sid):
        self.store.db.execute("UPDATE sessions SET last_seen=? WHERE sid=?", (time.time() - SESSION_TTL - 5, sid))


@pytest.fixture
def chat(tmp_path):
    return Chat(tmp_path)


def test_the_first_session_to_read_a_message_claims_it(chat):
    chat.say("ann", "ben", "q1", X)
    chat.say("ann", "ben", "q2", X)
    assert chat.store.waiting("ben", sid=S1)["unread"] == 2  # offered to every session...
    assert chat.store.waiting("ben", sid=S2)["unread"] == 2
    assert chat.got("ben", S1) == ["q1", "q2"]  # ...until one reads it
    assert chat.got("ben", S2) == []


def test_replies_and_later_messages_stay_between_the_two_sessions(chat):
    chat.say("ann", "ben", "q1", X)
    chat.got("ben", S1)
    chat.say("ben", "ann", "a1", S1)
    assert chat.got("ann", Y) == []
    assert chat.got("ann", X) == ["a1"]
    chat.say("ann", "ben", "q2", X)
    assert chat.got("ben", S2) == []
    assert chat.store.waiting("ben", sid=S2)["unread"] == 0
    assert chat.got("ben", S1) == ["q2"]


def test_another_session_can_hold_its_own_conversation(chat):
    chat.say("ann", "ben", "from x", X)
    chat.got("ben", S1)
    chat.say("ann", "ben", "from y", Y)
    chat.say("ann", "ben", "more from x", X)
    assert chat.got("ben", S2) == ["from y"]  # read out of order: x's message is still waiting for S1
    assert chat.got("ben", S1) == ["more from x"]


def test_broadcasts_reach_whichever_session_checks_first(chat):
    chat.say("ben", "all", "news", S1)
    assert chat.got("ann", Y) == ["news"]
    assert chat.got("ann", X) == []


def test_a_client_without_sessions_sees_everything_for_its_name(chat):
    chat.say("ann", "ben", "q1", X)
    chat.got("ben", S1)
    chat.say("ann", "ben", "q2", X)
    assert chat.got("ben") == ["q2"]  # how a 0.3 client reads


def test_held_messages_stay_unread_until_acknowledged(chat):
    chat.say("ann", "ben", "q1", X)
    assert chat.got("ben", S1, hold=True) == ["q1"]
    assert chat.got("ben", S1, hold=True) == ["q1"]
    chat.store.ack("ben", 10**9, S1)  # an ack can't run past the newest message
    assert chat.got("ben", S1) == []
    chat.say("ann", "ben", "q2", X)
    assert chat.got("ben", S1) == ["q2"]


def test_read_state_collapses_back_to_one_cursor(chat):
    chat.say("ann", "ben", "for s1", X)
    chat.got("ben", S1)
    chat.say("ann", "ben", "for s1 again", X)
    chat.say("ann", "ben", "for s2", Y)
    chat.got("ben", S2)
    assert chat.store.db.execute("SELECT COUNT(*) FROM readmarks").fetchone()[0] == 1
    chat.got("ben", S1)
    assert chat.store.db.execute("SELECT COUNT(*) FROM readmarks").fetchone()[0] == 0
    assert chat.store._cursor("ben") == chat.store.db.execute("SELECT MAX(id) FROM messages").fetchone()[0]


def test_a_closed_sessions_messages_are_never_handed_to_another_session(chat):
    chat.say("ann", "ben", "q1", X)
    chat.got("ben", S1)
    chat.say("ann", "ben", "q2", X)
    chat.close(S1)
    assert chat.got("ben", S2) == []
    assert chat.store.waiting("ben", sid=S2)["unread"] == 1  # but a watcher is woken...
    assert chat.store.stranded("ben", S2, note=True) == {"count": 1, "from": ["ann"]}  # ...and the user told, once
    assert chat.store.stranded("ben", S2)["count"] == 0
    assert chat.store.waiting("ben", sid=S2)["unread"] == 0
    chat.store.touch("ben", S1)
    assert chat.got("ben", S1) == ["q2"]  # if the session comes back, they are still there for it


def test_the_next_message_to_a_closed_session_starts_a_new_conversation(chat):
    chat.say("ann", "ben", "q1", X)
    chat.got("ben", S1)
    chat.close(S1)
    chat.say("ann", "ben", "q2", X)
    assert chat.got("ben", S2) == ["q2"]
    chat.store.touch("ben", S1)
    chat.say("ann", "ben", "q3", X)
    assert chat.got("ben", S1) == []
    assert chat.got("ben", S2) == ["q3"]  # and it stays with the session that picked it up
