"""The host's SQLite store: peers, messages, read state and session routing."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import time
from dataclasses import dataclass, fields
from pathlib import Path

from .config import (
    BROADCAST_TTL,
    CHECK_MAX_BYTES,
    CHECK_MAX_MESSAGES,
    MAX_BODY,
    PENDING_TTL,
    RETENTION_DAYS,
    RETENTION_MAX,
    SESSION_TTL,
    log,
    valid_name,
)
from .crypto import canonical_key, fingerprint, is_sealed, norm_fp


@dataclass
class Peer:
    key: str
    name: str
    fp: str
    status: str  # pending | accepted | revoked
    addr: str
    updated: float
    joined_id: int
    e2e: int  # has used a backchannel that can end-to-end encrypt (0.7 or later)


PEER_FIELDS = tuple(f.name for f in fields(Peer))
PEER_COLS = ",".join(PEER_FIELDS)


def _peer(row: tuple) -> Peer:
    return Peer(**dict(zip(PEER_FIELDS, row, strict=True)))


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=5)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        # with WAL this still can't corrupt the database; a power cut may lose the last moments. Without it every
        # write waits for the disk (3 ms on a hard drive), several times per request.
        self.db.execute("PRAGMA synchronous=NORMAL")
        self._migrate()
        self.lock_down()

    def _migrate(self) -> None:
        """Bring the database up to the current schema. `PRAGMA user_version` records which steps have run; a step
        is one function, runs once inside a transaction, and is never edited after release."""
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > len(self._MIGRATIONS):
            log.warning("this database was written by a newer backchannel (schema %s); carrying on", version)
        for step in range(version, len(self._MIGRATIONS)):
            with self.tx():
                self._MIGRATIONS[step](self)
                self.db.execute(f"PRAGMA user_version={step + 1}")

    def _schema_1(self) -> None:
        """Schema 1 is where version numbers start. Databases from 0.2 to 0.4 carry no number and can be in any of
        several shapes, so this step is written to be safe on all of them, and on an empty file."""
        ex = self.db.execute
        ex(
            "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, "
            "sender TEXT NOT NULL, recipient TEXT NOT NULL, body TEXT NOT NULL)"
        )
        ex("CREATE INDEX IF NOT EXISTS messages_sender_ts ON messages(sender, ts)")
        ex("CREATE TABLE IF NOT EXISTS cursors (user TEXT PRIMARY KEY, last_id INTEGER NOT NULL)")
        ex(
            "CREATE TABLE IF NOT EXISTS peers (key TEXT PRIMARY KEY, name TEXT NOT NULL, fp TEXT NOT NULL, "
            "status TEXT NOT NULL, addr TEXT NOT NULL DEFAULT '', updated REAL NOT NULL)"
        )

        def add_column(table: str, column: str, decl: str) -> None:
            if column not in {r[1] for r in ex(f"PRAGMA table_info({table})")}:
                ex(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

        add_column("peers", "joined_id", "INTEGER NOT NULL DEFAULT 0")  # since 0.3
        add_column("messages", "sender_sid", "TEXT NOT NULL DEFAULT ''")  # since 0.4; '' = no particular session
        add_column("messages", "recipient_sid", "TEXT NOT NULL DEFAULT ''")
        add_column("messages", "noted", "INTEGER NOT NULL DEFAULT 0")  # user was told it is stranded
        # rows written by 0.2: drop malformed ones, recompute fingerprints (0.2 used 40 bits), one key per name
        seen: set[str] = set()
        for key, name, status in ex("SELECT key,name,status FROM peers ORDER BY updated DESC").fetchall():
            if canonical_key(key) != key or not valid_name(name):
                ex("DELETE FROM peers WHERE key=?", (key,))
                continue
            if status == "accepted":
                if name in seen:
                    ex("UPDATE peers SET status='revoked' WHERE key=?", (key,))
                seen.add(name)
            ex("UPDATE peers SET fp=? WHERE key=?", (fingerprint(key), key))
        ex("CREATE UNIQUE INDEX IF NOT EXISTS one_accepted_name ON peers(name) WHERE status='accepted'")
        # last_wait is unused since 0.4.1 but stays: sessions still running 0.4.0 write to it
        ex(
            "CREATE TABLE IF NOT EXISTS sessions (user TEXT NOT NULL, sid TEXT NOT NULL, last_seen REAL NOT NULL, "
            "last_wait REAL NOT NULL DEFAULT 0, PRIMARY KEY(user, sid))"
        )
        # links: `user`'s session `sid` is in conversation with `peer`'s session `peer_sid`
        ex(
            "CREATE TABLE IF NOT EXISTS links (user TEXT NOT NULL, sid TEXT NOT NULL, peer TEXT NOT NULL, "
            "peer_sid TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(user, sid, peer))"
        )
        # readmarks: messages read out of order (another session's are still waiting below them)
        ex(
            "CREATE TABLE IF NOT EXISTS readmarks (user TEXT NOT NULL, msg_id INTEGER NOT NULL, "
            "PRIMARY KEY(user, msg_id))"
        )
        ex("CREATE TABLE IF NOT EXISTS sends (sender TEXT NOT NULL, ts REAL NOT NULL)")
        ex("CREATE INDEX IF NOT EXISTS sends_sender_ts ON sends(sender, ts)")

    def _schema_2(self) -> None:
        """0.7: who has used a version that can read end-to-end encrypted messages."""
        self.db.execute("ALTER TABLE peers ADD COLUMN e2e INTEGER NOT NULL DEFAULT 0")

    def _schema_3(self) -> None:
        """0.8: conversations. Their messages live in `messages` with recipient '#<id>', which keeps them out of
        everyone's ordinary inbox; who has been handed what is tracked per member here."""
        ex = self.db.execute
        ex(
            "CREATE TABLE conversations (id TEXT PRIMARY KEY, creator TEXT NOT NULL, created REAL NOT NULL, "
            "expires REAL NOT NULL, rev INTEGER NOT NULL DEFAULT 1)"
        )
        # state: invited | joined | left. sid: the session that joined. seen: the last message handed to them
        ex(
            "CREATE TABLE conv_members (conv TEXT NOT NULL, user TEXT NOT NULL, state TEXT NOT NULL, "
            "sid TEXT NOT NULL DEFAULT '', seen INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL, "
            "PRIMARY KEY(conv, user))"
        )
        ex("CREATE INDEX messages_recipient_id ON messages(recipient, id)")

    def _schema_4(self) -> None:
        """0.10: a broadcast is handed to every session, so which session has had which is tracked here."""
        self.db.execute(
            "CREATE TABLE seen (user TEXT NOT NULL, sid TEXT NOT NULL, msg_id INTEGER NOT NULL, "
            "PRIMARY KEY(user, sid, msg_id))"
        )

    _MIGRATIONS = (_schema_1, _schema_2, _schema_3, _schema_4)

    def lock_down(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.chmod(f"{self.path}{suffix}", 0o600)

    @contextlib.contextmanager
    def tx(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    # peers
    def peer(self, key: str) -> Peer | None:
        r = self.db.execute(f"SELECT {PEER_COLS} FROM peers WHERE key=?", (key,)).fetchone()
        return _peer(r) if r else None

    def peers(self, status: str | None = None) -> list[Peer]:
        q, a = f"SELECT {PEER_COLS} FROM peers", ()
        if status:
            q, a = q + " WHERE status=?", (status,)
        return [_peer(r) for r in self.db.execute(q + " ORDER BY name", a)]

    def by_fp(self, ref: str) -> list[Peer]:
        want = norm_fp(ref)
        return [p for p in self.peers() if norm_fp(p.fp) == want] if len(want) == 16 else []

    def by_name_or_fp(self, ref: str) -> list[Peer]:
        return self.by_fp(ref) or [p for p in self.peers() if p.name == ref.strip().lower()]

    def request_pairing(self, key: str, name: str, addr: str) -> None:
        self.db.execute(
            "INSERT INTO peers(key,name,fp,status,addr,updated,joined_id) VALUES(?,?,?,'pending',?,?,0) "
            "ON CONFLICT(key) DO UPDATE SET name=excluded.name, status='pending', addr=excluded.addr, "
            "updated=CASE WHEN peers.status='pending' THEN peers.updated ELSE excluded.updated END",
            (key, name, fingerprint(key), addr, time.time()),
        )

    def accept(self, key: str, expected_name: str, from_status: tuple[str, ...] = ("pending",)) -> bool:
        """Compare-and-set: accept only if the row still has the name and status the user was shown."""
        with self.tx():
            r = self.db.execute("SELECT name,status FROM peers WHERE key=?", (key,)).fetchone()
            if not r or r[0] != expected_name or r[1] not in from_status:
                return False
            # a name belongs to one key: the newly accepted key replaces any older one
            self.db.execute(
                "UPDATE peers SET status='revoked', updated=? WHERE name=? AND key!=? AND status='accepted'",
                (time.time(), expected_name, key),
            )
            top = self.db.execute("SELECT COALESCE(MAX(id),0) FROM messages").fetchone()[0]
            self.db.execute(
                "UPDATE peers SET status='accepted', updated=?, joined_id=? WHERE key=?", (time.time(), top, key)
            )
            # a new member starts with an empty inbox and can't read what was sent before they joined
            self.db.execute(
                "INSERT INTO cursors(user,last_id) VALUES(?,?) "
                "ON CONFLICT(user) DO UPDATE SET last_id=excluded.last_id",
                (expected_name, top),
            )
            for q in ("DELETE FROM readmarks WHERE user=?", "DELETE FROM sessions WHERE user=?"):
                self.db.execute(q, (expected_name,))
            self.db.execute("DELETE FROM links WHERE user=? OR peer=?", (expected_name, expected_name))
        return True

    def revoke(self, key: str) -> None:
        self.db.execute("UPDATE peers SET status='revoked', updated=? WHERE key=?", (time.time(), key))

    def expire_pending(self) -> None:
        self.db.execute("DELETE FROM peers WHERE status='pending' AND updated<?", (time.time() - PENDING_TTL,))

    def pending_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM peers WHERE status='pending'").fetchone()[0]

    def accepted_names(self) -> set[str]:
        return {p.name for p in self.peers("accepted")}

    def joined_id(self, user: str) -> int:
        r = self.db.execute("SELECT joined_id FROM peers WHERE name=? AND status='accepted'", (user,)).fetchone()
        return r[0] if r else 0

    # messages
    def add(self, sender: str, recipient: str, body: str, sender_sid: str = "", recipient_sid: str = "") -> int:
        return self.db.execute(
            "INSERT INTO messages(ts,sender,recipient,body,sender_sid,recipient_sid) VALUES(?,?,?,?,?,?)",
            (time.time(), sender, recipient, body, sender_sid, recipient_sid),
        ).lastrowid

    def sent_since(self, sender: str, seconds: float) -> int:
        """From a separate log, so pruning old messages can't reset anyone's daily quota."""
        return self.db.execute(
            "SELECT COUNT(*) FROM sends WHERE sender=? AND ts>?", (sender, time.time() - seconds)
        ).fetchone()[0]

    def record_send(self, sender: str) -> None:
        self.db.execute("INSERT INTO sends(sender,ts) VALUES(?,?)", (sender, time.time()))

    # sessions: a person can have several agent sessions open. A conversation locks to the two sessions in it:
    # the one that sent the first message and the one that first read it. Replies then go only to those two, and
    # no other session ever takes a conversation over. If a session closes, what was addressed to it stays with
    # it (readable in history); the next message its partner sends starts a new conversation.
    def touch(self, user: str, sid: str) -> None:
        """Record that this session is still open."""
        if sid:
            self.db.execute(
                "INSERT INTO sessions(user,sid,last_seen) VALUES(?,?,?) ON CONFLICT(user,sid) "
                "DO UPDATE SET last_seen=excluded.last_seen",
                (user, sid, time.time()),
            )

    def set_e2e(self, key: str) -> None:
        self.db.execute("UPDATE peers SET e2e=1 WHERE key=?", (key,))

    def live_sessions(self, user: str) -> list[str]:
        """Sessions that are still open: each one calls in every HEARTBEAT seconds."""
        return [
            r[0]
            for r in self.db.execute(
                "SELECT sid FROM sessions WHERE user=? AND last_seen>?", (user, time.time() - SESSION_TTL)
            )
        ]

    def linked(self, user: str, sid: str, peer: str) -> str:
        r = self.db.execute(
            "SELECT peer_sid FROM links WHERE user=? AND sid=? AND peer=?", (user, sid, peer)
        ).fetchone()
        return r[0] if r else ""

    def link(self, user: str, sid: str, peer: str, peer_sid: str) -> None:
        for a in ((user, sid, peer, peer_sid), (peer, peer_sid, user, sid)):
            self.db.execute(
                "INSERT INTO links(user,sid,peer,peer_sid,updated) VALUES(?,?,?,?,?) ON CONFLICT(user,sid,peer) "
                "DO UPDATE SET peer_sid=excluded.peer_sid, updated=excluded.updated",
                (*a, time.time()),
            )

    def _cursor(self, user: str) -> int:
        r = self.db.execute("SELECT last_id FROM cursors WHERE user=?", (user,)).fetchone()
        return max(r[0] if r else 0, self.joined_id(user))

    def _unread(self, user: str, sid: str = "", after: int = 0) -> tuple[str, list]:
        """WHERE clause for what `user` hasn't read. Without a session id (v0.3 clients, and the bookkeeping for
        the name as a whole): everything for the name that no session has read. With one: unclaimed messages and
        this session's own, plus every broadcast this session hasn't been handed, for as long as nobody under the
        name has read it or it is younger than BROADCAST_TTL. That includes broadcasts from the user's other
        sessions, which are only ever new while they are that young."""
        cursor = self._cursor(user)
        mine = "id>? AND sender!=? AND id NOT IN (SELECT msg_id FROM readmarks WHERE user=?)"
        if not sid:
            return f"WHERE {mine} AND (recipient=? OR recipient='all')", [max(cursor, after), user, user, user]
        where = (
            f"WHERE id>? AND (({mine} AND recipient=? AND recipient_sid IN ('',?)) OR ("
            "recipient='all' AND id NOT IN (SELECT msg_id FROM seen WHERE user=? AND sid=?) AND ("
            f"({mine}) OR (ts>? AND (sender!=? OR sender_sid NOT IN ('',?))))))"
        )
        direct = [cursor, user, user]
        return where, [
            max(self.joined_id(user), after), *direct, user, sid, user, sid, *direct, time.time() - BROADCAST_TTL,
            user, sid,
        ]  # fmt: skip

    def stranded(self, user: str, sid: str, note: bool = False) -> dict:
        """Unread messages addressed to a session of `user` that has closed. They are never handed to another
        session; a session that checks is told once (`note`) so the user can read them in history."""
        if not sid:
            return {"count": 0, "from": []}
        live = self.live_sessions(user)
        where, args = self._unread(user)
        others = ",".join("?" * (2 + len(live)))  # '', this session, and every session that is still open
        rows = self.db.execute(
            f"SELECT id,sender FROM messages {where} AND recipient=? AND noted=0 AND recipient_sid NOT IN ({others}) "
            "ORDER BY id LIMIT 200",
            (*args, user, "", sid, *live),
        ).fetchall()
        if note and rows:
            self.db.executemany("UPDATE messages SET noted=1 WHERE id=?", [(r[0],) for r in rows])
        return {"count": len(rows), "from": sorted({r[1] for r in rows if valid_name(r[1])})[:10]}

    def _mark(self, user: str, ids: list[int], sid: str = "") -> None:
        """Mark messages read, then move the cursor up to just below the oldest one still unread by anyone. A
        broadcast is also marked as handed to this session, since it stays new for the user's other sessions."""
        self.db.executemany("INSERT OR IGNORE INTO readmarks(user,msg_id) VALUES(?,?)", [(user, i) for i in ids])
        if sid:
            self.db.executemany(
                "INSERT OR IGNORE INTO seen(user,sid,msg_id) "
                "SELECT ?,?,id FROM messages WHERE id=? AND recipient='all'",
                [(user, sid, i) for i in ids],
            )
            # a mark only matters while its broadcast is young enough to be handed out again
            self.db.execute(
                "DELETE FROM seen WHERE msg_id<COALESCE("
                "(SELECT MIN(id) FROM messages WHERE ts>?), (SELECT MAX(id)+1 FROM messages))",
                (time.time() - BROADCAST_TTL,),
            )
        where, args = self._unread(user)
        low = self.db.execute(f"SELECT MIN(id) FROM messages {where}", args).fetchone()[0]
        top = self.db.execute("SELECT COALESCE(MAX(id),0) FROM messages").fetchone()[0]
        new = low - 1 if low else top
        self.db.execute(
            "INSERT INTO cursors(user,last_id) VALUES(?,?) "
            "ON CONFLICT(user) DO UPDATE SET last_id=MAX(last_id, excluded.last_id)",
            (user, new),
        )
        self.db.execute("DELETE FROM readmarks WHERE user=? AND msg_id<=?", (user, new))

    def ack(self, user: str, upto: object, sid: str = "") -> None:
        """Mark as read everything this session could see up to message id `upto`."""
        if not isinstance(upto, int) or isinstance(upto, bool) or upto <= 0:
            return
        where, args = self._unread(user, sid)
        ids = [r[0] for r in self.db.execute(f"SELECT id FROM messages {where} AND id<=?", (*args, upto))]
        if ids:
            with self.tx():
                self._mark(user, ids, sid)

    def waiting(self, user: str, after: object = 0, sid: str = "") -> dict:
        """What's unread for this session beyond message id `after`, without marking anything read."""
        after = after if isinstance(after, int) and not isinstance(after, bool) else 0
        where, args = self._unread(user, sid, after)
        rows = self.db.execute(f"SELECT id,sender FROM messages {where} ORDER BY id LIMIT 200", args).fetchall()
        lost = self.stranded(user, sid)  # someone should hear about these, so they wake a watcher too
        return {
            "unread": len(rows) + lost["count"],
            "latest": rows[-1][0] if rows else 0,
            "from": sorted({r[1] for r in rows if valid_name(r[1])} | set(lost["from"]))[:10],
        }

    def unread(self, user: str, hold: bool = False, sid: str = "") -> tuple[list[dict], int]:
        """Up to CHECK_MAX_MESSAGES / CHECK_MAX_BYTES new messages, and how many more remain. With `hold` they
        stay unread until the reader acknowledges them, so a reply lost on the way isn't lost for good. Reading a
        direct message claims it: that conversation now belongs to this session and the sender's."""
        self.touch(user, sid)
        where, args = self._unread(user, sid)
        rows, size = [], 0
        for m in self._rows(where + " ORDER BY id LIMIT ?", (*args, CHECK_MAX_MESSAGES)):
            # the budget is about what the agent ends up reading; an encrypted body is its text in base64, plus keys
            size += min(len(m["body"]) * 3 // 4, MAX_BODY) if is_sealed(m["body"]) else len(m["body"].encode())
            if rows and size > CHECK_MAX_BYTES:
                break
            rows.append(m)
        with self.tx():
            for m in rows:
                ssid, rsid = self.db.execute(
                    "SELECT sender_sid,recipient_sid FROM messages WHERE id=?", (m["id"],)
                ).fetchone()
                if sid and m["recipient"] == user and not rsid:
                    self.db.execute("UPDATE messages SET recipient_sid=? WHERE id=?", (sid, m["id"]))
                    if ssid:
                        self.link(user, sid, m["sender"], ssid)
                        # and anything else that session already sent, beyond this page
                        self.db.execute(
                            "UPDATE messages SET recipient_sid=? WHERE recipient=? AND sender=? AND "
                            "sender_sid=? AND recipient_sid='' AND id>?",
                            (sid, user, m["sender"], ssid, m["id"]),
                        )
            if rows and not hold:
                self._mark(user, [m["id"] for m in rows], sid)
        where, args = self._unread(user, sid)  # the cursor may have moved
        total = self.db.execute(f"SELECT COUNT(*) FROM messages {where}", args).fetchone()[0]
        return rows, total - (len(rows) if hold else 0)

    def unread_count(self, user: str, sid: str = "") -> int:
        where, args = self._unread(user, sid)
        return self.db.execute(f"SELECT COUNT(*) FROM messages {where}", args).fetchone()[0]

    def history(self, user: str, limit: int, with_user: str | None) -> list[dict]:
        # conversations ('#id') have their own way in; here they would show as one side's raw protocol messages
        where = "WHERE id>? AND (recipient=? OR recipient='all' OR sender=?) AND recipient NOT LIKE '#%'"
        a = [self.joined_id(user), user, user]
        if with_user:
            where += " AND (sender=? OR recipient=?)"
            a += [with_user, with_user]
        a.append(max(1, min(int(limit), 50)))
        return list(reversed(self._rows(where + " ORDER BY id DESC LIMIT ?", a)))

    def _rows(self, where: str, args) -> list[dict]:
        cur = self.db.execute(f"SELECT id,ts,sender,recipient,body FROM messages {where}", args)
        return [dict(zip(("id", "ts", "sender", "recipient", "body"), r, strict=True)) for r in cur]

    # conversations: a live exchange between named members, each taking part from one session. Membership is
    # fixed when it starts. It ends at its time limit, or when everyone who joined has left.
    def conv_create(self, conv: str, creator: str, sid: str, invited: list[str], minutes: float) -> bool:
        now = time.time()
        with self.tx():
            if self.db.execute("SELECT 1 FROM conversations WHERE id=?", (conv,)).fetchone():
                return False
            self.db.execute(
                "INSERT INTO conversations(id,creator,created,expires) VALUES(?,?,?,?)",
                (conv, creator, now, now + minutes * 60),
            )
            rows = [(conv, creator, "joined", sid, now), *((conv, n, "invited", "", now) for n in invited)]
            self.db.executemany("INSERT INTO conv_members(conv,user,state,sid,updated) VALUES(?,?,?,?,?)", rows)
        return True

    def conv(self, conv: str) -> dict | None:
        r = self.db.execute("SELECT creator,expires,rev FROM conversations WHERE id=?", (conv,)).fetchone()
        if not r:
            return None
        members = {
            m[0]: {"state": m[1], "sid": m[2], "seen": m[3], "updated": m[4]}
            for m in self.db.execute("SELECT user,state,sid,seen,updated FROM conv_members WHERE conv=?", (conv,))
        }
        over = time.time() >= r[1] or (
            any(m["state"] == "left" for m in members.values())
            and not any(m["state"] == "joined" for m in members.values())
        )
        return {"id": conv, "creator": r[0], "expires": r[1], "rev": r[2], "ended": over, "members": members}

    def conv_set(self, conv: str, user: str, state: str, sid: str = "") -> None:
        """A member joins or leaves. Bumps the revision, which is what tells waiting members something changed."""
        with self.tx():
            self.db.execute(
                "UPDATE conv_members SET state=?, sid=?, updated=? WHERE conv=? AND user=?",
                (state, sid, time.time(), conv, user),
            )
            self.db.execute("UPDATE conversations SET rev=rev+1 WHERE id=?", (conv,))

    def conv_seen(self, conv: str, user: str, upto: int) -> None:
        self.db.execute("UPDATE conv_members SET seen=MAX(seen,?) WHERE conv=? AND user=?", (upto, conv, user))

    def conv_messages(self, conv: str, after: int, reader: str, limit: int) -> list[dict]:
        """What others have said in the conversation since message id `after`."""
        return self._rows(
            "WHERE recipient=? AND id>? AND sender!=? ORDER BY id LIMIT ?", (f"#{conv}", after, reader, limit)
        )

    def conv_transcript(self, conv: str, after: int, limit: int, until: float | None = None) -> list[dict]:
        """Everything said in the conversation, by anyone, after message id `after` (and up to time `until`)."""
        where, args = "WHERE recipient=? AND id>?", [f"#{conv}", after]
        if until is not None:
            where, args = where + " AND ts<=?", [*args, until]
        return self._rows(where + " ORDER BY id LIMIT ?", (*args, limit))

    def conv_unread(self, user: str, sid: str, skip: tuple[str, ...] = (), after: int = 0) -> dict:
        """Conversation messages not yet handed to this session (and newer than `after`), so a watcher can wake
        it."""
        count, who, latest = 0, set(), 0
        mine = self.db.execute(
            "SELECT m.conv, m.seen FROM conv_members m JOIN conversations c ON c.id=m.conv "
            "WHERE m.user=? AND m.state='joined' AND m.sid=? AND c.expires>?",
            (user, sid, time.time()),
        ).fetchall()
        for conv, seen in mine:
            if conv in skip:
                continue
            for sender, mid in self.db.execute(
                "SELECT sender, id FROM messages WHERE recipient=? AND id>? AND sender!=? ORDER BY id LIMIT 200",
                (f"#{conv}", max(seen, after), user),
            ):
                count, latest = count + 1, max(latest, mid)
                who.add(sender)
        return {"count": count, "from": sorted(n for n in who if valid_name(n))[:10], "latest": latest}

    def convs_for(self, user: str) -> list[dict]:
        """Conversations `user` is invited to or taking part in that are still going."""
        out = []
        ids = self.db.execute(
            "SELECT m.conv FROM conv_members m JOIN conversations c ON c.id=m.conv "
            "WHERE m.user=? AND m.state!='left' AND c.expires>? ORDER BY c.created",
            (user, time.time()),
        ).fetchall()
        for (cid,) in ids:
            c = self.conv(cid)
            if c and not c["ended"]:
                me = c["members"][user]
                unread = self.db.execute(
                    "SELECT COUNT(*) FROM messages WHERE recipient=? AND id>? AND sender!=?",
                    (f"#{cid}", me["seen"], user),
                ).fetchone()[0]
                others = sorted(n for n in c["members"] if n != user)
                out.append(
                    {"id": cid, "state": me["state"], "sid": me["sid"], "with": others, "by": c["creator"]}
                    | {"unread": unread}
                )
        return out

    def prune(self) -> None:
        old = time.time() - RETENTION_DAYS * 86400
        self.db.execute("DELETE FROM conv_members WHERE conv IN (SELECT id FROM conversations WHERE expires<?)", (old,))
        self.db.execute("DELETE FROM conversations WHERE expires<?", (old,))
        self.db.execute("DELETE FROM sends WHERE ts<?", (time.time() - 86400,))
        self.db.execute("DELETE FROM messages WHERE ts<?", (time.time() - RETENTION_DAYS * 86400,))
        self.db.execute(
            "DELETE FROM messages WHERE id NOT IN (SELECT id FROM messages ORDER BY id DESC LIMIT ?)", (RETENTION_MAX,)
        )
        self.db.execute("DELETE FROM readmarks WHERE msg_id < (SELECT COALESCE(MIN(id),0) FROM messages)")
        self.db.execute("DELETE FROM sessions WHERE last_seen<?", (time.time() - 86400,))
        self.db.execute("DELETE FROM links WHERE updated<?", (time.time() - RETENTION_DAYS * 86400,))


def describe_request(store: Store, p: Peer) -> str:
    others = [q for q in store.peers() if q.name == p.name and q.key != p.key and q.status != "pending"]
    flag = ""
    if any(q.status == "accepted" for q in others):
        flag = f" (NEW KEY: '{p.name}' is already on your backchannel with a different key)"
    elif others:
        flag = f" (the name '{p.name}' was used before by a key you removed)"
    return f"'{p.name}'{flag} wants to join, key {p.fp}, from {p.addr or 'unknown address'}"
