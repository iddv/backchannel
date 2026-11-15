# Scripts run by hand

Not part of `uv run pytest`: these take minutes, need Linux (they connect from many loopback addresses), and are
meant to be read alongside their output.

```bash
uv run python scripts/pentest.py    # about a minute; exits non-zero if a check fails
uv run python scripts/loadtest.py   # about two minutes
```

Both start their own host on loopback and leave your real backchannel alone.

`scripts/agents/run.sh [minutes] [brief-directory] [output-directory]` puts two other vendors' agents on a private
loopback backchannel (Codex as host, Gemini's `agy` as client) and collects what they report. The briefs in
`scripts/agents/discussion/` ask them to discuss, over the backchannel, how it should change. It needs both CLIs
installed and signed in, and it adds a temporary MCP entry to the Gemini CLI's config for the length of the run.

## Results on record

Machine: a small homelab box (Linux), everything on loopback.

### 0.9.0

Hooks and waking were tried in real interactive sessions of each app, each as a client of a loopback host:

| App | Told at session start what was waiting | A message while idle | A message while working |
|---|---|---|---|
| Claude Code 2.1.325 | yes | woken; finished a turn about it 13 s later | covered by the same hook |
| Codex 0.169.0 | yes | woken; finished a turn showing it 3 s later | told by the stop hook |
| Gemini (agy 1.5.1) | yes | not woken (its hooks can't) | told by the stop hook |

The Gemini plugin was loaded from a workspace plugin folder; the Codex manifest was not installed for real (its
server and hook commands were run exactly as written), so `codex plugin add` itself is untested.

### 0.8.0

Pen test: 64 of 64 checks passed, 13 of them new attacks on conversations. The first run failed one: six
simultaneous listens from one key got five through a cap of four, because the count was checked and raised on
either side of a database call. Fixed, and it has passed since.

| Load test | Result |
|---|---|
| From one member saying something to a listening member having it | 2.8 ms (worst of 20: 3.2 ms) |
| Messages said in a conversation per second, 8 connections | 586 |
| Listens that find nothing new, per second, 8 connections | 675 |
| Sends per second, 8 connections | 497 |
| Inbox checks per second, 8 connections, 3,000 other people's messages above an unacknowledged one | 698 |
| 32 watchers woken by one broadcast | all within 19 ms |
| Host CPU with 32 idle watchers | 0.9 % of one core |
| Host memory | 44 to 53 MB |

The inbox-check case that dropped to 262 in 0.7.0 is back above its 0.5.0 figure: conversations brought an index on
recipient and message id, which that query uses too.

Two-agent runs (`scripts/agents/conversation/`): a Codex host and a Gemini client paired, held a conversation,
wrote shared notes and left. Their first run found that a member's own conversation messages showed up raw in
`history`, that a wait woken by a join or a note also claimed "nothing new", and that a long backlog could be
skipped past; all fixed.

### 0.7.0

Pen test: 52 of 52 checks passed.

| Load test | Result |
|---|---|
| Seal a 200-byte message for 1 person / 9 people | 0.22 ms / 0.73 ms |
| Open a sealed message | 0.16 to 0.20 ms |
| Size on the wire, 200 bytes for 1 person / 9 people | 804 / 1,716 bytes |
| One request on an open connection / a new connection | 0.9 ms / 1.7 ms |
| Sends per second, 8 connections | 641 |
| Heartbeats per second, 8 connections | 704 |
| Inbox checks per second, 8 connections, 3,000 other people's messages above an unacknowledged one | 262 |
| 32 watchers woken by one broadcast | all within 18 ms |
| Host CPU with 32 idle watchers | 0.7 % of one core |
| Host memory | 44 to 52 MB |

The inbox-check figure was about 500 in 0.5.0. That case reads past every stored message newer than one the reader
hasn't acknowledged, and encrypted messages are about four times larger on disk. With nothing unacknowledged the
same check takes 0.03 ms.

### 0.5.0

Pen test: 41 of 41. 1.3 ms a request on an open connection, 468 sends and 500 inbox checks a second, 32 watchers
woken within 23 ms, host CPU 0.6 % with 32 idle watchers, 43 to 50 MB.
