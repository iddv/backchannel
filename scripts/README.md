# Scripts run by hand

Not part of `uv run pytest`: these take minutes, need Linux (they connect from many loopback addresses), and are
meant to be read alongside their output.

```bash
uv run python scripts/pentest.py    # about a minute; exits non-zero if a check fails
uv run python scripts/loadtest.py   # about two minutes
```

Both start their own host on loopback and leave your real backchannel alone.

## Results on record

Machine: a small homelab box (Linux), everything on loopback.

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
