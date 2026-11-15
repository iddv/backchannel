# backchannel

**Pass a note to your friend's coding agent.**

You're debugging over voice chat. "Tell sam to try bumping the timeout to 30s and rerun the tests." backchannel
carries that to sam's Claude Code session, where the agent shows sam and asks before acting. The reply comes back to
the exact session that asked.

- **No cloud service, no accounts.** One of you hosts from a Claude Code session or a homelab box. Traffic stays on
  the private network you already share: ZeroTier, Tailscale or a home LAN.
- **Nothing spent while idle.** `/backchannel:watch` sleeps in the background and wakes your agent only when a
  message arrives.
- **You still call the shots.** A message is someone else's words, never an instruction. Your agent shows it and asks.
- **Conversations, not just notes.** Agents can enter a live conversation you agreed to, talk it through, keep
  shared notes of what was decided, and report back.
- **End-to-end encrypted.** Only the people a message is for can read it. The host relays and stores ciphertext
  and can't read or alter it.
- **Conversations don't get crossed.** With several sessions open, each one stays between the two that started it.
- **Quick to set up.** One plugin install each, then two yes/no confirmations. Hosts are found automatically.
- **Small enough to read.** Under 3,000 lines of Python, requests signed with a key per device, and a
  [plain-language threat model](SECURITY.md).

For small groups who trust each other, not for the open internet.

## Install

Requires Linux or macOS, [uv](https://docs.astral.sh/uv/), Claude Code **2.1.287 or later**, and a shared private network.

Run in Claude Code on each machine:

```text
/plugin install backchannel --marketplace iddv/backchannel
```

Choose a role and name when prompted:

- **host**: one person per group. Relays messages while their Claude Code session stays open.
- **client**: everyone else.
- **name**: use lowercase letters, digits and dashes. Defaults to your OS username. Choose a different name for each person.

Restart Claude Code, or run `/reload-plugins`.

To get new versions automatically, run `/plugin`, open **Marketplaces**, select `backchannel` and choose
**Enable auto-update**. Otherwise update by hand with `/plugin` now and then.

### Host firewall

Allow incoming **TCP and UDP port 8787** on your private network. For ZeroTier with ufw, this allows both:

```bash
sudo ufw allow in on zt+ to any port 8787
```

For other networks, allow the same port on their private interface. On macOS, allow incoming connections for Python when prompted.

### First connection

1. Client runs `/backchannel:check`. It finds the host and asks whether to connect. Confirm yes.
2. Host runs `/backchannel:check` and approves the client.
3. Client runs `/backchannel:check` again. You're connected.

If discovery fails, the host runs `/backchannel:status` and shares an invite code. The client runs:

```text
/backchannel:join <invite-code>
```

Confirm the host, then have the host approve the client as above.

## Commands

| Command | Action |
|---|---|
| `/backchannel:check` | Read new messages; host also handles join requests |
| `/backchannel:send <name\|all> <message>` | Send a message |
| `/backchannel:watch` | Wake this session when a message or join request arrives. Waits in the background and uses no tokens until then |
| `/backchannel:stop` | Stop watching |
| `/backchannel:peers` | List members and, on the host, pending requests |
| `/backchannel:status` | Show role and connection state; host also gets invite codes |
| `/backchannel:join <code\|ip\|ip:port>` | Connect manually |
| `/backchannel:remove <name\|fingerprint>` | Remove or decline someone; host only |

You rarely need the commands: "tell sam to try bumping the timeout" or "anything on the backchannel?" works too.

### Several sessions on one machine

Every Claude Code session on a machine is the same person: one name and one key. Conversations are kept apart per
session, though. When one of your sessions messages sam, the first of sam's sessions to read it claims the
conversation, and from then on replies go only between those two sessions. Another session can start its own
conversation with sam alongside it.

A message to `all`, or a first message nobody has claimed yet, goes to whichever session checks first, and wakes
every session that is watching.

No session ever takes over another's conversation. If a session closes, messages addressed to it stay with it: your
other sessions are told once that they exist, and "show backchannel history" lists them. The next message its
partner sends starts a new conversation with whichever of your sessions reads it. A session that is restarted or
resumed counts as a new one.

On the host's machine, the first session holds the port and relays. Other sessions share its messages, and one of
them takes over within a few seconds if it closes. `/backchannel:status` says which session is hosting.

### Conversations

A message is a note passed along: your agent shows it to you and waits. A conversation is for when you want
something talked through. "Talk to sam's agent about why the build is slow" makes your agent start one and invite
sam. Sam sees the invitation and, if they agree, their agent joins. Three or more can take part.

Inside a conversation the agents answer each other without asking each time; that is what joining means, and it
lasts until the conversation's time limit (30 minutes unless the starter says otherwise) or until an agent leaves.
What it never means: an agent still won't run commands, change files or share anything from your machine because
someone in the conversation asked, without your go-ahead.

Your agent chooses how to wait for the others, and can switch at any point:

- **Waiting in the conversation.** When you've asked it to carry the conversation and aren't waiting on it, each
  thing it says holds until someone answers. The others see it as listening.
- **Getting on with you.** When you're working with it, it sends, tells you, and carries on with you. With
  `/backchannel:watch` running it is woken when a reply arrives.

Anyone in the conversation can write a named entry in its shared notes ("cause: stale cache key"), so the outcome
doesn't get buried in the messages; your agent gives you the notes when it leaves. Conversations are end-to-end
encrypted for exactly their members, and the host never puts them in anyone's ordinary inbox. They need 0.8 or
later on the host and on everyone taking part.

### End-to-end encryption

Since 0.7, every message is encrypted on the sender's machine for exactly the people it is addressed to, and signed.
The host only passes it along: it can't read it, change it, or put someone else's name on it. There is nothing to
set up, because the key each device already has is the one used.

There is no unencrypted mode. A message that wasn't encrypted, or doesn't check out, is never shown; your agent
gets a note saying so instead.

Keys are handed out by the host, so to be sure nobody sits in the middle, compare the key shown for a friend in
"who is on the backchannel?" with the one in their `/backchannel:status`. You are told if a friend's key ever
changes. [SECURITY.md](SECURITY.md) has the details and the limits.

### Updating from 0.6 or earlier

0.7 does not exchange messages with older versions, so everyone needs to update, the host first:

- Through a host older than 0.7, a 0.7 client can't send or read anything, and says so.
- A member older than 0.7 is told to update when they try to send. You can still write to them; they can read it
  once they have updated ("show backchannel history").
- Sessions that were already open keep running the old version until they are restarted.

## Headless host

For an always-on homelab host, clone this repo and run from its directory:

```bash
git clone https://github.com/iddv/backchannel.git
cd backchannel
uv run --locked --no-dev backchannel serve
```

Keep it running, or run it under systemd. Everyone, including the host's owner, installs the plugin as a **client**.

The server takes a name of its own (the OS username by default) and nobody reads its inbox, so nothing is encrypted
for it: a headless host only ever holds ciphertext. Give it a name no person
uses, such as `BACKCHANNEL_NAME=relay`; otherwise a client with the same name is refused as "name taken".

Manage pairing from another terminal:

```bash
uv run --locked --no-dev backchannel status
uv run --locked --no-dev backchannel peers
uv run --locked --no-dev backchannel peers accept <fingerprint> <name>
```

`status` prints invite codes. `peers` lists pending requests for approval.

Set these environment variables consistently for the server and management commands:

| Variable | Default / purpose |
|---|---|
| `BACKCHANNEL_NAME` | OS username; host's name |
| `BACKCHANNEL_DATA` | `~/.local/share/backchannel`; identity and stored data |
| `BACKCHANNEL_BIND` | `overlay`; prefer ZeroTier/Tailscale, fall back to private interfaces. Use `private` or comma-separated local IPs to override |
| `BACKCHANNEL_PORT` | `8787`; TCP and UDP port |

Don't expose the port to the internet. See [SECURITY.md](SECURITY.md) for what is and isn't protected.

## Development

A standard Python project: `pyproject.toml`, the package in `src/backchannel/`, tests in `tests/`, dependencies pinned
in `uv.lock`. The modules are `config` (limits, settings, errors), `crypto` (keys, what gets signed, sealing messages),
`store` (SQLite), `host` (the relay), `client`, `roster` (whose key is whose), `talk` (conversations), `tools`
(what the agent sees) and `cli`.

```bash
uv run pytest                                      # about a minute
uv run ruff check . && uv run ruff format --check .
```

Test hosts listen on loopback only; set `BACKCHANNEL_BIND=private` to also cover LAN binding, as CI does.

`scripts/` holds a pen test and a load test that are run by hand before a release; past results are in
[scripts/README.md](scripts/README.md).
