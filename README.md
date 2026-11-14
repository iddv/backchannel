# backchannel

Let your friends' Claude Code agents pass messages and "try this" instructions to each other over a shared private network like ZeroTier or Tailscale.

One person hosts. Everyone else finds the host automatically. The client confirms the host, the host approves the client: one yes/no on each side.

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

You can also say "tell sam to try bumping the timeout." Received requests are shown to you; your agent asks before acting.

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

### Mixed versions

0.4 talks to 0.3 in both directions. Waking on arrival needs a 0.4 host; against a 0.3 host `/backchannel:watch`
falls back to checking every 3 minutes (or the interval you pass, e.g. `/backchannel:watch 10m`).
Per-session conversations need a 0.4 host; a 0.3 client on it behaves as one shared session, as before.

## Headless host

For an always-on homelab host, clone this repo and run from its directory:

```bash
git clone https://github.com/iddv/backchannel.git
cd backchannel
uv run --locked --script backchannel.py serve
```

Keep it running, or run it under systemd. Everyone, including the host's owner, installs the plugin as a **client**.

The server takes a name of its own (the OS username by default) and nobody reads its inbox. Give it a name no person
uses, such as `BACKCHANNEL_NAME=relay`; otherwise a client with the same name is refused as "name taken".

Manage pairing from another terminal:

```bash
uv run --locked --script backchannel.py status
uv run --locked --script backchannel.py peers
uv run --locked --script backchannel.py peers accept <fingerprint> <name>
```

`status` prints invite codes. `peers` lists pending requests for approval.

Set these environment variables consistently for the server and management commands:

| Variable | Default / purpose |
|---|---|
| `BACKCHANNEL_NAME` | OS username; host's name |
| `BACKCHANNEL_DATA` | `~/.local/share/backchannel`; identity and stored data |
| `BACKCHANNEL_BIND` | `overlay`; prefer ZeroTier/Tailscale, fall back to private interfaces. Use `private` or comma-separated local IPs to override |
| `BACKCHANNEL_PORT` | `8787`; TCP and UDP port |

For small trusted groups on private networks. Don't expose it to the internet. See [SECURITY.md](SECURITY.md).

## Tests

From the repo directory:

```bash
uv run --no-project --no-config --locked --script tests/e2e.py
```