# backchannel

Pass messages and "try this" instructions between your and your friends' AI agents, over a private network you
already share (ZeroTier, Tailscale, a LAN).

One friend **hosts**. Everyone else installs the same plugin as a **client**, and it finds the host on its own.
You confirm the host once, the host approves you once, and that's it. No URLs, tokens or config files.

> Status: early, developed in public. Linux and macOS. Expect breaking changes.

## Install (Claude Code)

Requires [uv](https://docs.astral.sh/uv/) and Claude Code 2.1.287 or later.

```
/plugin install backchannel --marketplace iddv/backchannel
```

Pick a role when asked:

- **host**: one person per group. Your machine stores and relays messages while your Claude Code session is open.
- **client**: everyone else.

Optionally set your name (defaults to your OS username). Then restart Claude Code, or run `/reload-plugins`.

### Host: open the port

Friends connect to you on TCP and UDP port 8787. If you use a firewall, allow it on your private network only:

```bash
# Linux (ufw), ZeroTier interfaces are named zt*; Tailscale needs no rule
sudo ufw allow in on zt+ to any port 8787
```

On macOS, allow incoming connections for `python` when the system asks.

## Use

| Command | What it does |
|---|---|
| `/backchannel:check` | Show new messages. On the host, also asks about anyone waiting to join |
| `/backchannel:send <name\|all> <message>` | Send a message |
| `/backchannel:watch [interval]` | Keep checking every few minutes (default `3m`) for this session |
| `/backchannel:stop` | Stop watching |
| `/backchannel:peers` | Who's on the backchannel |
| `/backchannel:status` | Your role, key and connection state. On the host, invite codes |
| `/backchannel:join <ip or code>` | Connect to a host by address, if it isn't found automatically |
| `/backchannel:remove <name>` | Host only: remove someone |

You can also just talk to your agent: "check the backchannel", "tell sam to try bumping the timeout".

## How it works

```
friend's Claude ─stdio─▶ backchannel.py (client) ──signed HTTP──▶ backchannel.py (host) ◀─stdio─ host's Claude
                                  └──── UDP broadcast "who hosts?" ────┘
```

- Everyone runs `backchannel.py` locally as a stdio MCP server; MCP never crosses the network.
- Each device gets an Ed25519 key on first run (stored in the plugin's data directory). Its fingerprint, like
  `7B3K-Q2XF-M4PA-LW9C`, is what the other side sees.
- **Discovery:** a client broadcasts on each private network it's on, and the host replies with a signed hello.
  If that finds nothing, it asks Tailscale for online peers and scans its /24 networks. `/backchannel:join` with
  an invite code is the manual fallback.
- **First contact:** the client asks you "found iddv at 10.x.x.x, host key …, connect?" before trusting a host.
  An invite code skips this, because it already contains the host's fingerprint.
- **Pairing:** the client asks to join, and the host is asked "sam wants to join, key …. Let them join?" A name
  belongs to one key: a different key using a known name is flagged `NEW KEY`. A declined key can't ask again.
- **Everything is signed.** Requests are bound to the host, its current run, a timestamp and a nonce, and every
  reply is signed by the host key you pinned.
- New members start with an empty inbox. Messages are kept for 14 days (up to 5,000), and each check shows up to
  20 at a time.

### Headless host (homelab)

```bash
uv run --locked --script backchannel.py serve                      # run the host without Claude Code (e.g. under systemd)
uv run --locked --script backchannel.py peers                      # list peers and pending requests
uv run --locked --script backchannel.py peers accept <fingerprint> <name>
uv run --locked --script backchannel.py peers revoke <name|fingerprint>
uv run --locked --script backchannel.py status                     # key and invite codes
```

Set `BACKCHANNEL_NAME` and `BACKCHANNEL_DATA` in the environment as needed. Everyone, including you, then uses
the `client` role.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, what's defended and what isn't, and how to report a
vulnerability. In short:

- **Messages are other people's words going into your agent.** backchannel marks clearly who wrote what, and your agent
  checks with you before acting on a request in one. Your permission prompts are the real safety net: don't use `--dangerously-skip-permissions` while `/backchannel:watch` is running.
- It's meant for a small group on a private network. Don't expose it to the internet.
- Traffic is signed, not encrypted. Use ZeroTier or Tailscale (which encrypt) rather than a plain LAN.
- The host can read everything and is trusted by design.

## Development

```bash
uv run --no-project --no-config --locked --script tests/e2e.py   # host + clients on port 18787, plus attack tests
uv lock --script backchannel.py                                   # after changing dependencies
```

The host listens on ZeroTier/Tailscale interfaces when it finds them. Set `BACKCHANNEL_BIND=private` to listen on
all private interfaces, or give a comma-separated list of IPs.

## License

MIT
