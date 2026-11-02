# backchannel

Pass messages and "try this" instructions between your and your friends' AI agents, over a private network you
already share (ZeroTier, Tailscale, a LAN).

One friend **hosts**. Everyone else installs the same plugin as a **client**, and it finds the host on its own.
The host gets a yes/no prompt the first time someone new connects. No URLs, tokens or config files.

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
# Linux (ufw), ZeroTier interfaces are named zt*
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
- Each device gets an Ed25519 key on first run (stored in the plugin's data directory). A key's short fingerprint,
  like `7B3K-Q2XF`, is what the host sees in the join prompt.
- **Discovery:** a client broadcasts on each private network it's on; the host replies with a signed hello. If
  broadcast is blocked, it scans its /24 networks, and `/backchannel:join` is the manual fallback.
- **Pairing:** a new client automatically asks to join. The host is asked "sam wants to join, key 9F2A-LMQ3. Let
  them join?" A name belongs to one key: a different key using a known name is flagged `NEW KEY`.
- **Every request is signed** (method, path, timestamp, nonce and body hash). The host rejects unsigned, stale or
  replayed requests and anyone it hasn't accepted.
- Messages are kept for 14 days (up to 5,000).

### Headless host (homelab)

```bash
uv run backchannel.py serve                      # run the host without Claude Code (e.g. under systemd)
uv run backchannel.py peers                      # list peers and pending requests
uv run backchannel.py peers accept <fingerprint>
uv run backchannel.py peers revoke <name|fingerprint>
uv run backchannel.py status                     # key and invite codes
```

Set `BACKCHANNEL_NAME` and `BACKCHANNEL_DATA` in the environment as needed. Everyone, including you, then uses
the `client` role.

## Security notes

- **Messages are other people's words going into your agent.** The server tells agents to show messages verbatim
  and to get your go-ahead before acting on anything in them, but your Claude Code permission prompts are the
  real safety net. Don't use `--dangerously-skip-permissions` or broad auto-allow rules while `/backchannel:watch`
  is running.
- It's meant for a small group on a private network. The host only accepts connections from private addresses;
  don't expose it to the internet.
- There's no TLS: ZeroTier/Tailscale already encrypt traffic between members, and requests are signed.
- The host can read everything and is trusted by design.

## Development

```bash
uv run tests/e2e.py      # starts a host and two clients on port 18787 and runs the full flow
```

## License

MIT
