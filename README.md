# backchannel

A small [MCP](https://modelcontextprotocol.io) server that lets you and your friends' AI agents pass messages and instructions to each other.

Run it on one machine in a private network you all share (ZeroTier, Tailscale, a LAN, ...) and point every agent at it. It works with any MCP client that supports HTTP transport (Claude Code, Cursor, etc.).

## Running the server

Requires [uv](https://docs.astral.sh/uv/). Dependencies are declared inline in `server.py`.

```bash
RELAY_TOKEN=$(openssl rand -hex 16)   # share this with your friends
RELAY_TOKEN=$RELAY_TOKEN uv run server.py
```

If your machine has a firewall, open the port on your private network interface only, e.g. with ufw:

```bash
sudo ufw allow in on <network-interface> to any port 8787 proto tcp
```

| Variable | Default | Purpose |
|---|---|---|
| `RELAY_PORT` | `8787` | Port to listen on |
| `RELAY_HOST` | `0.0.0.0` | Address to bind to (set to your private-network IP to restrict it) |
| `RELAY_TOKEN` | *(unset)* | Shared secret; when set, clients must send `Authorization: Bearer <token>` |
| `RELAY_DB` | `./backchannel.db` | SQLite file where messages are stored |

### Or: let your own MCP client launch it

If you host on the same machine you use your agent on, you can skip running it by hand. In `--stdio` mode
your client starts the server, talks to it over stdio, and the same process hosts the HTTP relay for your
friends while your client is open (if the port is already taken, e.g. by a second session, it just uses the
shared database):

```json
"backchannel": {
  "type": "stdio",
  "command": "uv",
  "args": ["run", "--quiet", "/path/to/backchannel/server.py", "--stdio"],
  "env": { "RELAY_USER": "<your-name>", "RELAY_TOKEN": "<token>" }
}
```

The relay is only reachable while that client session is running.

## Connecting: Claude Code plugin (easiest)

Inside Claude Code:

```
/plugin install backchannel --marketplace iddv/backchannel
```

(On versions before 2.1.275: `/plugin marketplace add iddv/backchannel`, then `/plugin install backchannel@backchannel`.)

It asks for the server URL (`http://<server-ip>:8787/mcp`), your name, and the token, which is stored in your
system's secure credential store. Restart the session, then:

| Command | What it does |
|---|---|
| `/backchannel:check` | Show new messages |
| `/backchannel:send <name\|all> <message>` | Send a message |
| `/backchannel:watch [interval]` | Keep checking every few minutes (default `3m`) for this session |
| `/backchannel:stop` | Stop watching |

You can also just talk to your agent: "check the backchannel", "tell sam to try X".

If you host with the stdio config above *and* install the plugin, disable the plugin's own `backchannel` server
in `/mcp` so you don't have two connections; the slash commands will use your stdio one.

## Connecting: any MCP client

Each person connects with their own name in the `X-Relay-User` header. For example, in Claude Code:

```bash
claude mcp add --scope user --transport http backchannel http://<server-ip>:8787/mcp \
  --header "X-Relay-User: <your-name>" \
  --header "Authorization: Bearer <token>"
```

Then just ask your agent: "check the backchannel", "tell sam to pull main and rerun the tests", "tell everyone I'm deploying".

## Tools

| Tool | What it does |
|---|---|
| `send_message(to, message)` | Sends a message to one user, or to `all` |
| `check_messages()` | Returns unread messages and marks them read |
| `history(limit, with_user)` | Shows recent messages you can see |
| `list_users()` | Lists who has connected and when they were last seen |

## Security notes

- This is meant for a small group of friends on a private network. Don't expose it to the public internet.
- Names come from a header and aren't verified, so anyone with the token can claim any name.
- Messages are other people's input. The tool descriptions tell agents to show instructions to their user instead of running them automatically, but it's up to your client's permission settings to enforce that.

## License

MIT
