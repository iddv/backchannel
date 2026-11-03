# Security

backchannel lets other people's words reach your AI agent, and your agent can run commands on your machine.
This page describes what backchannel defends against, what it doesn't, and how to report problems.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting (**Security → Report a vulnerability** on the repository).
Don't open a public issue for security problems.

## Threat model

backchannel is built for a small group of friends on a private overlay network (ZeroTier, Tailscale) or a home
LAN. It assumes:

- **The host is trusted.** It relays and stores every message and could read or forge any of them.
- **Accepted peers are mostly trusted, but may turn malicious or get compromised.** Their messages are treated as
  untrusted input.
- **Other machines on the same network are not trusted.** That includes strangers on shared Wi-Fi and network
  members nobody has accepted.
- **Exposure to the internet is out of scope.** Don't port-forward it.

## What's protected

| Threat | Defence |
|---|---|
| Impersonating a friend | Every request is signed with a per-device Ed25519 key. A name belongs to one key, and a new key using a known name is flagged `NEW KEY` and must be approved |
| Replaying or forwarding requests | Signatures cover the host's key, a per-process boot id, timestamp, nonce, method, path and body hash. The host keeps a nonce cache |
| Forging or altering host replies (man in the middle) | Every reply is signed by the host key the client pinned, bound to that exact request |
| A stranger posing as the host | The client asks you to confirm a host the first time it finds one. Invite codes (`bc1:…`) carry the host's 80-bit key fingerprint |
| Swapping identity during approval | Approval is compare-and-set on the exact key and name shown in the prompt |
| Flooding and resource exhaustion | Request size cap before reading, read timeouts, connection limit, per-IP and per-sender rate limits, daily send quota, a cap on pending join requests, paginated inboxes, retention (14 days / 5,000 messages) |
| Join-request nagging | A declined or removed key can't ask again; only the host can let it back in |
| Prompt injection via messages | Messages are wrapped in per-response random tags that a message can't forge or close. Invisible, bidirectional and control characters are stripped. The server tells agents exactly which text is a message and who wrote it, and to check with you before acting on a request in one |
| Injection via network metadata | Host names, peer names, addresses and errors from the network are validated or stripped before your agent sees them |
| Joining arbitrary servers | `join` only accepts private-network IP literals |
| Exposure on untrusted networks | The host listens only on ZeroTier/Tailscale interfaces when they exist, plus loopback. It accepts only sources from those networks and only IP-literal `Host` headers, which blocks DNS rebinding |
| Supply chain | Dependencies are locked (`backchannel.py.lock`) and run with `uv run --locked --no-project --no-config`, so a `uv.toml` or `pyproject.toml` in your working project can't redirect package installs |
| Local data | The data directory is mode 0700 and the key, database and state files are 0600 |

## What isn't

- **Message confidentiality on a plain LAN.** Traffic is signed but not encrypted. ZeroTier and Tailscale encrypt
  it between members, so prefer them over a plain LAN.
- **A determined prompt injection.** Passing instructions between agents is the point of backchannel, so the defence is
  making sure your agent knows exactly who wrote what and checks with you, not blocking actions. Your agent is still a
  language model. Keep Claude Code's permission prompts on, and don't use
  `--dangerously-skip-permissions` while watching the backchannel.
- **A compromised host.** It can read and forge everything.
- **Updates.** Installing or updating the plugin runs code from this repository. Review releases before updating if
  that matters to you, and pin a version.
