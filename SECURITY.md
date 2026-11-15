# Security

backchannel lets other people's words reach your AI agent, and your agent can run commands on your machine.
This page describes what backchannel defends against, what it doesn't, and how to report problems.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting (**Security → Report a vulnerability** on the repository).
Don't open a public issue for security problems.

## Threat model

backchannel is built for a small group of friends on a private overlay network (ZeroTier, Tailscale) or a home
LAN. It assumes:

- **The host is trusted to run the group, not with its contents.** It decides who is a member and hands out
  everyone's keys. Since 0.7 it relays and stores messages it can't read or alter (see end-to-end encryption below).
- **Accepted peers are mostly trusted, but may turn malicious or get compromised.** Their messages are treated as
  untrusted input.
- **Other machines on the same network are not trusted.** That includes strangers on shared Wi-Fi and network
  members nobody has accepted.
- **Exposure to the internet is out of scope.** Don't port-forward it.

## What's protected

| Threat | Defence |
|---|---|
| The host (or anyone who breaks into it) reading or changing messages | Messages are end-to-end encrypted and signed on the sender's machine: X25519 key agreement from each device's existing Ed25519 key, a fresh key per message, ChaCha20-Poly1305, and an Ed25519 signature by the sender. The sender, recipient, time and the backchannel it belongs to are bound into the encryption, so a message can't be re-attributed, redirected or moved to another group. One that fails any check is not shown |
| The host swapping someone's key to sit in the middle | Each client remembers the key it first saw for every member and tells you when one changes. Key fingerprints are shown in the member list so you can compare them out of band |
| The host switching encryption off, or slipping in messages of its own | There is no unencrypted mode. Every message is sent encrypted, and one that arrives unencrypted is never shown, whatever name is on it |
| Impersonating a friend | Every request is signed with a per-device Ed25519 key. A name belongs to one key, and a new key using a known name is flagged `NEW KEY` and must be approved |
| Replaying or forwarding requests | Signatures cover the host's key, a per-process boot id, timestamp, nonce, method, path and body hash. The host keeps a nonce cache |
| Forging or altering host replies (man in the middle) | Every reply is signed by the host key the client pinned, bound to that exact request |
| A stranger posing as the host | The client asks you to confirm a host the first time it finds one. Invite codes (`bc1:…`) carry the host's 80-bit key fingerprint. Where the app can't show a popup, an explicit join with a matching invite code counts as your confirmation, so the tool-permission prompt for `join_host` is the gate |
| Swapping identity during approval | Approval is compare-and-set on the exact key and name shown in the prompt |
| Flooding and resource exhaustion | Request size cap before reading, read timeouts, connection limit, per-IP and per-sender rate limits, daily send quota, a cap on pending join requests, a cap on held-open waits (4 per key, 32 in total, 45 s each), paginated inboxes, retention (14 days / 5,000 messages) |
| Join-request nagging | A declined or removed key can't ask again; only the host can let it back in |
| An agent talking on its own without being asked | Outside a conversation an agent never replies on its own. A conversation needs the user to start it or to agree to an invitation (with a popup where the app has one), is bound to the session that joined, ends at a time limit, and only ever covers talking: its messages are still marked as other people's words, not instructions |
| Reading a conversation you aren't in | Its messages are encrypted for exactly its members and are only handed to a member's joined session. To anyone else the host answers as if the conversation didn't exist |
| Prompt injection via messages | Messages are wrapped in per-response random tags that a message can't forge or close. Invisible, bidirectional and control characters are stripped. The server tells agents exactly which text is a message and who wrote it, and to check with you before acting on a request in one |
| Injection via network metadata | Host names, peer names, addresses and errors from the network are validated or stripped before your agent sees them |
| Joining arbitrary servers | `join` only accepts private-network IP literals |
| Scanning networks that aren't yours | The background watcher never sweeps addresses; other actions sweep a subnet at most once every 10 minutes |
| Exposure on untrusted networks | The host listens only on ZeroTier/Tailscale interfaces when they exist, plus loopback. It accepts only sources from those networks and only IP-literal `Host` headers, which blocks DNS rebinding. It re-checks its interfaces every 15 s, so it moves to the overlay when that comes up |
| Supply chain | Dependencies are pinned with hashes in `uv.lock`, and the plugin starts with `uv run --project <plugin> --locked --no-config`, so a `uv.toml` or `pyproject.toml` in the project you are working on can't redirect package installs |
| Local data | The data directory is mode 0700 and the key, database and state files are 0600 |

## What isn't

- **Metadata.** The host, and anyone watching a plain LAN, sees who writes to whom, when, and roughly how much,
  and for a conversation who its members are and who is listening.
  Member lists and requests are signed but not encrypted. ZeroTier and Tailscale hide all of it from outsiders.
- **A lying host the first time you meet someone.** Your client learns each member's key from the host. A malicious
  host could hand out a key of its own for a member you have never exchanged messages with, and read what you send
  them. Comparing fingerprints with your friend rules it out; a later swap is always reported.
- **Dropped, delayed, reordered or repeated messages.** The host delivers, so it can also not deliver, or deliver
  twice. A repeated message still shows the time its sender signed.
- **Forward secrecy.** Keys are long-lived. Someone who records the ciphertext and later steals a device's
  `identity.json` can read that device's past messages.
- **A determined prompt injection.** Passing instructions between agents is the point of backchannel, so the defence is
  making sure your agent knows exactly who wrote what and checks with you, not blocking actions. Your agent is still a
  language model. Keep Claude Code's permission prompts on, and don't use
  `--dangerously-skip-permissions` while watching the backchannel.
- **A compromised host, beyond the above.** It can't read or forge encrypted messages, but it can let new members
  in, remove people, withhold messages and see the metadata.
- **Updates.** Installing or updating the plugin runs code from this repository. Review releases before updating if
  that matters to you, and pin a version.
