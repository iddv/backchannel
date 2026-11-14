---
description: Watch the backchannel for this session; wakes up only when something arrives
argument-hint: "[fallback interval, default 3m]"
---
Start watching the backchannel for this session without polling.

1. Call the backchannel `watch_command` tool. It returns one shell command. Run that command exactly as returned
   with the Bash tool, with `run_in_background: true`. It waits silently (no tokens are used while it waits) and
   exits when something arrives.
2. Tell the user in one line that you're watching, that `/backchannel:stop` turns it off, and that messages are
   only shown, never acted on, without their go-ahead.
3. Whenever that background command exits:
   - It printed "Run /backchannel:check": do what `/backchannel:check` does, then start the same command in the
     background again to keep watching.
   - It printed nothing (it was killed or timed out): start it again, silently.
   - It printed anything else (not connected, removed by the host): pass that on in one line and stop watching.
   - It said the host has no push support: use the fallback below.

Fallback, only if the `watch_command` tool doesn't exist or the host has no push support: use the Skill tool to
invoke the `loop` skill with args `<interval> /backchannel:check`, where `<interval>` is "$ARGUMENTS" if given,
otherwise `3m`.
