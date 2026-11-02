---
description: Keep checking the backchannel every few minutes for this session
argument-hint: "[interval, default 3m]"
---
Start watching the backchannel for this session.

Use the Skill tool to invoke the `loop` skill with args: `<interval> /backchannel:check`,
where `<interval>` is "$ARGUMENTS" if given, otherwise `3m`.

Then tell the user in one line that you're watching, and that `/backchannel:stop` turns it off.
