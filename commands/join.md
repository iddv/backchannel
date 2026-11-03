---
description: Connect to a backchannel host by invite code or IP (only needed if it isn't found automatically)
argument-hint: <bc1:invite-code | ip | ip:port>
---
Call the backchannel `join_host` tool with address "$ARGUMENTS" and report the result in one or two lines.
If no address was given, explain that the host can get an invite code with /backchannel:status; invite codes are
preferred over bare IPs because they also prove it's the right host.
