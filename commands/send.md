---
description: Send a message to a friend (or "all") on the backchannel
argument-hint: <name|all> <message>
---
Send a message on the backchannel. Arguments: $ARGUMENTS

The first word is the recipient (a friend's name, or `all` to broadcast); the rest is the message.
Call the backchannel `send_message` tool with those values and confirm in one line.
If no recipient or message was given, call `list_peers` and ask who to send to and what to say.
