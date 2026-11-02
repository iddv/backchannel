---
description: List who is on the backchannel
---
Call the backchannel `list_peers` tool and show the result as a short list.
If anyone is WAITING, ask the user whether to let them in (then call `accept_peer` with their fingerprint, or `revoke_peer` to decline).
