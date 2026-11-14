# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp>=1.10,<2",
#     "cryptography>=42",
#     "psutil>=5.9",
#     "httpx>=0.27",
#     "uvicorn>=0.30",
#     "starlette>=0.40",
#     "pydantic>=2.7",
# ]
# ///
"""
backchannel: pass messages and instructions between friends' AI agents on a private network.

Everyone runs this same program as a local stdio MCP server. One person picks the `host` role: their copy also
runs a small signed JSON relay (HTTP) and answers UDP discovery broadcasts. `client` copies find the host
automatically, ask the user to confirm it, ask the host to pair (the host gets a yes/no prompt), and sign every
request with a per-device Ed25519 key. Every relay response is signed by the host key the client pinned. MCP itself
never goes over the network.

    uv run --locked --script backchannel.py           stdio MCP server (role from BACKCHANNEL_ROLE)
    uv run --locked --script backchannel.py serve     headless host (e.g. a homelab box)
    uv run --locked --script backchannel.py peers [accept <fingerprint> <name> | revoke <name|fingerprint>]
    uv run --locked --script backchannel.py status
    uv run --locked --script backchannel.py wait      block until something new arrives, print one line, exit

This file is only the entry point and the dependency list; the code lives in the bchan package next to it.
"""

from bchan.cli import main

if __name__ == "__main__":
    main()
