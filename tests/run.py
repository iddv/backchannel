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
#     "pytest>=8",
# ]
# ///
"""Run the test suite with locked dependencies:

    uv run --no-project --no-config --locked --script tests/run.py [pytest arguments]

Hosts under test listen on loopback only unless BACKCHANNEL_BIND says otherwise (CI sets it to `private`).
"""

import sys
from pathlib import Path

import pytest

sys.exit(pytest.main([str(Path(__file__).parent), "-q", "-p", "no:cacheprovider", *sys.argv[1:]]))
