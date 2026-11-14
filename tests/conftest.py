import pytest
from harness import Relay


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def relay(tmp_path):
    r = Relay(tmp_path)
    yield r
    r.stop()
