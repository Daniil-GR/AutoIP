import asyncio
from commander.monitor import checkhost_tcp


def test_invalid_host_is_unknown():
    out = asyncio.run(checkhost_tcp("127.0.0.1", 443))
    assert out["status"] == "unknown"


def test_invalid_port_is_unknown():
    out = asyncio.run(checkhost_tcp("example.com", 90000))
    assert out["status"] == "unknown"
