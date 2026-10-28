import asyncio
from types import SimpleNamespace

import pytest

from commander.sponsorship import (
    ManualRequired,
    expects,
    matching_button,
    parse_tag,
    register,
)


def test_tag_parser_does_not_treat_user_secret_as_ad_tag():
    secret = "1" * 32
    tag = "a" * 32
    assert (
        parse_tag("Here is your proxy tag: " + tag + "\nsecret=" + secret, secret)
        == tag
    )
    with pytest.raises(ManualRequired):
        parse_tag("secret=" + secret, secret)
    with pytest.raises(ManualRequired):
        parse_tag("tag: " + secret, secret)
    with pytest.raises(ManualRequired):
        parse_tag("tag: " + tag + "\ntag: " + "b" * 32, secret)


def test_expected_prompts_and_exact_proxy_selection():
    assert expects("Please send your IP address and port", "endpoint")
    assert expects("Send the secret", "secret")
    assert not expects("Invalid secret", "secret")
    message = SimpleNamespace(
        buttons=[
            [SimpleNamespace(text="1.1.1.1:443"), SimpleNamespace(text="11.1.1.1:443")]
        ]
    )
    assert matching_button(message, lambda label: label == "1.1.1.1:443") == (0, 0)
    with pytest.raises(ManualRequired):
        matching_button(message, lambda label: "1.1.1.1" in label)


def test_registration_stops_before_sending_secret_on_unknown_prompt():
    sent = []
    checkpoints = []

    class Conversation:
        async def send_message(self, value):
            sent.append(value)

        async def get_response(self):
            return SimpleNamespace(
                raw_text="Unexpected interface, please contact support"
            )

    async def checkpoint(*value):
        checkpoints.append(value)

    with pytest.raises(ManualRequired):
        asyncio.run(register(Conversation(), "1.1.1.1:443", "1" * 32, checkpoint))
    assert sent == ["/newproxy"]
    assert checkpoints == [("REGISTRATION_SUBMITTING",)]


def test_registration_flow_checkpoints_tag_without_persisting_secret():
    sent = []
    checkpoints = []

    class Conversation:
        def __init__(self):
            self.replies = iter(
                [
                    "Send IP address and port",
                    "Send the secret",
                    "Here is the proxy tag: " + "a" * 32,
                ]
            )

        async def send_message(self, value):
            sent.append(value)

        async def get_response(self):
            return SimpleNamespace(raw_text=next(self.replies))

    async def checkpoint(*value):
        checkpoints.append(value)

    result = asyncio.run(register(Conversation(), "1.1.1.1:443", "1" * 32, checkpoint))
    assert result == "a" * 32 and sent == ["/newproxy", "1.1.1.1:443", "1" * 32]
    assert "1" * 32 not in str(checkpoints)
    assert checkpoints[-1] == ("REGISTERED", "a" * 32)
