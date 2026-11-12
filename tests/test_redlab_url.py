from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_prompt_shield.redlab_model import OpenAIResponsesEvaluator
from agent_prompt_shield.redlab_strategy import OpenAIResponsesStrategist
from agent_prompt_shield.redlab_url import validate_provider_url


@pytest.mark.parametrize(
    "value",
    (
        "http://api.openai.com/v1/responses",
        "ftp://example.test/responses",
        "file:///tmp/responses",
        "https:///responses",
        "https://user:secret@example.test/responses",
        "https://example.test/responses#fragment",
        "https://example.test:70000/responses",
        "https://[invalid/responses",
        " https://example.test/responses",
        "https://example.test/a b",
    ),
)
def test_provider_url_rejects_unsafe_or_malformed_values(value: str) -> None:
    with pytest.raises(ValueError):
        validate_provider_url(value)


@pytest.mark.parametrize(
    "value",
    (
        "https://api.openai.com/v1/responses",
        "https://provider.example.test/custom/responses?version=1",
        "https://localhost:8443/v1/responses",
    ),
)
def test_provider_url_accepts_https_provider_endpoints(value: str) -> None:
    assert validate_provider_url(value) == value


@pytest.mark.parametrize(
    "client",
    (OpenAIResponsesStrategist, OpenAIResponsesEvaluator),
)
def test_clients_validate_url_before_environment_or_transport(
    monkeypatch: pytest.MonkeyPatch,
    client,
) -> None:
    class GuardedEnvironment:
        def get(self, _name: str) -> str:
            raise AssertionError("credential environment was read")

    module = __import__(client.__module__, fromlist=["os"])
    monkeypatch.setattr(module, "os", SimpleNamespace(environ=GuardedEnvironment()))

    with pytest.raises(ValueError, match="HTTPS"):
        client(base_url="http://example.test/responses", transport=lambda _: {})
