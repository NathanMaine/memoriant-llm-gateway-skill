"""Provider adapter for OpenAI-compatible LLM APIs.

Supports a real mode (forwarding to actual API endpoints) and a stub/mock mode
that returns canned responses when no API key is configured.
"""

import uuid
from dataclasses import dataclass
from typing import List, Optional

import httpx

from src.config import ProviderConfig
from src.models import ChatMessage, UsageInfo


@dataclass
class ProviderResult:
    """Result returned by the provider adapter."""

    message: ChatMessage
    usage: UsageInfo
    provider_request_id: Optional[str] = None


_STUB_RESPONSE = (
    "This is a stub response from the gateway. "
    "Configure a valid API key to get real completions."
)


async def call_provider(
    provider: ProviderConfig,
    model: str,
    messages: List[ChatMessage],
) -> ProviderResult:
    """Call an LLM provider and return the result.

    If the provider's API key is not set in the environment, falls back to a
    stub/mock response so the gateway can be tested without real credentials.

    Args:
        provider: Provider configuration (base URL, API key env, etc.).
        model: The concrete model identifier to request.
        messages: The conversation messages to send.

    Returns:
        A ProviderResult with the assistant message and usage info.

    Raises:
        httpx.HTTPStatusError: If the provider returns a non-2xx response.
    """
    api_key = provider.api_key

    if not api_key:
        return _stub_response(messages)

    return await _real_request(provider, model, messages, api_key)


def _stub_response(messages: List[ChatMessage]) -> ProviderResult:
    """Return a canned response for testing without real API keys."""
    prompt_tokens = sum(len(m.content.split()) for m in messages)
    stub_tokens = len(_STUB_RESPONSE.split())
    return ProviderResult(
        message=ChatMessage(role="assistant", content=_STUB_RESPONSE),
        usage=UsageInfo(
            prompt_tokens=prompt_tokens,
            completion_tokens=stub_tokens,
            total_tokens=prompt_tokens + stub_tokens,
        ),
        provider_request_id="stub-{}".format(uuid.uuid4().hex[:8]),
    )


async def _real_request(
    provider: ProviderConfig,
    model: str,
    messages: List[ChatMessage],
    api_key: str,
) -> ProviderResult:
    """Forward the request to an OpenAI-compatible API endpoint."""
    url = "{}/chat/completions".format(provider.base_url.rstrip("/"))
    headers = {
        "Authorization": "Bearer {}".format(api_key),
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": m.role, "content": m.content} for m in messages],
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    choices = data.get("choices", [])
    if not choices:
        raise ValueError("Provider returned no choices in response")
    choice = choices[0]
    msg = choice.get("message", {})
    usage_raw = data.get("usage", {})

    return ProviderResult(
        message=ChatMessage(
            role=msg.get("role", "assistant"),
            content=msg.get("content", ""),
        ),
        usage=UsageInfo(
            prompt_tokens=usage_raw.get("prompt_tokens", 0),
            completion_tokens=usage_raw.get("completion_tokens", 0),
            total_tokens=usage_raw.get("total_tokens", 0),
        ),
        provider_request_id=data.get("id"),
    )
