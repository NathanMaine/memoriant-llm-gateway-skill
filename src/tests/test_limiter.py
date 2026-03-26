"""Tests for the in-memory rate limiter."""

import pytest

from src.limiter import RateLimitExceeded, RateLimiter


def test_allows_requests_within_limit() -> None:
    """Requests under the limit should succeed."""
    limiter = RateLimiter(requests_per_minute=3)
    for _ in range(3):
        limiter.check("client-a")


def test_rejects_over_limit() -> None:
    """Exceeding the request limit raises RateLimitExceeded."""
    limiter = RateLimiter(requests_per_minute=2)
    limiter.check("client-a")
    limiter.check("client-a")

    with pytest.raises(RateLimitExceeded, match="Request rate exceeded"):
        limiter.check("client-a")


def test_separate_clients_have_independent_limits() -> None:
    """Different client_ids have independent counters."""
    limiter = RateLimiter(requests_per_minute=1)
    limiter.check("client-a")
    limiter.check("client-b")  # Should not raise


def test_token_limit_exceeded() -> None:
    """Exceeding the token limit raises RateLimitExceeded."""
    limiter = RateLimiter(requests_per_minute=100, tokens_per_minute=50)
    limiter.check("client-a")
    limiter.record_tokens("client-a", 30)
    limiter.record_tokens("client-a", 15)  # 45 total, still under 50

    with pytest.raises(RateLimitExceeded, match="Token rate exceeded"):
        limiter.record_tokens("client-a", 10)  # 55 total, exceeds 50


def test_token_limit_not_set() -> None:
    """When tokens_per_minute is None, token recording is a no-op."""
    limiter = RateLimiter(requests_per_minute=100, tokens_per_minute=None)
    limiter.check("client-a")
    limiter.record_tokens("client-a", 999999)  # Should not raise


def test_window_resets(monkeypatch: pytest.MonkeyPatch) -> None:
    """After the window expires, counters reset."""
    import time

    current_time = 1000.0

    def mock_time() -> float:
        return current_time

    monkeypatch.setattr(time, "time", mock_time)

    limiter = RateLimiter(requests_per_minute=1)
    limiter.check("client-a")

    with pytest.raises(RateLimitExceeded):
        limiter.check("client-a")

    # Advance past the 60-second window
    current_time = 1061.0
    limiter.check("client-a")  # Should succeed after window reset
