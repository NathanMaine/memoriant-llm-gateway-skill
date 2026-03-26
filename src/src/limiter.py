"""In-memory rate limiter for the governed LLM gateway.

Tracks per-client_id request counts and (optionally) token counts using a
fixed-window approach that resets each minute.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional


class RateLimitExceeded(Exception):
    """Raised when a client exceeds their rate limit."""

    def __init__(self, client_id: str, detail: str) -> None:
        self.client_id = client_id
        self.detail = detail
        super().__init__(detail)


@dataclass
class _ClientBucket:
    """Fixed-window counters for a single client_id."""

    window_start: float = 0.0
    request_count: int = 0
    token_count: int = 0


@dataclass
class RateLimiter:
    """Per-client_id in-memory rate limiter.

    Uses a simple fixed-window approach (resets each minute). This is
    approximate and suitable for a prototype only.
    """

    requests_per_minute: int = 20
    tokens_per_minute: Optional[int] = None
    _buckets: Dict[str, _ClientBucket] = field(default_factory=dict)

    def check(self, client_id: str) -> None:
        """Check whether the client is allowed to make a request.

        Increments the request counter. Call record_tokens() after the
        provider responds if token-based limiting is enabled.

        Args:
            client_id: The caller's identifier.

        Raises:
            RateLimitExceeded: If the client has exceeded their limit.
        """
        now = time.time()
        bucket = self._get_or_reset_bucket(client_id, now)

        if bucket.request_count >= self.requests_per_minute:
            raise RateLimitExceeded(
                client_id,
                "Request rate exceeded for client_id {} ({} req/min).".format(
                    client_id, self.requests_per_minute
                ),
            )

        bucket.request_count += 1

    def record_tokens(self, client_id: str, tokens: int) -> None:
        """Record token usage for the current window.

        Args:
            client_id: The caller's identifier.
            tokens: Number of tokens used in this request.

        Raises:
            RateLimitExceeded: If the token limit has been exceeded.
        """
        if self.tokens_per_minute is None:
            return

        now = time.time()
        bucket = self._get_or_reset_bucket(client_id, now)
        bucket.token_count += tokens

        if bucket.token_count > self.tokens_per_minute:
            raise RateLimitExceeded(
                client_id,
                "Token rate exceeded for client_id {} ({} tokens/min).".format(
                    client_id, self.tokens_per_minute
                ),
            )

    def _get_or_reset_bucket(
        self, client_id: str, now: float
    ) -> _ClientBucket:
        """Retrieve the bucket for client_id, resetting if the window expired."""
        bucket = self._buckets.get(client_id)
        window_seconds = 60.0

        if bucket is None or (now - bucket.window_start) >= window_seconds:
            bucket = _ClientBucket(window_start=now)
            self._buckets[client_id] = bucket

        return bucket
