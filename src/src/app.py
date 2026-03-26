"""FastAPI application for the governed LLM gateway.

Provides a single /v1/chat endpoint that validates requests, evaluates
policy rules, resolves model aliases, enforces rate limits, forwards to
the appropriate provider, and records an immutable audit trail entry.

Compliance-first architecture:
1. Policy evaluation BEFORE provider dispatch
2. Immutable hash-chain audit trail for every request
3. Prompt/response content hashed, never stored raw
"""

import os
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from src.auth import AuthenticationError, validate_api_key
from src.audit import AuditTrail, hash_content
from src.config import GatewayConfig, load_config
from src.limiter import RateLimitExceeded, RateLimiter
from src.models import (
    AuditInfo,
    ChatRequest,
    ChatResponse,
    ErrorDetail,
    ErrorResponse,
    PolicyInfo,
    UsageInfo,
)
from src.policy import (
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    RequestContext,
    load_policies,
)
from src.provider import call_provider
from src.router import RoutingError, resolve_route
from src.telemetry import log_request, setup_logging

CONFIG_PATH = os.getenv("GATEWAY_CONFIG", "config/example.config.json")

_config: Optional[GatewayConfig] = None
_limiter: Optional[RateLimiter] = None
_audit_trail: Optional[AuditTrail] = None
_policy_engine: Optional[PolicyEngine] = None


def get_config() -> GatewayConfig:
    """Return the loaded gateway configuration (lazy-init)."""
    global _config
    if _config is None:
        _config = load_config(CONFIG_PATH)
    return _config


def get_limiter() -> RateLimiter:
    """Return the rate limiter (lazy-init from config)."""
    global _limiter
    if _limiter is None:
        cfg = get_config()
        _limiter = RateLimiter(
            requests_per_minute=cfg.rate_limit.requests_per_minute,
            tokens_per_minute=cfg.rate_limit.tokens_per_minute,
        )
    return _limiter


def get_audit_trail() -> AuditTrail:
    """Return the audit trail (lazy-init from config)."""
    global _audit_trail
    if _audit_trail is None:
        cfg = get_config()
        _audit_trail = AuditTrail(cfg.audit_log_file)
    return _audit_trail


def get_policy_engine() -> PolicyEngine:
    """Return the policy engine (lazy-init from config)."""
    global _policy_engine
    if _policy_engine is None:
        cfg = get_config()
        if cfg.policy_file:
            try:
                policy_config = load_policies(cfg.policy_file)
            except (FileNotFoundError, ValueError):
                policy_config = PolicyConfig()
        else:
            policy_config = PolicyConfig()
        _policy_engine = PolicyEngine(policy_config)
    return _policy_engine


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Initialize config, logging, audit trail, and policy engine on startup."""
    cfg = get_config()
    setup_logging(cfg.log_file)
    get_limiter()
    get_audit_trail()
    get_policy_engine()
    yield


app = FastAPI(
    title="Governed LLM Gateway",
    version="0.2.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)


def _error_response(
    status: int,
    error_type: str,
    message: str,
    policy_info: Optional[PolicyInfo] = None,
) -> JSONResponse:
    """Build a consistent JSON error response."""
    body = ErrorResponse(
        error=ErrorDetail(type=error_type, message=message),
        policy=policy_info,
    )
    return JSONResponse(status_code=status, content=body.model_dump())


@app.post("/v1/chat", response_model=None)
async def chat(
    request: ChatRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> JSONResponse:
    """Handle a chat completion request.

    Request flow:
    1. Validate request (prompt size, required fields)
    2. Evaluate policy rules (ALLOW/DENY/REQUIRE_APPROVAL)
    3. Resolve model alias to provider
    4. Enforce rate limits
    5. Call provider (if policy allows)
    6. Record immutable audit trail entry
    7. Return response with policy and audit metadata
    """
    config = get_config()
    limiter = get_limiter()
    audit = get_audit_trail()
    policy_engine = get_policy_engine()
    request_id = "gw-{}".format(uuid.uuid4().hex[:12])

    # --- Authentication ---
    auth_client = None
    if config.auth.enabled:
        try:
            auth_client = validate_api_key(x_api_key, config.auth.api_keys)
        except AuthenticationError as exc:
            log_request(
                client_id=request.client_id,
                alias=request.model,
                provider=None,
                outcome="auth_failed",
                error=exc.detail,
                request_id=request_id,
            )
            audit.append(
                request_id=request_id,
                client_id=request.client_id,
                model=request.model,
                action="auth_failure",
                prompt_hash="",
                response_hash="",
                policy_decision="DENY",
                metadata={"reason": "auth_failed", "detail": exc.detail},
            )
            return _error_response(401, "authentication_error", exc.detail)

    # Combine all message content for policy evaluation and hashing
    prompt_text = " ".join(m.content for m in request.messages)
    prompt_hash = hash_content(prompt_text)

    # --- Prompt size validation ---
    if config.max_prompt_tokens is not None:
        total_words = sum(len(m.content.split()) for m in request.messages)
        if total_words > config.max_prompt_tokens:
            log_request(
                client_id=request.client_id,
                alias=request.model,
                provider=None,
                outcome="validation_error",
                error="Prompt too large",
                request_id=request_id,
            )
            audit.append(
                request_id=request_id,
                client_id=request.client_id,
                model=request.model,
                action="chat_completion",
                prompt_hash=prompt_hash,
                response_hash="",
                policy_decision="DENY",
                metadata={"reason": "prompt_too_large"},
            )
            return _error_response(
                400,
                "validation_error",
                "Prompt size ({} approx tokens) exceeds maximum ({}).".format(
                    total_words, config.max_prompt_tokens
                ),
            )

    # --- Policy evaluation ---
    policy_context = RequestContext(
        client_id=request.client_id,
        model=request.model,
        prompt_text=prompt_text,
        data_classification=request.data_classification,
        jurisdiction=request.jurisdiction,
        metadata=request.metadata or {},
    )
    policy_result = policy_engine.evaluate(policy_context)

    policy_info = PolicyInfo(
        decision=policy_result.decision.value,
        triggered_rules=policy_result.triggered_rules,
        details=policy_result.details,
    )

    if policy_result.decision == PolicyDecision.DENY:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=None,
            outcome="policy_denied",
            error="Policy denied: {}".format(", ".join(policy_result.triggered_rules)),
            request_id=request_id,
        )
        audit.append(
            request_id=request_id,
            client_id=request.client_id,
            model=request.model,
            action="policy_violation",
            prompt_hash=prompt_hash,
            response_hash="",
            policy_decision="DENY",
            metadata={
                "triggered_rules": policy_result.triggered_rules,
                "details": policy_result.details,
            },
        )
        return _error_response(
            403,
            "policy_denied",
            "Request denied by policy: {}".format(
                ", ".join(policy_result.triggered_rules)
            ),
            policy_info=policy_info,
        )

    if policy_result.decision == PolicyDecision.REQUIRE_APPROVAL:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=None,
            outcome="approval_required",
            error="Approval required: {}".format(
                ", ".join(policy_result.triggered_rules)
            ),
            request_id=request_id,
        )
        audit.append(
            request_id=request_id,
            client_id=request.client_id,
            model=request.model,
            action="approval_required",
            prompt_hash=prompt_hash,
            response_hash="",
            policy_decision="REQUIRE_APPROVAL",
            metadata={
                "triggered_rules": policy_result.triggered_rules,
                "details": policy_result.details,
            },
        )
        return _error_response(
            403,
            "approval_required",
            "Request requires approval: {}".format(
                ", ".join(policy_result.triggered_rules)
            ),
            policy_info=policy_info,
        )

    # --- Routing ---
    try:
        route = resolve_route(config, request.model)
    except RoutingError as exc:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=None,
            outcome="routing_error",
            error=str(exc),
            request_id=request_id,
        )
        audit.append(
            request_id=request_id,
            client_id=request.client_id,
            model=request.model,
            action="chat_completion",
            prompt_hash=prompt_hash,
            response_hash="",
            policy_decision="ALLOW",
            metadata={"error": "routing_error", "detail": str(exc)},
        )
        return _error_response(400, "routing_error", str(exc))

    # --- Rate limiting ---
    try:
        limiter.check(request.client_id)
    except RateLimitExceeded as exc:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=route.provider.name,
            outcome="rate_limited",
            error=exc.detail,
            request_id=request_id,
        )
        audit.append(
            request_id=request_id,
            client_id=request.client_id,
            model=request.model,
            action="chat_completion",
            prompt_hash=prompt_hash,
            response_hash="",
            policy_decision="ALLOW",
            metadata={"error": "rate_limited", "detail": exc.detail},
        )
        return _error_response(429, "rate_limit_exceeded", exc.detail)

    # --- Provider call ---
    try:
        result = await call_provider(route.provider, route.model, request.messages)
    except httpx.HTTPStatusError as exc:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=route.provider.name,
            outcome="provider_error",
            error="Provider returned HTTP {}".format(exc.response.status_code),
            request_id=request_id,
        )
        audit.append(
            request_id=request_id,
            client_id=request.client_id,
            model=request.model,
            action="chat_completion",
            prompt_hash=prompt_hash,
            response_hash="",
            policy_decision="ALLOW",
            metadata={
                "error": "provider_error",
                "detail": "HTTP {}".format(exc.response.status_code),
            },
        )
        return _error_response(
            502,
            "provider_error",
            "Provider returned HTTP {}.".format(exc.response.status_code),
        )
    except (httpx.RequestError, ValueError) as exc:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=route.provider.name,
            outcome="provider_error",
            error=str(exc),
            request_id=request_id,
        )
        audit.append(
            request_id=request_id,
            client_id=request.client_id,
            model=request.model,
            action="chat_completion",
            prompt_hash=prompt_hash,
            response_hash="",
            policy_decision="ALLOW",
            metadata={"error": "provider_error", "detail": str(exc)},
        )
        return _error_response(
            502,
            "provider_error",
            "Failed to reach provider. Check request_id {} in logs.".format(
                request_id
            ),
        )

    # --- Record token usage for rate limiting ---
    try:
        limiter.record_tokens(request.client_id, result.usage.total_tokens)
    except RateLimitExceeded:
        pass  # Already served this request; log but do not reject

    # --- Audit trail entry for successful request ---
    response_hash = hash_content(result.message.content)
    audit_entry = audit.append(
        request_id=request_id,
        client_id=request.client_id,
        model=request.model,
        action="chat_completion",
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        policy_decision="ALLOW",
        metadata={
            "provider": route.provider.name,
            "usage": result.usage.model_dump(),
            "triggered_rules": policy_result.triggered_rules,
            "authenticated_as": auth_client,
        },
    )

    audit_info = AuditInfo(
        chain_hash=audit_entry.chain_hash,
        entry_index=audit.entry_count,
    )

    # --- Telemetry ---
    log_request(
        client_id=request.client_id,
        alias=request.model,
        provider=route.provider.name,
        outcome="success",
        usage=result.usage.model_dump(),
        request_id=request_id,
    )

    response = ChatResponse(
        id=request_id,
        model=request.model,
        provider=route.provider.name,
        usage=result.usage,
        message=result.message,
        policy=policy_info,
        audit=audit_info,
    )
    return JSONResponse(status_code=200, content=response.model_dump())


@app.exception_handler(422)
async def validation_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Convert FastAPI's validation errors into our error envelope format."""
    return _error_response(
        422,
        "validation_error",
        "Request validation failed. Check required fields and types.",
    )
