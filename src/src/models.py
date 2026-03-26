"""Request and response models for the governed LLM gateway."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """A single message in a chat conversation."""

    role: str
    content: str


class ChatRequest(BaseModel):
    """Incoming chat request from the client."""

    client_id: str = Field(..., min_length=1, description="Caller identifier")
    model: str = Field(..., min_length=1, description="Model alias to route to")
    messages: List[ChatMessage] = Field(
        ..., min_length=1, description="Conversation messages"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional caller metadata"
    )
    data_classification: Optional[str] = Field(
        default=None,
        description="Data classification label (e.g. PHI, PCI, public, internal)",
    )
    jurisdiction: Optional[str] = Field(
        default=None,
        description="Jurisdiction for data residency routing (e.g. EU, US)",
    )


class UsageInfo(BaseModel):
    """Token usage information returned by the provider."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class PolicyInfo(BaseModel):
    """Policy evaluation result included in responses."""

    decision: str
    triggered_rules: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class AuditInfo(BaseModel):
    """Audit trail reference included in responses."""

    chain_hash: str
    entry_index: int


class ChatResponse(BaseModel):
    """Successful chat response envelope."""

    id: str
    model: str
    provider: str
    usage: UsageInfo
    message: ChatMessage
    policy: Optional[PolicyInfo] = None
    audit: Optional[AuditInfo] = None


class ErrorDetail(BaseModel):
    """Structured error detail."""

    type: str
    message: str


class ErrorResponse(BaseModel):
    """Error response envelope."""

    error: ErrorDetail
    policy: Optional[PolicyInfo] = None
