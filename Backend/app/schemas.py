from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, ConfigDict


class TrustLevel(str, Enum):
    trusted = "trusted"
    untrusted = "untrusted"


class DecisionType(str, Enum):
    auto_execute = "auto_execute"
    block = "block"
    escalate = "escalate"


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=100)
    trust_level: TrustLevel
    content: dict[str, Any]


class Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=255)
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    hypothesis: str = Field(min_length=1, max_length=2000)


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: DecisionType
    reason_codes: list[str] = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=1.0)
    approval_required: bool


from pydantic import BaseModel, Field


class AnalyzeEventRequest(BaseModel):
    failed_attempts: int = Field(ge=0)
    threshold: int = Field(default=5, ge=1)
