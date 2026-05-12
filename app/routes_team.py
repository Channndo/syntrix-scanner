"""Team-tier HTTP surface — starts with a stub for outbound webhook registration."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator

from app.deps import AuthenticatedUser
from app.plan_tier import require_team_plan

router = APIRouter(tags=["team"])


class TeamWebhookRegisterStubBody(BaseModel):
    """Future: persist URL + signing secret; today only validates shape."""

    url: Optional[str] = Field(default=None, max_length=2048)

    @field_validator("url")
    @classmethod
    def https_only(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        if not s.startswith("https://"):
            raise ValueError("url must start with https://")
        return s


@router.post("/webhooks/register")
def register_outbound_webhook_stub(
    payload: TeamWebhookRegisterStubBody,
    user: AuthenticatedUser = Depends(require_team_plan),
) -> Dict[str, Any]:
    """
    Stub: acknowledges Team tier and optional target URL — no persistence yet.

    Next step will be signed deliveries + SSRF-safe URL validation and storage.
    """
    return {
        "ok": True,
        "stub": True,
        "plan": "team",
        "url_received": bool(payload.url),
        "detail": "Webhook registration is not persisted yet; Team tier acknowledged.",
    }
