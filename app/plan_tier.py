"""Stripe plan → coarse tier for server-side feature gating (Pro vs Team).

Compares persisted ``plan_id`` to ``STRIPE_PRICE_PRO`` / ``STRIPE_PRICE_TEAM`` from settings.
"""

from __future__ import annotations

from typing import Any, Dict, Literal

from fastapi import Depends, HTTPException, status

from app.authorization import require_authorized_account
from app.config import settings
from app.deps import AuthenticatedUser
from app.storage import store

PlanTier = Literal["none", "pro", "team"]

_ACTIVE_SUBSCRIPTION_STATUSES = frozenset({"active", "trialing"})


def subscription_plan_tier(subrec: Dict[str, Any]) -> PlanTier:
    """
    Map a subscription row (from ``store.get_subscription``) to ``none`` / ``pro`` / ``team``.

    Unknown-but-non-empty ``plan_id`` on an active subscription is treated as **pro** so rotated
    Stripe price IDs do not silently drop paying users to ``none``.
    """
    st = (subrec.get("status") or "inactive").strip().lower()
    if st not in _ACTIVE_SUBSCRIPTION_STATUSES:
        return "none"
    plan_id = (subrec.get("plan_id") or "").strip()
    team_id = (settings.stripe_price_team or "").strip()
    pro_id = (settings.stripe_price_pro or "").strip()
    if team_id and plan_id == team_id:
        return "team"
    if pro_id and plan_id == pro_id:
        return "pro"
    if plan_id:
        return "pro"
    return "none"


def require_team_plan(user: AuthenticatedUser = Depends(require_authorized_account)) -> AuthenticatedUser:
    """
    Team-only surfaces — sole admin may always call (dogfood / ops).

    Uses the same active statuses as billing webhooks (``active``, ``trialing``).
    """
    em = store.canonical_email_for_sub(user.sub, user.email)
    if settings.is_admin_email(em):
        return user
    sub = store.get_subscription(user.sub)
    if subscription_plan_tier(sub) != "team":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Team plan required for this feature.",
        )
    return user
