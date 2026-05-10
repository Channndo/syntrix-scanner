"""Stripe billing integration and subscription authorization helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

import stripe
from fastapi import Depends, Header, HTTPException, Request, status

from app.deps import AuthenticatedUser, require_user
from app.authorization import require_authorized_account
from app.config import settings
from app.storage import store


def validate_billing_config() -> None:
    if not settings.billing_required:
        return

    missing = []
    if not settings.stripe_secret_key:
        missing.append("STRIPE_SECRET_KEY")
    if not settings.stripe_webhook_secret:
        missing.append("STRIPE_WEBHOOK_SECRET")
    if not settings.stripe_price_pro:
        missing.append("STRIPE_PRICE_PRO")
    if not settings.stripe_price_team:
        missing.append("STRIPE_PRICE_TEAM")

    if missing:
        raise RuntimeError("Invalid billing config. Missing: " + ", ".join(missing))

    stripe.api_key = settings.stripe_secret_key


def _is_active_subscription(status: str) -> bool:
    return status in {"active", "trialing"}


def require_active_subscription(
    user: AuthenticatedUser = Depends(require_authorized_account),
) -> AuthenticatedUser:
    if not settings.billing_required:
        return user
    sub = store.get_subscription(user.sub)
    if not _is_active_subscription(sub.get("status", "inactive")):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Active subscription required. Visit billing to upgrade.",
        )
    return user


def create_checkout_session(user: AuthenticatedUser, price_id: str) -> Dict[str, str]:
    if not (settings.stripe_secret_key or "").strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe is not configured on this API (set STRIPE_SECRET_KEY).",
        )
    stripe.api_key = settings.stripe_secret_key
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=f"{settings.app_base_url}/account.html?checkout=success",
            cancel_url=f"{settings.app_base_url}/billing.html?checkout=cancelled",
            customer_email=user.email,
            client_reference_id=user.sub,
            metadata={"auth_sub": user.sub},
        )
    except stripe.StripeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=getattr(exc, "user_message", None) or str(exc) or "Stripe checkout could not be started.",
        ) from exc
    return {"checkout_url": session.url, "session_id": session.id}


def create_billing_portal_session(user: AuthenticatedUser) -> Dict[str, str]:
    if not (settings.stripe_secret_key or "").strip():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe is not configured on this API (set STRIPE_SECRET_KEY).",
        )
    stripe.api_key = settings.stripe_secret_key
    current = store.get_subscription(user.sub)
    customer_id = current.get("stripe_customer_id")
    if not customer_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No billing customer found for this account.",
        )

    try:
        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=f"{settings.app_base_url}/account.html",
        )
    except stripe.StripeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=getattr(exc, "user_message", None) or str(exc) or "Stripe billing portal could not be opened.",
        ) from exc
    return {"portal_url": session.url}


def _to_dt(ts: Any) -> datetime | None:
    if not ts:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc)


def _handle_subscription_payload(sub: Dict[str, Any]) -> None:
    customer_id = sub.get("customer")
    auth_sub = None
    meta = sub.get("metadata") or {}
    if meta.get("auth_sub"):
        auth_sub = meta["auth_sub"]
    elif customer_id:
        auth_sub = store.get_auth_sub_for_customer(customer_id)
    if not auth_sub:
        return

    item_data = ((sub.get("items") or {}).get("data") or [{}])[0]
    price_obj = item_data.get("price") or {}
    plan_id = price_obj.get("id")

    st = sub.get("status", "inactive")
    store.set_subscription(
        auth_sub=auth_sub,
        status=st,
        stripe_customer_id=customer_id,
        stripe_subscription_id=sub.get("id"),
        plan_id=plan_id,
        current_period_end=_to_dt(sub.get("current_period_end")),
    )
    if _is_active_subscription(st):
        store.set_account_authorized(auth_sub, True)


async def handle_stripe_webhook(
    request: Request,
    stripe_signature: str = Header(default="", alias="Stripe-Signature"),
) -> Dict[str, Any]:
    stripe.api_key = settings.stripe_secret_key
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=stripe_signature,
            secret=settings.stripe_webhook_secret,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook signature: {exc}") from exc

    event_type = event.get("type", "")
    data_obj = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        auth_sub = (data_obj.get("metadata") or {}).get("auth_sub") or data_obj.get("client_reference_id")
        if auth_sub:
            store.ensure_user(auth_sub, email=data_obj.get("customer_details", {}).get("email"))
            store.set_subscription(
                auth_sub=auth_sub,
                status="active",
                stripe_customer_id=data_obj.get("customer"),
                stripe_subscription_id=data_obj.get("subscription"),
            )
            store.set_account_authorized(auth_sub, True)
    elif event_type in {"customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"}:
        _handle_subscription_payload(data_obj)
    elif event_type == "invoice.paid":
        subscription_id = data_obj.get("subscription")
        if subscription_id:
            sub = stripe.Subscription.retrieve(subscription_id)
            _handle_subscription_payload(sub)

    return {"ok": True, "received": event_type}
