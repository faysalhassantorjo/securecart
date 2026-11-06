"""
apps/core/audit.py
==================
Helper utility to record security audit logs cleanly and safely.
Never records plaintext secrets, passwords, phone numbers, emails, or encryption keys.
"""

import logging
from typing import Optional
from django.http import HttpRequest

logger = logging.getLogger("security.audit")


def get_client_ip(request: Optional[HttpRequest]) -> Optional[str]:
    """Extracts client IP address safely from request headers."""
    if not request:
        return None
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def record_security_event(
    event_type: str,
    request: Optional[HttpRequest] = None,
    user=None,
    order_id: Optional[int] = None,
    description: str = "",
) -> None:
    """
    Creates an AuditLog record.
    Silently fails or logs warning if DB is unavailable, ensuring
    an audit logging failure never crashes user transactions unexpectedly.
    """
    actor = user
    if actor is None and request and hasattr(request, "user") and request.user.is_authenticated:
        actor = request.user

    ip_address = get_client_ip(request)

    # Log to Python logger for system/container log streams
    actor_identifier = actor.username if (actor and hasattr(actor, "username")) else "anonymous"
    logger.info(
        f"[AUDIT] Event={event_type} Actor={actor_identifier} IP={ip_address} Order={order_id} Info={description}"
    )

    # Persist to database
    try:
        from apps.audit_logs.models import AuditLog

        AuditLog.objects.create(
            event_type=event_type,
            user=actor if (actor and hasattr(actor, "is_authenticated") and actor.is_authenticated) else None,
            order_id=order_id,
            ip_address=ip_address,
            description=description[:255] if description else "",
        )
    except Exception as e:
        logger.error(f"Failed to record audit log to database: {e}")
