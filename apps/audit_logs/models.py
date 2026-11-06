"""
apps/audit_logs/models.py
=========================
AuditLog model for recording critical security events.
Stores immutable security event metadata without persisting sensitive plaintext data.
"""

from django.db import models
from django.contrib.auth.models import User


class AuditLog(models.Model):
    """
    Records security-relevant events across the application lifecycle.
    """

    EVENT_TYPES = [
        ("CHECKOUT_SUCCESS", "Checkout Successful"),
        ("UNAUTHORIZED_ACCESS_ATTEMPT", "Unauthorized Access Attempt"),
        ("ADMIN_SENSITIVE_DATA_ACCESS", "Admin Viewed Sensitive Customer Data"),
        ("DECRYPTION_FAILURE", "Decryption Failure / Tamper Detected"),
        ("USER_REGISTRATION", "User Registration"),
    ]

    event_type = models.CharField(max_length=64, choices=EVENT_TYPES, db_index=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_events")
    order_id = models.IntegerField(null=True, blank=True, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-timestamp"]
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"

    def __str__(self):
        user_str = self.user.username if self.user else "Anonymous"
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {self.event_type} by {user_str}"
