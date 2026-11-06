"""
apps/audit_logs/serializers.py
==============================
Serializers for AuditLog inspection by authorized administrators.
"""

from rest_framework import serializers
from apps.audit_logs.models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True, default=None)

    class Meta:
        model = AuditLog
        fields = [
            "id",
            "event_type",
            "username",
            "order_id",
            "ip_address",
            "description",
            "timestamp",
        ]
        read_only_fields = fields
