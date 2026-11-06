"""
apps/audit_logs/views.py
========================
Audit logging API views for compliance and security monitoring.
Accessible only to administrators with the 'audit_logs.view_auditlog' permission.
"""

from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema, extend_schema_view
from apps.audit_logs.models import AuditLog
from apps.audit_logs.serializers import AuditLogSerializer
from apps.core.permissions import HasSecurityAuditPermission


@extend_schema_view(
    get=extend_schema(
        summary="Admin list security audit events",
        description="Lists immutable audit trail records (checkout successes, IDOR attempts, admin sensitive data access, decryption errors). Restricted to staff holding 'audit_logs.view_auditlog'.",
        tags=["Admin"],
    )
)
class SecurityEventListAPIView(ListAPIView):
    """
    GET /api/admin/security-events/
    Lists immutable audit records chronologically.
    Restricted to authorized staff holding the 'audit_logs.view_auditlog' permission.
    """

    queryset = AuditLog.objects.all().select_related("user")
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated, HasSecurityAuditPermission]
