"""
tests/test_admin.py
===================
Tests for Admin role access, permission checks, and audit logging.
- Staff with 'orders.view_order' can view administrative order lists.
- Staff with 'orders.view_sensitive_customer_data' receives decrypted PII.
- Viewing sensitive PII generates 'ADMIN_SENSITIVE_DATA_ACCESS' audit event.
- Staff without permission receives masked PII.
- Compliance staff with 'audit_logs.view_auditlog' can view security events.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth.models import User, Group, Permission
from django.core.management import call_command
from rest_framework.test import APIClient
from rest_framework import status

from apps.orders.models import Order
from apps.audit_logs.models import AuditLog
from apps.core.encryption import encrypt_value


class AdminSecurityTests(TestCase):
    def setUp(self):
        call_command("setup_roles")
        admin_group = Group.objects.get(name="Admin")
        customer_group = Group.objects.get(name="Customer")

        # Regular customer
        self.customer = User.objects.create_user(
            username="customer_claire",
            email="claire@example.com",
            password="ClairePass123!",
        )
        self.customer.groups.add(customer_group)

        # Full Admin user (in Admin group with all permissions)
        self.admin = User.objects.create_user(
            username="super_admin",
            email="admin@securecart.local",
            password="AdminPass123!",
            is_staff=True,
        )
        self.admin.groups.add(admin_group)

        # Restricted Staff user (is_staff=True, but only has view_order, lacks view_sensitive_customer_data)
        self.restricted_staff = User.objects.create_user(
            username="restricted_staff",
            email="staff@securecart.local",
            password="StaffPass123!",
            is_staff=True,
        )
        view_order_perm = Permission.objects.get(
            content_type__app_label="orders",
            codename="view_order",
        )
        self.restricted_staff.user_permissions.add(view_order_perm)

        # Customer Order with sensitive PII
        self.order = Order.objects.create(
            user=self.customer,
            status="confirmed",
            total_amount=Decimal("89.00"),
            recipient_name="Claire Customer",
            delivery_address="456 Elm St",
            delivery_city="Denver",
            delivery_postal_code="80201",
            encrypted_phone=encrypt_value("+1-555-444-5555"),
            encrypted_email=encrypt_value("claire.private@example.com"),
        )

        self.client = APIClient()

    def test_authorized_admin_can_view_orders_and_decrypted_pii(self):
        """Admin with view_sensitive_customer_data permission sees decrypted contact details."""
        self.client.force_authenticate(user=self.admin)

        response = self.client.get(f"/api/orders/{self.order.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Plaintext phone and email are decrypted
        self.assertEqual(response.data["decrypted_phone"], "+1-555-444-5555")
        self.assertEqual(response.data["decrypted_email"], "claire.private@example.com")

        # Viewing sensitive details MUST generate an audit log record
        audit = AuditLog.objects.filter(
            event_type="ADMIN_SENSITIVE_DATA_ACCESS",
            user=self.admin,
            order_id=self.order.id,
        ).first()
        self.assertIsNotNone(audit, "Admin viewing customer PII must trigger an audit log entry")

    def test_restricted_staff_without_sensitive_perm_sees_masked_pii(self):
        """Staff without 'orders.view_sensitive_customer_data' receives masked values."""
        self.client.force_authenticate(user=self.restricted_staff)

        response = self.client.get(f"/api/orders/{self.order.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Order metadata is visible
        self.assertEqual(response.data["recipient_name"], "Claire Customer")

        # But sensitive fields are safely masked
        self.assertIn("MASKED", response.data["decrypted_phone"])
        self.assertIn("MASKED", response.data["decrypted_email"])

    def test_admin_can_view_security_audit_events(self):
        """Staff holding 'audit_logs.view_auditlog' can query security events."""
        # Create dummy event
        AuditLog.objects.create(
            event_type="CHECKOUT_SUCCESS",
            user=self.customer,
            order_id=self.order.id,
            description="Test checkout event",
        )

        self.client.force_authenticate(user=self.admin)
        response = self.client.get("/api/admin/security-events/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data) >= 1)
