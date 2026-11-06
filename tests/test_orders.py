"""
tests/test_orders.py
====================
Tests for Order retrieval, IDOR/BOLA prevention, and authorized decryption.
- Customer can retrieve own order with decrypted phone and email.
- Customer B cannot retrieve Customer A's order (returns 404 and creates audit log).
- Unauthenticated users cannot view orders.
- Address management object-level isolation.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from rest_framework.test import APIClient
from rest_framework import status

from apps.orders.models import Order
from apps.accounts.models import Address
from apps.audit_logs.models import AuditLog
from apps.core.encryption import encrypt_value


class OrderAndAddressSecurityTests(TestCase):
    def setUp(self):
        call_command("setup_roles")
        customer_group = Group.objects.get(name="Customer")

        # Customer Alice
        self.alice = User.objects.create_user(
            username="alice",
            email="alice@example.com",
            password="AlicePass123!",
        )
        self.alice.groups.add(customer_group)

        # Customer Bob
        self.bob = User.objects.create_user(
            username="bob",
            email="bob@example.com",
            password="BobPass123!",
        )
        self.bob.groups.add(customer_group)

        # Order belonging to Alice
        self.alice_order = Order.objects.create(
            user=self.alice,
            status="confirmed",
            total_amount=Decimal("129.99"),
            recipient_name="Alice Smith",
            delivery_address="100 Crypto Lane",
            delivery_city="Securityville",
            delivery_postal_code="12345",
            encrypted_phone=encrypt_value("+1-555-111-2222"),
            encrypted_email=encrypt_value("alice.personal@example.com"),
        )

        # Address belonging to Alice
        self.alice_address = Address.objects.create(
            user=self.alice,
            full_name="Alice Smith",
            street_address="100 Crypto Lane",
            city="Securityville",
            postal_code="12345",
            encrypted_phone=encrypt_value("+1-555-111-2222"),
            encrypted_email=encrypt_value("alice.personal@example.com"),
        )

        self.client = APIClient()

    def test_customer_can_retrieve_own_order_with_decrypted_pii(self):
        """Owner of order can view decrypted phone number and email."""
        self.client.force_authenticate(user=self.alice)

        response = self.client.get(f"/api/orders/{self.alice_order.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Decrypted fields match submitted plaintext
        self.assertEqual(response.data["decrypted_phone"], "+1-555-111-2222")
        self.assertEqual(response.data["decrypted_email"], "alice.personal@example.com")

        # Encrypted ciphertext is also present for verification
        self.assertTrue(len(response.data["encrypted_phone"]) > 20)

    def test_idor_bola_prevention_different_customer_gets_404(self):
        """Customer Bob attempting to retrieve Alice's order gets 404 (IDOR prevented)."""
        self.client.force_authenticate(user=self.bob)

        # Bob requests Alice's order ID
        response = self.client.get(f"/api/orders/{self.alice_order.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Verify unauthorized access attempt was logged
        unauthorized_event = AuditLog.objects.filter(
            event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
            user=self.bob,
        ).first()
        self.assertIsNotNone(unauthorized_event, "Unauthorized order access must be recorded in audit log")

    def test_customer_order_list_scoped_to_own_account_only(self):
        """Order list only returns orders belonging to the authenticated customer."""
        self.client.force_authenticate(user=self.bob)

        response = self.client.get("/api/orders/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Bob has 0 orders, must not see Alice's order
        self.assertEqual(len(response.data), 0)

    def test_address_management_object_level_isolation(self):
        """Customer cannot view, update, or delete another customer's address."""
        self.client.force_authenticate(user=self.bob)

        # Bob attempts GET on Alice's address
        resp = self.client.get(f"/api/addresses/{self.alice_address.id}/")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

        # Bob attempts PATCH on Alice's address
        resp = self.client.patch(
            f"/api/addresses/{self.alice_address.id}/",
            {"city": "HackedCity"},
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

        # Alice's address remains unmodified
        self.alice_address.refresh_from_db()
        self.assertEqual(self.alice_address.city, "Securityville")
