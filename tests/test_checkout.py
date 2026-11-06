"""
tests/test_checkout.py
======================
Tests for checkout workflow:
- Validates product existence and stock sufficiency.
- Enforces server-calculated pricing.
- Verifies encryption of customer phone number and email at rest.
- Confirms database stores ciphertext != plaintext.
- Verifies atomic transaction rollback on validation failure.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from rest_framework.test import APIClient
from rest_framework import status

from apps.products.models import Product
from apps.orders.models import Order, OrderItem
from apps.audit_logs.models import AuditLog
from apps.core.encryption import decrypt_value


class CheckoutTests(TestCase):
    def setUp(self):
        call_command("setup_roles")
        self.client = APIClient()

        self.customer = User.objects.create_user(
            username="buyer_bob",
            email="bob@example.com",
            password="BobPassword123!",
        )
        self.customer.groups.add(Group.objects.get(name="Customer"))
        self.client.force_authenticate(user=self.customer)

        self.p1 = Product.objects.create(
            name="Hardware Wallet X",
            price=Decimal("100.00"),
            stock_quantity=10,
        )
        self.p2 = Product.objects.create(
            name="Security Key",
            price=Decimal("50.00"),
            stock_quantity=5,
        )

    def test_successful_checkout_and_encryption_at_rest(self):
        """Checkout stores encrypted phone number and email; DB values != plaintext."""
        phone_plaintext = "+1-555-999-1234"
        email_plaintext = "bob.buyer@private.org"

        payload = {
            "items": [
                {"product_id": self.p1.id, "quantity": 2},
                {"product_id": self.p2.id, "quantity": 1},
            ],
            "recipient_name": "Bob Buyer",
            "phone_number": phone_plaintext,
            "email": email_plaintext,
            "delivery_address": "123 Cryptography Ave",
            "delivery_city": "Cipher City",
            "delivery_postal_code": "10101",
        }

        response = self.client.post("/api/checkout/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        order_id = response.data["id"]
        order = Order.objects.get(id=order_id)

        # 1. Database values MUST NOT equal plaintext
        self.assertNotEqual(order.encrypted_phone, phone_plaintext)
        self.assertNotEqual(order.encrypted_email, email_plaintext)

        # 2. Database values MUST decrypt to original plaintext with valid key
        self.assertEqual(decrypt_value(order.encrypted_phone), phone_plaintext)
        self.assertEqual(decrypt_value(order.encrypted_email), email_plaintext)

        # 3. Server calculates total: (100 * 2) + (50 * 1) = 250.00
        self.assertEqual(order.total_amount, Decimal("250.00"))

        # 4. Product stock quantities deducted
        self.p1.refresh_from_db()
        self.p2.refresh_from_db()
        self.assertEqual(self.p1.stock_quantity, 8)
        self.assertEqual(self.p2.stock_quantity, 4)

        # 5. Order confirmation response does not leak unnecessary plaintext
        self.assertNotIn("phone_number", response.data)
        self.assertNotIn("email", response.data)

        # 6. Audit log recorded
        audit = AuditLog.objects.filter(event_type="CHECKOUT_SUCCESS", order_id=order_id).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.user, self.customer)

    def test_server_side_price_calculation_ignores_client_tampering(self):
        """Even if malicious client submits fraudulent price or total, backend enforces catalog price."""
        payload = {
            "items": [{"product_id": self.p1.id, "quantity": 1, "price": "1.00", "total": "1.00"}],
            "recipient_name": "Tamperer",
            "phone_number": "+1-555-000-0000",
            "email": "hacker@example.com",
            "delivery_address": "Dark Alley",
            "delivery_city": "Gotham",
            "delivery_postal_code": "99999",
        }

        response = self.client.post("/api/checkout/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        order = Order.objects.get(id=response.data["id"])
        # Backend price is 100.00, NOT 1.00
        self.assertEqual(order.total_amount, Decimal("100.00"))
        item = order.items.first()
        self.assertEqual(item.unit_price, Decimal("100.00"))
        self.assertEqual(item.subtotal, Decimal("100.00"))

    def test_insufficient_stock_atomic_rollback(self):
        """Checkout fails and rolls back completely if requested quantity exceeds stock."""
        initial_order_count = Order.objects.count()
        initial_p2_stock = self.p2.stock_quantity  # 5

        payload = {
            "items": [
                {"product_id": self.p1.id, "quantity": 1},
                {"product_id": self.p2.id, "quantity": 99},  # Exceeds available stock
            ],
            "recipient_name": "Bob",
            "phone_number": "+1-555-111-2222",
            "email": "bob@example.com",
            "delivery_address": "Street",
            "delivery_city": "City",
            "delivery_postal_code": "00000",
        }

        response = self.client.post("/api/checkout/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Insufficient Stock", response.data.get("error", ""))

        # No order created
        self.assertEqual(Order.objects.count(), initial_order_count)

        # Stock for p1 must NOT have been deducted (atomic rollback)
        self.p1.refresh_from_db()
        self.assertEqual(self.p1.stock_quantity, 10)
        self.p2.refresh_from_db()
        self.assertEqual(self.p2.stock_quantity, initial_p2_stock)

    def test_nonexistent_product_rejected_atomically(self):
        """Non-existent product ID returns 400 and creates no order."""
        payload = {
            "items": [{"product_id": 99999, "quantity": 1}],
            "recipient_name": "Bob",
            "phone_number": "+1-555-111-2222",
            "email": "bob@example.com",
            "delivery_address": "Street",
            "delivery_city": "City",
            "delivery_postal_code": "00000",
        }

        response = self.client.post("/api/checkout/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Order.objects.filter(recipient_name="Bob").exists())
