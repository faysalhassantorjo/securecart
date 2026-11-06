"""
tests/test_order_address.py
===========================
Tests for OrderAddress model, checkout automatic creation,
relationship linking, encryption at rest, and strict RBAC/OLAC:
- OrderAddress created when user checks out.
- Relationship between Order and OrderAddress established.
- Street address, phone number, and email encrypted at rest with AES-256-GCM.
- Only ordering user, superadmin, and users with Admin role can view order addresses.
- Other customers cannot view order addresses (404 Not Found + audit log).
- No update URLs (PUT/PATCH returns 405 Method Not Allowed).
- OpenAPI/Swagger schema reflects order address endpoints.
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from rest_framework.test import APIClient
from rest_framework import status

from apps.products.models import Product
from apps.orders.models import Order, OrderAddress, Address
from apps.audit_logs.models import AuditLog
from apps.core.encryption import decrypt_value


class OrderAddressTests(TestCase):
    def setUp(self):
        call_command("setup_roles")
        customer_group = Group.objects.get(name="Customer")
        admin_group = Group.objects.get(name="Admin")

        # Customer Alice (the one who orders)
        self.alice = User.objects.create_user(
            username="alice_shopper",
            email="alice@example.com",
            password="AlicePassword123!",
        )
        self.alice.groups.add(customer_group)

        # Customer Bob (different user, should NOT see Alice's order address)
        self.bob = User.objects.create_user(
            username="bob_shopper",
            email="bob@example.com",
            password="BobPassword123!",
        )
        self.bob.groups.add(customer_group)

        # Admin user (in 'Admin' group)
        self.admin = User.objects.create_user(
            username="admin_user",
            email="admin@securecart.local",
            password="AdminPassword123!",
            is_staff=True,
        )
        self.admin.groups.add(admin_group)

        # Superadmin (is_superuser=True)
        self.superadmin = User.objects.create_superuser(
            username="root_admin",
            email="superadmin@securecart.local",
            password="SuperPassword123!",
        )

        # Product catalog item
        self.product = Product.objects.create(
            name="Encrypted USB Drive",
            price=Decimal("45.00"),
            stock_quantity=20,
        )

        self.client = APIClient()

    def _execute_checkout(self):
        """Helper to execute checkout as Alice."""
        self.client.force_authenticate(user=self.alice)
        payload = {
            "items": [{"product_id": self.product.id, "quantity": 2}],
            "recipient_name": "Alice Shopper",
            "phone_number": "+1-555-888-7777",
            "email": "alice.shopper@private.org",
            "delivery_address": "742 Evergreen Terrace",
            "delivery_city": "Springfield",
            "delivery_postal_code": "97477",
        }
        response = self.client.post("/api/checkout/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        order_id = response.data["id"]
        order = Order.objects.get(id=order_id)
        return order

    def test_checkout_creates_order_address_and_relationship(self):
        """When user creates order in checkout, OrderAddress is created and linked."""
        order = self._execute_checkout()

        # Verify OrderAddress exists
        self.assertTrue(OrderAddress.objects.filter(order=order).exists())
        order_address = OrderAddress.objects.get(order=order)

        # Verify relationship from Order to OrderAddress
        self.assertEqual(order.order_address, order_address)
        self.assertEqual(order.address, order_address)
        self.assertIn(order_address, order.addresses)
        self.assertIn(order_address, order.order_addresses.all())

        # Verify relationship from OrderAddress to Order and User
        self.assertEqual(order_address.order, order)
        self.assertEqual(order_address.user, self.alice)

        # Verify Address alias points to same model
        self.assertIs(Address, OrderAddress)
        self.assertEqual(order_address.recipient_name, "Alice Shopper")
        self.assertEqual(order_address.city, "Springfield")
        self.assertEqual(order_address.postal_code, "97477")

    def test_encrypt_and_store_at_rest(self):
        """Order address sensitive fields (phone, email, street) are encrypted at rest."""
        order = self._execute_checkout()
        order_address = OrderAddress.objects.get(order=order)

        # Ciphertexts must NOT match plaintext
        self.assertNotEqual(order_address.encrypted_phone, "+1-555-888-7777")
        self.assertNotEqual(order_address.encrypted_email, "alice.shopper@private.org")
        self.assertNotEqual(order_address.encrypted_street_address, "742 Evergreen Terrace")

        # Ciphertexts MUST decrypt to the original plaintext with valid key
        self.assertEqual(decrypt_value(order_address.encrypted_phone), "+1-555-888-7777")
        self.assertEqual(decrypt_value(order_address.encrypted_email), "alice.shopper@private.org")
        self.assertEqual(decrypt_value(order_address.encrypted_street_address), "742 Evergreen Terrace")

    def test_ordering_user_can_view_order_address(self):
        """Customer who placed the order can view their order address with decrypted data."""
        order = self._execute_checkout()
        order_address = order.address

        self.client.force_authenticate(user=self.alice)
        response = self.client.get(f"/api/order-addresses/{order_address.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Plaintext decrypted fields
        self.assertEqual(response.data["decrypted_phone"], "+1-555-888-7777")
        self.assertEqual(response.data["decrypted_email"], "alice.shopper@private.org")
        self.assertEqual(response.data["decrypted_street_address"], "742 Evergreen Terrace")
        self.assertEqual(response.data["city"], "Springfield")
        self.assertEqual(response.data["recipient_name"], "Alice Shopper")

    def test_superadmin_can_view_order_address(self):
        """Superadmin can view any order address and triggers audit log."""
        order = self._execute_checkout()
        order_address = order.address

        self.client.force_authenticate(user=self.superadmin)
        response = self.client.get(f"/api/order-addresses/{order_address.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data["decrypted_phone"], "+1-555-888-7777")
        self.assertEqual(response.data["decrypted_email"], "alice.shopper@private.org")
        self.assertEqual(response.data["decrypted_street_address"], "742 Evergreen Terrace")

        # Audit event recorded for admin access to customer data
        audit = AuditLog.objects.filter(
            event_type="ADMIN_SENSITIVE_DATA_ACCESS",
            user=self.superadmin,
            order_id=order.id,
        ).first()
        self.assertIsNotNone(audit, "Superadmin viewing customer PII must trigger audit log")

    def test_admin_role_user_can_view_order_address(self):
        """User who has Admin role can view order address and triggers audit log."""
        order = self._execute_checkout()
        order_address = order.address

        self.client.force_authenticate(user=self.admin)
        response = self.client.get(f"/api/order-addresses/{order_address.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(response.data["decrypted_phone"], "+1-555-888-7777")
        self.assertEqual(response.data["decrypted_email"], "alice.shopper@private.org")
        self.assertEqual(response.data["decrypted_street_address"], "742 Evergreen Terrace")

        # Audit event recorded
        audit = AuditLog.objects.filter(
            event_type="ADMIN_SENSITIVE_DATA_ACCESS",
            user=self.admin,
            order_id=order.id,
        ).first()
        self.assertIsNotNone(audit, "Admin viewing customer PII must trigger audit log")

    def test_other_customer_cannot_view_order_address_idor_prevented(self):
        """Another customer cannot view Alice's order address (returns 404 + audit log)."""
        order = self._execute_checkout()
        order_address = order.address

        self.client.force_authenticate(user=self.bob)
        response = self.client.get(f"/api/order-addresses/{order_address.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # Unauthorized access attempt must be logged
        unauth_event = AuditLog.objects.filter(
            event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
            user=self.bob,
        ).first()
        self.assertIsNotNone(unauth_event, "Unauthorized access attempt must be recorded in audit log")

    def test_other_customer_cannot_see_order_address_in_list(self):
        """Order address list is strictly scoped to the requesting user."""
        order = self._execute_checkout()
        order_address = order.address

        # Bob requests list
        self.client.force_authenticate(user=self.bob)
        response = self.client.get("/api/order-addresses/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Bob has 0 orders, must not see Alice's order address
        self.assertEqual(len(response.data), 0)

        # Alice requests list -> sees her address
        self.client.force_authenticate(user=self.alice)
        response = self.client.get("/api/order-addresses/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], order_address.id)

    def test_unauthenticated_request_rejected(self):
        """Unauthenticated requests to order address endpoints are rejected with 401."""
        order = self._execute_checkout()
        self.client.logout()

        resp = self.client.get("/api/order-addresses/")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

        resp = self.client.get(f"/api/order-addresses/{order.address.id}/")
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_update_urls_allowed(self):
        """PUT and PATCH methods are not supported (405 Method Not Allowed)."""
        order = self._execute_checkout()
        order_address = order.address

        self.client.force_authenticate(user=self.alice)

        # Attempt PUT
        resp_put = self.client.put(
            f"/api/order-addresses/{order_address.id}/",
            {"city": "Tampered City"},
            format="json",
        )
        self.assertEqual(resp_put.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        # Attempt PATCH
        resp_patch = self.client.patch(
            f"/api/order-addresses/{order_address.id}/",
            {"city": "Tampered City"},
            format="json",
        )
        self.assertEqual(resp_patch.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_order_address_by_order_endpoint(self):
        """Can retrieve order address by order ID."""
        order = self._execute_checkout()

        self.client.force_authenticate(user=self.alice)
        resp = self.client.get(f"/api/orders/{order.id}/address/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["id"], order.address.id)
        self.assertEqual(resp.data["decrypted_phone"], "+1-555-888-7777")

        # Bob querying Alice's order address by order ID gets 404
        self.client.force_authenticate(user=self.bob)
        resp_bob = self.client.get(f"/api/orders/{order.id}/address/")
        self.assertEqual(resp_bob.status_code, status.HTTP_404_NOT_FOUND)

    def test_order_detail_includes_order_address(self):
        """GET /api/orders/<id>/ includes nested order_address."""
        order = self._execute_checkout()

        self.client.force_authenticate(user=self.alice)
        resp = self.client.get(f"/api/orders/{order.id}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("order_address", resp.data)
        self.assertEqual(resp.data["order_address"]["id"], order.address.id)
        self.assertEqual(resp.data["order_address"]["decrypted_street_address"], "742 Evergreen Terrace")

    def test_swagger_schema_includes_order_address_endpoints(self):
        """OpenAPI schema contains order address endpoints and tags."""
        self.client.force_authenticate(user=self.alice)
        resp = self.client.get("/api/schema/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        schema_text = resp.content.decode("utf-8")
        self.assertIn("/api/order-addresses/", schema_text)
        self.assertIn("/api/order-addresses/{id}/", schema_text)
        self.assertIn("/api/orders/{order_id}/address/", schema_text)

    def test_api_docs_and_swagger_ui_endpoints(self):
        """Verify Swagger UI and OpenAPI doc endpoints return HTTP 200."""
        for endpoint in ["/api/docs/", "/docs/", "/api/swagger/", "/swagger/", "/api/redoc/", "/redoc/"]:
            resp = self.client.get(endpoint)
            self.assertEqual(
                resp.status_code,
                status.HTTP_200_OK,
                f"Expected 200 OK from documentation endpoint {endpoint}",
            )
