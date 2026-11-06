"""
tests/test_role_boundaries.py
=============================
Tests for 3-Role Access Control (RBAC):
- CUSTOMER: Automatically assigned upon registration; can create orders and addresses; cannot create/modify/delete products.
- MODERATOR: Only system superadmin or ADMIN can assign this role. Can create and update products, but CANNOT delete products.
- ADMIN: ONLY system superadmin can assign this role. Full access (create, update, delete products, view all orders, audit logs).
"""

from decimal import Decimal
from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from rest_framework.test import APIClient
from rest_framework import status

from apps.products.models import Product
from apps.core.permissions import get_user_role
from apps.audit_logs.models import AuditLog


class RoleBoundariesTests(TestCase):
    def setUp(self):
        call_command("setup_roles")
        customer_group = Group.objects.get(name="Customer")
        moderator_group = Group.objects.get(name="Moderator")
        admin_group = Group.objects.get(name="Admin")

        # 1. Superadmin
        self.superadmin = User.objects.create_superuser(
            username="superadmin_sam",
            email="superadmin@securecart.local",
            password="SuperPassword123!",
        )

        # 2. Admin User (in Admin group)
        self.admin = User.objects.create_user(
            username="admin_alice",
            email="admin@securecart.local",
            password="AdminPassword123!",
            is_staff=True,
        )
        self.admin.groups.add(admin_group)

        # 3. Moderator User (in Moderator group)
        self.moderator = User.objects.create_user(
            username="moderator_mike",
            email="moderator@securecart.local",
            password="ModPassword123!",
        )
        self.moderator.groups.add(moderator_group)

        # 4. Customer User (in Customer group)
        self.customer = User.objects.create_user(
            username="customer_charlie",
            email="charlie@example.com",
            password="CustPassword123!",
        )
        self.customer.groups.add(customer_group)

        # 5. Target User for role assignments
        self.target_user = User.objects.create_user(
            username="target_tim",
            email="tim@example.com",
            password="TimPassword123!",
        )
        self.target_user.groups.add(customer_group)

        # Catalog product
        self.product = Product.objects.create(
            name="Privacy Filter Screen",
            price=Decimal("29.99"),
            stock_quantity=15,
        )

        self.client = APIClient()

    # =========================================================================
    # 1. Registration: CUSTOMER role automatically assigned
    # =========================================================================
    def test_customer_role_automatically_assigned_on_registration(self):
        """When a user registers, they are automatically granted the CUSTOMER role."""
        payload = {
            "username": "brand_new_user",
            "email": "brandnew@example.com",
            "password": "StrongPassword123!",
            "password_confirm": "StrongPassword123!",
            "first_name": "Brand",
            "last_name": "New",
        }
        resp = self.client.post("/api/auth/register/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username="brand_new_user")
        self.assertEqual(get_user_role(user), "CUSTOMER")
        self.assertTrue(user.groups.filter(name="Customer").exists())
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(resp.data["user"]["role"], "CUSTOMER")

    # =========================================================================
    # 2. MODERATOR Role Assignment Authority
    # =========================================================================
    def test_superadmin_can_assign_moderator_role(self):
        """Superadmin can promote a user to MODERATOR."""
        self.client.force_authenticate(user=self.superadmin)
        resp = self.client.post(
            f"/api/admin/users/{self.target_user.id}/role/",
            {"role": "MODERATOR"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["role"], "MODERATOR")

        self.target_user.refresh_from_db()
        self.assertEqual(get_user_role(self.target_user), "MODERATOR")
        self.assertTrue(self.target_user.groups.filter(name="Moderator").exists())
        self.assertFalse(self.target_user.groups.filter(name="Customer").exists())

    def test_admin_can_assign_moderator_role(self):
        """ADMIN can promote a user to MODERATOR."""
        self.client.force_authenticate(user=self.admin)
        resp = self.client.post(
            f"/api/admin/users/{self.target_user.id}/role/",
            {"role": "MODERATOR"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["role"], "MODERATOR")

        self.target_user.refresh_from_db()
        self.assertEqual(get_user_role(self.target_user), "MODERATOR")

    def test_customer_cannot_assign_moderator_role(self):
        """Customer cannot assign the MODERATOR role (403 Forbidden)."""
        self.client.force_authenticate(user=self.customer)
        resp = self.client.post(
            f"/api/admin/users/{self.target_user.id}/role/",
            {"role": "MODERATOR"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_moderator_cannot_assign_moderator_role(self):
        """Moderator cannot assign roles (403 Forbidden)."""
        self.client.force_authenticate(user=self.moderator)
        resp = self.client.post(
            f"/api/admin/users/{self.target_user.id}/role/",
            {"role": "MODERATOR"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # =========================================================================
    # 3. ADMIN Role Assignment Authority
    # =========================================================================
    def test_superadmin_can_assign_admin_role(self):
        """Only system superadmin can assign the ADMIN role."""
        self.client.force_authenticate(user=self.superadmin)
        resp = self.client.post(
            f"/api/admin/users/{self.target_user.id}/role/",
            {"role": "ADMIN"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["role"], "ADMIN")

        self.target_user.refresh_from_db()
        self.assertEqual(get_user_role(self.target_user), "ADMIN")
        self.assertTrue(self.target_user.groups.filter(name="Admin").exists())
        self.assertTrue(self.target_user.is_staff)

    def test_admin_cannot_assign_admin_role(self):
        """ADMIN cannot assign the ADMIN role (only superadmin can; 403 Forbidden)."""
        self.client.force_authenticate(user=self.admin)
        resp = self.client.post(
            f"/api/admin/users/{self.target_user.id}/role/",
            {"role": "ADMIN"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("Only system superadmin can assign the ADMIN role", resp.data.get("detail", ""))

        # Target user role must remain unchanged
        self.target_user.refresh_from_db()
        self.assertEqual(get_user_role(self.target_user), "CUSTOMER")

    def test_moderator_and_customer_cannot_assign_admin_role(self):
        """Neither Moderator nor Customer can assign the ADMIN role."""
        self.client.force_authenticate(user=self.moderator)
        resp = self.client.post(
            f"/api/admin/users/{self.target_user.id}/role/",
            {"role": "ADMIN"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        self.client.force_authenticate(user=self.customer)
        resp = self.client.post(
            f"/api/admin/users/{self.target_user.id}/role/",
            {"role": "ADMIN"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    # =========================================================================
    # 4. MODERATOR Permission Boundaries
    # =========================================================================
    def test_moderator_can_create_product(self):
        """Moderator CAN create product object."""
        self.client.force_authenticate(user=self.moderator)
        payload = {
            "name": "Moderator Created Camera Cover",
            "description": "Sliding webcam cover",
            "price": "9.99",
            "stock_quantity": 50,
        }
        resp = self.client.post("/api/products/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(resp.data["name"], "Moderator Created Camera Cover")
        self.assertTrue(Product.objects.filter(name="Moderator Created Camera Cover").exists())

    def test_moderator_can_update_product(self):
        """Moderator CAN update product object."""
        self.client.force_authenticate(user=self.moderator)
        resp = self.client.patch(
            f"/api/products/{self.product.id}/",
            {"price": "34.99"},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.product.refresh_from_db()
        self.assertEqual(self.product.price, Decimal("34.99"))

    def test_moderator_cannot_delete_product(self):
        """Moderator CANNOT delete product object (403 Forbidden)."""
        self.client.force_authenticate(user=self.moderator)
        resp = self.client.delete(f"/api/products/{self.product.id}/")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        # Product must still exist in the database
        self.assertTrue(Product.objects.filter(id=self.product.id).exists())

    def test_moderator_cannot_view_cross_customer_orders_or_audit_logs(self):
        """Moderator cannot view admin orders or audit logs."""
        self.client.force_authenticate(user=self.moderator)

        resp_orders = self.client.get("/api/admin/orders/")
        self.assertEqual(resp_orders.status_code, status.HTTP_403_FORBIDDEN)

        resp_events = self.client.get("/api/admin/security-events/")
        self.assertEqual(resp_events.status_code, status.HTTP_403_FORBIDDEN)

    # =========================================================================
    # 5. CUSTOMER Permission Boundaries
    # =========================================================================
    def test_customer_cannot_create_or_delete_product(self):
        """Customer cannot create or delete products."""
        self.client.force_authenticate(user=self.customer)

        resp_create = self.client.post(
            "/api/products/",
            {"name": "Hacked Product", "price": "1.00", "stock_quantity": 1},
            format="json",
        )
        self.assertEqual(resp_create.status_code, status.HTTP_403_FORBIDDEN)

        resp_delete = self.client.delete(f"/api/products/{self.product.id}/")
        self.assertEqual(resp_delete.status_code, status.HTTP_403_FORBIDDEN)

    def test_customer_can_create_order_and_address(self):
        """Customer can create order and address."""
        self.client.force_authenticate(user=self.customer)

        # 1. Customer can create address
        addr_resp = self.client.post(
            "/api/addresses/",
            {
                "full_name": "Charlie Customer",
                "street_address": "123 Main St",
                "city": "Boston",
                "postal_code": "02101",
                "phone_number": "+1-555-111-3333",
                "email": "charlie@example.com",
            },
            format="json",
        )
        self.assertEqual(addr_resp.status_code, status.HTTP_201_CREATED)

        # 2. Customer can checkout
        order_resp = self.client.post(
            "/api/checkout/",
            {
                "items": [{"product_id": self.product.id, "quantity": 1}],
                "recipient_name": "Charlie Customer",
                "phone_number": "+1-555-111-3333",
                "email": "charlie@example.com",
                "delivery_address": "123 Main St",
                "delivery_city": "Boston",
                "delivery_postal_code": "02101",
            },
            format="json",
        )
        self.assertEqual(order_resp.status_code, status.HTTP_201_CREATED)

    # =========================================================================
    # 6. ADMIN & SUPERADMIN Permission Boundaries
    # =========================================================================
    def test_admin_can_delete_product(self):
        """Admin CAN delete product."""
        self.client.force_authenticate(user=self.admin)
        resp = self.client.delete(f"/api/products/{self.product.id}/")
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Product.objects.filter(id=self.product.id).exists())

    def test_superadmin_can_delete_product(self):
        """Superadmin CAN delete product."""
        prod = Product.objects.create(name="Delete Me", price=Decimal("5.00"), stock_quantity=1)
        self.client.force_authenticate(user=self.superadmin)
        resp = self.client.delete(f"/api/products/{prod.id}/")
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Product.objects.filter(id=prod.id).exists())

    # =========================================================================
    # 7. Role Documentation API
    # =========================================================================
    def test_roles_list_endpoint_documents_boundaries(self):
        """GET /api/admin/roles/ returns definitions and boundaries for all 3 roles."""
        resp = self.client.get("/api/admin/roles/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        roles = [r["role"] for r in resp.data]
        self.assertEqual(roles, ["CUSTOMER", "MODERATOR", "ADMIN"])

        # Check moderator boundary in docs
        mod_info = next(r for r in resp.data if r["role"] == "MODERATOR")
        self.assertTrue(mod_info["can_create_products"])
        self.assertFalse(mod_info["can_delete_products"])
        self.assertEqual(mod_info["assigned_by"], "System Superadmin or ADMIN")

        # Check admin boundary in docs
        admin_info = next(r for r in resp.data if r["role"] == "ADMIN")
        self.assertTrue(admin_info["can_delete_products"])
        self.assertEqual(admin_info["assigned_by"], "System Superadmin ONLY")

    def test_admin_can_list_users_with_roles(self):
        """Admin can list all users and view their roles."""
        self.client.force_authenticate(user=self.admin)
        resp = self.client.get("/api/admin/users/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        usernames = [u["username"] for u in resp.data]
        self.assertIn("admin_alice", usernames)
        self.assertIn("moderator_mike", usernames)
        self.assertIn("customer_charlie", usernames)

    def test_customer_cannot_list_users(self):
        """Customer cannot list users (403 Forbidden)."""
        self.client.force_authenticate(user=self.customer)
        resp = self.client.get("/api/admin/users/")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_swagger_and_schema_endpoints_accessible(self):
        """Swagger UI (/api/docs/) and Schema (/api/schema/) are accessible."""
        resp_docs = self.client.get("/api/docs/")
        self.assertEqual(resp_docs.status_code, status.HTTP_200_OK)

        resp_schema = self.client.get("/api/schema/")
        self.assertEqual(resp_schema.status_code, status.HTTP_200_OK)
