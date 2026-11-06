"""
tests/test_auth_roles.py
========================
Tests for JWT Authentication, Django Default Groups and Permissions,
and access control boundaries.
"""

from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from rest_framework.test import APIClient
from rest_framework import status


class AuthAndRoleTests(TestCase):
    def setUp(self):
        call_command("setup_roles")
        self.client = APIClient()

        # Customer user
        self.customer = User.objects.create_user(
            username="customer_tester",
            email="tester@example.com",
            password="TestPassword123!",
        )
        self.customer.groups.add(Group.objects.get(name="Customer"))

        # Admin user
        self.admin = User.objects.create_user(
            username="admin_tester",
            email="admin@example.com",
            password="AdminPassword123!",
            is_staff=True,
        )
        self.admin.groups.add(Group.objects.get(name="Admin"))

    def test_jwt_token_obtain_success(self):
        """Valid credentials return JWT access and refresh tokens."""
        response = self.client.post(
            "/api/auth/token/",
            {"username": "customer_tester", "password": "TestPassword123!"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_jwt_token_obtain_invalid_credentials(self):
        """Invalid credentials return 401 Unauthorized."""
        response = self.client.post(
            "/api/auth/token/",
            {"username": "customer_tester", "password": "WrongPassword"},
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_jwt_token_refresh(self):
        """Valid refresh token issues a new access token."""
        token_resp = self.client.post(
            "/api/auth/token/",
            {"username": "customer_tester", "password": "TestPassword123!"},
        )
        refresh_token = token_resp.data["refresh"]

        refresh_resp = self.client.post(
            "/api/auth/token/refresh/",
            {"refresh": refresh_token},
        )
        self.assertEqual(refresh_resp.status_code, status.HTTP_200_OK)
        self.assertIn("access", refresh_resp.data)

    def test_unauthenticated_request_rejected(self):
        """Unauthenticated requests to protected endpoints return 401."""
        response = self.client.get("/api/products/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        response = self.client.get("/api/orders/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        response = self.client.get("/api/addresses/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_customer_cannot_access_admin_endpoints(self):
        """Customer role cannot access administrative endpoints (returns 403 Forbidden)."""
        self.client.force_authenticate(user=self.customer)

        resp = self.client.get("/api/admin/orders/")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

        resp = self.client.get("/api/admin/security-events/")
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)

    def test_customer_cannot_create_or_modify_products(self):
        """Customers cannot create, modify, or delete catalog products."""
        self.client.force_authenticate(user=self.customer)

        resp = self.client.post(
            "/api/products/",
            {"name": "Hacked Product", "price": "1.00", "stock_quantity": 10},
        )
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
