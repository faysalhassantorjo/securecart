"""
tests/test_registration.py
==========================
Comprehensive tests for User Registration API:
- Successful customer account creation with password validation.
- Automatic assignment to 'Customer' role group.
- JWT token pair issuance for immediate authentication.
- Immediate access to protected endpoints using issued tokens.
- Privilege escalation defense (ignoring is_staff, is_superuser flags).
- Password mismatch validation.
- Password complexity validation against Django password validators.
- Duplicate username and email prevention (case-insensitive).
- Security audit event recording for USER_REGISTRATION.
"""

from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from rest_framework.test import APIClient
from rest_framework import status

from apps.audit_logs.models import AuditLog


class UserRegistrationTests(TestCase):
    def setUp(self):
        call_command("setup_roles")
        self.client = APIClient()

        self.valid_payload = {
            "username": "new_shopper",
            "email": "shopper@example.com",
            "password": "SecurePassword123!",
            "password_confirm": "SecurePassword123!",
            "first_name": "Jane",
            "last_name": "Doe",
        }

    def test_registration_success(self):
        """Valid registration creates customer, hashes password, assigns role, and returns JWT tokens."""
        response = self.client.post("/api/auth/register/", self.valid_payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["message"], "User registered successfully.")

        # Validate user payload in response
        user_data = response.data["user"]
        self.assertEqual(user_data["username"], "new_shopper")
        self.assertEqual(user_data["email"], "shopper@example.com")
        self.assertEqual(user_data["first_name"], "Jane")
        self.assertEqual(user_data["last_name"], "Doe")
        self.assertNotIn("password", user_data)

        # Validate tokens returned
        tokens = response.data["tokens"]
        self.assertIn("access", tokens)
        self.assertIn("refresh", tokens)

        # Verify database record
        user = User.objects.get(username="new_shopper")
        self.assertTrue(user.check_password("SecurePassword123!"))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        # Verify group assignment
        customer_group = Group.objects.get(name="Customer")
        self.assertIn(customer_group, user.groups.all())

        # Verify security audit event
        audit_entry = AuditLog.objects.filter(
            event_type="USER_REGISTRATION",
            user=user,
        ).first()
        self.assertIsNotNone(audit_entry, "Registration must create a security audit event.")
        self.assertIn("new_shopper", audit_entry.description)

    def test_registration_alias_endpoint(self):
        """Direct alias /api/register/ behaves identically to /api/auth/register/."""
        payload = dict(self.valid_payload)
        payload["username"] = "alias_shopper"
        payload["email"] = "alias@example.com"

        response = self.client.post("/api/register/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username="alias_shopper").exists())

    def test_tokens_allow_immediate_authenticated_access(self):
        """Tokens issued at registration immediately authorize access to protected endpoints."""
        reg_response = self.client.post("/api/auth/register/", self.valid_payload, format="json")
        self.assertEqual(reg_response.status_code, status.HTTP_201_CREATED)

        access_token = reg_response.data["tokens"]["access"]

        # Access protected address endpoint with the returned token
        auth_client = APIClient()
        auth_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        resp = auth_client.get("/api/addresses/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        # Create address with the returned token
        create_addr_resp = auth_client.post(
            "/api/addresses/",
            {
                "full_name": "Jane Doe",
                "street_address": "123 Shopping Way",
                "city": "Metropolis",
                "postal_code": "10001",
                "phone_number": "+1-555-0199",
                "email": "shopper@example.com",
            },
            format="json",
        )
        self.assertEqual(create_addr_resp.status_code, status.HTTP_201_CREATED)

    def test_registration_password_mismatch(self):
        """Mismatched password and password_confirm returns 400 Bad Request."""
        payload = dict(self.valid_payload)
        payload["password_confirm"] = "DifferentPass999!"

        response = self.client.post("/api/auth/register/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username="new_shopper").exists())
        self.assertIn("password_confirm", str(response.data))

    def test_registration_weak_password_rejected(self):
        """Weak passwords rejected by Django password validators return 400."""
        # Too short (< 8 chars)
        payload_short = dict(self.valid_payload)
        payload_short["password"] = "short"
        payload_short["password_confirm"] = "short"

        resp_short = self.client.post("/api/auth/register/", payload_short, format="json")
        self.assertEqual(resp_short.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username="new_shopper").exists())

        # Entirely numeric
        payload_numeric = dict(self.valid_payload)
        payload_numeric["password"] = "12345678"
        payload_numeric["password_confirm"] = "12345678"

        resp_num = self.client.post("/api/auth/register/", payload_numeric, format="json")
        self.assertEqual(resp_num.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_duplicate_username_rejected(self):
        """Cannot register with an existing username (case-insensitive)."""
        self.client.post("/api/auth/register/", self.valid_payload, format="json")

        duplicate_payload = dict(self.valid_payload)
        duplicate_payload["username"] = "NEW_SHOPPER"  # uppercase variant
        duplicate_payload["email"] = "different_email@example.com"

        response = self.client.post("/api/auth/register/", duplicate_payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("username", str(response.data))

    def test_registration_duplicate_email_rejected(self):
        """Cannot register with an existing email (case-insensitive)."""
        self.client.post("/api/auth/register/", self.valid_payload, format="json")

        duplicate_email_payload = dict(self.valid_payload)
        duplicate_email_payload["username"] = "another_unique_user"
        duplicate_email_payload["email"] = "SHOPPER@EXAMPLE.COM"  # uppercase variant

        response = self.client.post("/api/auth/register/", duplicate_email_payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", str(response.data))

    def test_registration_invalid_email_format(self):
        """Invalid email formats return 400 Bad Request."""
        payload = dict(self.valid_payload)
        payload["email"] = "not-a-valid-email"

        response = self.client.post("/api/auth/register/", payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", str(response.data))

    def test_privilege_escalation_prevented(self):
        """Attempting to inject is_staff or is_superuser flags has no effect."""
        escalation_payload = dict(self.valid_payload)
        escalation_payload["is_staff"] = True
        escalation_payload["is_superuser"] = True

        response = self.client.post("/api/auth/register/", escalation_payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(username="new_shopper")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
