"""
apps/accounts/serializers.py
============================
Address serializer with AES-256-GCM encryption on write
and permission-gated decryption on read.
"""

from rest_framework import serializers
from django.contrib.auth.models import User, Group
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction

from apps.accounts.models import Address
from apps.core.encryption import encrypt_value, decrypt_value, get_cipher
from apps.core.permissions import can_view_sensitive_data
from apps.core.audit import record_security_event


class AddressSerializer(serializers.ModelSerializer):
    # Plaintext input fields for creation/update
    phone_number = serializers.CharField(
        write_only=True,
        required=True,
        max_length=30,
        help_text="Plaintext phone number (will be encrypted prior to database persistence).",
    )
    email = serializers.EmailField(
        write_only=True,
        required=True,
        help_text="Plaintext email address (will be encrypted prior to database persistence).",
    )

    # Output fields (conditionally decrypted or masked)
    decrypted_phone = serializers.SerializerMethodField(read_only=True)
    decrypted_email = serializers.SerializerMethodField(read_only=True)
    encrypted_phone = serializers.CharField(read_only=True)
    encrypted_email = serializers.CharField(read_only=True)

    class Meta:
        model = Address
        fields = [
            "id",
            "full_name",
            "street_address",
            "city",
            "postal_code",
            "phone_number",
            "email",
            "decrypted_phone",
            "decrypted_email",
            "encrypted_phone",
            "encrypted_email",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def create(self, validated_data):
        phone_plaintext = validated_data.pop("phone_number")
        email_plaintext = validated_data.pop("email")

        # Encrypt sensitive fields prior to database insert
        validated_data["encrypted_phone"] = encrypt_value(phone_plaintext)
        validated_data["encrypted_email"] = encrypt_value(email_plaintext)

        return super().create(validated_data)

    def update(self, instance, validated_data):
        phone_plaintext = validated_data.pop("phone_number", None)
        email_plaintext = validated_data.pop("email", None)

        if phone_plaintext is not None:
            instance.encrypted_phone = encrypt_value(phone_plaintext)
        if email_plaintext is not None:
            instance.encrypted_email = encrypt_value(email_plaintext)

        return super().update(instance, validated_data)

    def _check_and_log_admin_access(self, instance):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            # If admin is accessing someone else's sensitive data, record an audit trail
            if request.user.is_staff and instance.user != request.user:
                record_security_event(
                    event_type="ADMIN_SENSITIVE_DATA_ACCESS",
                    request=request,
                    description=f"Admin '{request.user.username}' accessed decrypted PII for Address #{instance.id} (Owner: '{instance.user.username}')",
                )

    def get_decrypted_phone(self, instance) -> str:
        request = self.context.get("request")
        user = request.user if request else None

        if can_view_sensitive_data(user, instance):
            self._check_and_log_admin_access(instance)
            return get_cipher().decrypt_or_mask(instance.encrypted_phone)
        return "[MASKED - INSUFFICIENT PERMISSION]"

    def get_decrypted_email(self, instance) -> str:
        request = self.context.get("request")
        user = request.user if request else None

        if can_view_sensitive_data(user, instance):
            return get_cipher().decrypt_or_mask(instance.encrypted_email)
        return "[MASKED - INSUFFICIENT PERMISSION]"


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for new customer registration.
    Enforces strong passwords, checks username/email uniqueness,
    and automatically assigns the Customer group.
    """

    password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        trim_whitespace=False,
        style={"input_type": "password"},
        help_text="Password must satisfy standard security rules (minimum 8 characters, non-common).",
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        trim_whitespace=False,
        style={"input_type": "password"},
        help_text="Confirm password to prevent typos.",
    )

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "password",
            "password_confirm",
            "first_name",
            "last_name",
        ]
        read_only_fields = ["id"]
        extra_kwargs = {
            "first_name": {"required": False, "allow_blank": True},
            "last_name": {"required": False, "allow_blank": True},
            "email": {"required": True, "allow_blank": False},
        }

    def validate_username(self, value):
        username = value.strip()
        if len(username) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        validator = UnicodeUsernameValidator()
        try:
            validator(username)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        if User.objects.filter(username__iexact=username).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        return username

    def validate_email(self, value):
        email = value.strip().lower()
        if not email:
            raise serializers.ValidationError("Email is required.")
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("A user with this email address already exists.")
        return email

    def validate(self, attrs):
        password = attrs.get("password")
        password_confirm = attrs.get("password_confirm")

        if password != password_confirm:
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})

        # Run Django configured password validators
        temp_user = User(
            username=attrs.get("username", ""),
            email=attrs.get("email", ""),
            first_name=attrs.get("first_name", ""),
            last_name=attrs.get("last_name", ""),
        )
        try:
            validate_password(password, user=temp_user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})

        return attrs

    def create(self, validated_data):
        validated_data.pop("password_confirm", None)
        password = validated_data.pop("password")
        username = validated_data["username"]
        email = validated_data["email"]
        first_name = validated_data.get("first_name", "")
        last_name = validated_data.get("last_name", "")

        with transaction.atomic():
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
            user.is_staff = False
            user.is_superuser = False
            user.save(update_fields=["is_staff", "is_superuser"])

            customer_group, _ = Group.objects.get_or_create(name="Customer")
            user.groups.add(customer_group)

        return user


class UserSummarySerializer(serializers.ModelSerializer):
    """
    Public representation of a User object.
    Never exposes passwords, password hashes, or administrative flags.
    Includes the computed primary role (CUSTOMER, MODERATOR, ADMIN, SUPERADMIN).
    """

    role = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "role",
            "date_joined",
        ]
        read_only_fields = fields

    def get_role(self, obj) -> str:
        from apps.core.permissions import get_user_role
        return get_user_role(obj)


class TokenPairSerializer(serializers.Serializer):
    access = serializers.CharField(help_text="JWT access token.")
    refresh = serializers.CharField(help_text="JWT refresh token.")


class UserRegistrationResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    user = UserSummarySerializer()
    tokens = TokenPairSerializer()


class UserRoleAssignmentSerializer(serializers.Serializer):
    role = serializers.ChoiceField(
        choices=["CUSTOMER", "MODERATOR", "ADMIN"],
        help_text="Target role to assign. Allowed choices: CUSTOMER, MODERATOR, ADMIN.",
    )


class UserRoleResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    user_id = serializers.IntegerField()
    username = serializers.CharField()
    role = serializers.CharField()
    previous_role = serializers.CharField(required=False)


class UserRoleDetailSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    username = serializers.CharField()
    email = serializers.EmailField()
    role = serializers.CharField()
    is_staff = serializers.BooleanField()
    is_superuser = serializers.BooleanField()
    groups = serializers.ListField(child=serializers.CharField())
    permissions = serializers.ListField(child=serializers.CharField())


class RoleBoundarySerializer(serializers.Serializer):
    role = serializers.CharField()
    title = serializers.CharField()
    assigned_by = serializers.CharField()
    description = serializers.CharField()
    can_browse_products = serializers.BooleanField()
    can_create_products = serializers.BooleanField()
    can_update_products = serializers.BooleanField()
    can_delete_products = serializers.BooleanField()
    can_create_orders = serializers.BooleanField()
    can_create_addresses = serializers.BooleanField()
    can_view_all_orders = serializers.BooleanField()
    can_view_all_order_addresses = serializers.BooleanField()
    can_view_audit_logs = serializers.BooleanField()
    can_assign_moderator_role = serializers.BooleanField()
    can_assign_admin_role = serializers.BooleanField()
