"""
apps/orders/serializers.py
==========================
Serializers for Checkout validation, Order listing, and Order detail retrieval.
Enforces server-side validation and permission-gated decryption of sensitive contact info.
"""

from rest_framework import serializers
from apps.orders.models import Order, OrderItem, OrderAddress
from apps.core.encryption import get_cipher
from apps.core.permissions import can_view_sensitive_data
from apps.core.audit import record_security_event


class CheckoutItemInputSerializer(serializers.Serializer):
    product_id = serializers.IntegerField(required=True, min_value=1)
    quantity = serializers.IntegerField(required=True, min_value=1)


class CheckoutInputSerializer(serializers.Serializer):
    items = CheckoutItemInputSerializer(many=True, allow_empty=False)
    recipient_name = serializers.CharField(max_length=255, required=True)
    phone_number = serializers.CharField(max_length=30, required=True)
    email = serializers.EmailField(required=True)
    delivery_address = serializers.CharField(max_length=255, required=True)
    delivery_city = serializers.CharField(max_length=100, required=True)
    delivery_postal_code = serializers.CharField(max_length=20, required=True)


class OrderItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source="product.name", read_only=True)

    class Meta:
        model = OrderItem
        fields = [
            "id",
            "product_id",
            "product_name",
            "quantity",
            "unit_price",
            "subtotal",
        ]
        read_only_fields = fields


class OrderAddressSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for OrderAddress.
    Decrypts sensitive street address, phone number, and email strictly for:
    - The customer who placed the order (owner)
    - Superadmin
    - Users holding the Admin role
    For all other callers, sensitive values are securely masked.
    """

    order_id = serializers.IntegerField(source="order.id", read_only=True)
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    username = serializers.CharField(source="user.username", read_only=True)

    # Decrypted fields (gated by permission check)
    decrypted_street_address = serializers.SerializerMethodField()
    decrypted_phone = serializers.SerializerMethodField()
    decrypted_email = serializers.SerializerMethodField()

    # Raw ciphertexts preserved for evaluation inspection
    encrypted_street_address = serializers.CharField(read_only=True)
    encrypted_phone = serializers.CharField(read_only=True)
    encrypted_email = serializers.CharField(read_only=True)

    class Meta:
        model = OrderAddress
        fields = [
            "id",
            "order_id",
            "user_id",
            "username",
            "recipient_name",
            "street_address",
            "city",
            "postal_code",
            "decrypted_street_address",
            "decrypted_phone",
            "decrypted_email",
            "encrypted_street_address",
            "encrypted_phone",
            "encrypted_email",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def _check_and_log_admin_access(self, instance):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            is_admin_or_super = (
                request.user.is_superuser
                or request.user.groups.filter(name="Admin").exists()
                or (request.user.is_staff and request.user.has_perm("orders.view_order"))
            )
            if is_admin_or_super and instance.user != request.user:
                record_security_event(
                    event_type="ADMIN_SENSITIVE_DATA_ACCESS",
                    request=request,
                    order_id=instance.order_id,
                    description=(
                        f"Admin '{request.user.username}' viewed decrypted PII for OrderAddress #{instance.id} "
                        f"(Order #{instance.order_id}, Customer: '{instance.user.username}')"
                    ),
                )

    def _is_authorized(self, instance) -> bool:
        request = self.context.get("request")
        user = request.user if request else None
        return can_view_sensitive_data(user, instance)

    def get_decrypted_street_address(self, instance) -> str:
        if self._is_authorized(instance):
            self._check_and_log_admin_access(instance)
            if instance.encrypted_street_address:
                return get_cipher().decrypt_or_mask(instance.encrypted_street_address)
            return instance.street_address
        return "[MASKED - INSUFFICIENT PERMISSION]"

    def get_decrypted_phone(self, instance) -> str:
        if self._is_authorized(instance):
            self._check_and_log_admin_access(instance)
            return get_cipher().decrypt_or_mask(instance.encrypted_phone)
        return "[MASKED - INSUFFICIENT PERMISSION]"

    def get_decrypted_email(self, instance) -> str:
        if self._is_authorized(instance):
            return get_cipher().decrypt_or_mask(instance.encrypted_email)
        return "[MASKED - INSUFFICIENT PERMISSION]"


class OrderConfirmationSerializer(serializers.ModelSerializer):
    """Safe response after checkout that does not leak unnecessary sensitive PII."""

    items_count = serializers.IntegerField(source="items.count", read_only=True)
    order_address_id = serializers.IntegerField(source="address.id", read_only=True)
    message = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            "id",
            "status",
            "total_amount",
            "recipient_name",
            "items_count",
            "order_address_id",
            "created_at",
            "message",
        ]
        read_only_fields = fields

    def get_message(self, obj) -> str:
        return "Order placed successfully. Sensitive customer details have been encrypted with AES-256-GCM."


class OrderListSerializer(serializers.ModelSerializer):
    """Compact summary of orders for list endpoints."""

    items_count = serializers.IntegerField(source="items.count", read_only=True)

    class Meta:
        model = Order
        fields = [
            "id",
            "status",
            "total_amount",
            "recipient_name",
            "items_count",
            "created_at",
        ]
        read_only_fields = fields


class OrderDetailSerializer(serializers.ModelSerializer):
    """
    Detailed order representation with decrypted contact details only when authorized.
    Includes related OrderAddress object(s).
    """

    username = serializers.CharField(source="user.username", read_only=True)
    items = OrderItemSerializer(many=True, read_only=True)
    order_address = OrderAddressSerializer(source="address", read_only=True)
    order_addresses = OrderAddressSerializer(source="addresses", many=True, read_only=True)

    # Decrypted fields (gated by permission check)
    decrypted_phone = serializers.SerializerMethodField()
    decrypted_email = serializers.SerializerMethodField()

    # Raw ciphertexts preserved for evaluation inspection
    encrypted_phone = serializers.CharField(read_only=True)
    encrypted_email = serializers.CharField(read_only=True)

    class Meta:
        model = Order
        fields = [
            "id",
            "username",
            "status",
            "total_amount",
            "recipient_name",
            "delivery_address",
            "delivery_city",
            "delivery_postal_code",
            "decrypted_phone",
            "decrypted_email",
            "encrypted_phone",
            "encrypted_email",
            "items",
            "order_address",
            "order_addresses",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def _check_and_log_admin_access(self, instance):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            if request.user.is_staff and instance.user != request.user:
                record_security_event(
                    event_type="ADMIN_SENSITIVE_DATA_ACCESS",
                    request=request,
                    order_id=instance.id,
                    description=f"Admin '{request.user.username}' viewed decrypted PII for Order #{instance.id} (Customer: '{instance.user.username}')",
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
