"""
apps/orders/models.py
=====================
Models for Order and OrderItem.
Orders store server-calculated totals, delivery snapshots, and AES-256-GCM
encrypted customer contact details (phone and email).
"""

from decimal import Decimal
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator
from django.db.models.signals import post_save
from django.dispatch import receiver
from apps.products.models import Product
from apps.core.encryption import encrypt_value, get_cipher


class Order(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("confirmed", "Confirmed"),
        ("processing", "Processing"),
        ("shipped", "Shipped"),
        ("cancelled", "Cancelled"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="orders")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="confirmed")
    total_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=Decimal("0.00"),
        validators=[MinValueValidator(Decimal("0.00"))],
    )

    # Immutable delivery snapshot captured at checkout
    recipient_name = models.CharField(max_length=255)
    delivery_address = models.CharField(max_length=255)
    delivery_city = models.CharField(max_length=100)
    delivery_postal_code = models.CharField(max_length=20)

    # Sensitive customer contact details encrypted at rest using AES-256-GCM
    encrypted_phone = models.TextField(help_text="AES-256-GCM encrypted customer phone number")
    encrypted_email = models.TextField(help_text="AES-256-GCM encrypted customer email address")

    # Relationship to dedicated order address snapshot
    order_address = models.ForeignKey(
        "orders.OrderAddress",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="primary_orders",
        help_text="Primary delivery address associated with this order.",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Order"
        verbose_name_plural = "Orders"
        permissions = [
            ("view_sensitive_customer_data", "Can view decrypted customer sensitive data"),
        ]

    def __str__(self):
        return f"Order #{self.id} - {self.user.username} (${self.total_amount}) [{self.status}]"

    @property
    def address(self):
        """Returns the primary order address or first linked order address."""
        if self.order_address_id:
            return self.order_address
        return self.order_addresses.first()

    @property
    def addresses(self):
        """QuerySet of all order addresses linked to this order."""
        return self.order_addresses.all()


class OrderAddress(models.Model):
    """
    Model for storing user order address snapshots created during checkout.
    Establishes foreign-key relationships with both Order and User.
    Sensitive contact and address fields are encrypted at rest using AES-256-GCM.
    Access is restricted to the user who placed the order, superadmin, and users with Admin role.
    """

    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="order_addresses")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="order_addresses")

    recipient_name = models.CharField(max_length=255)
    street_address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)

    # Sensitive contact and street address details encrypted at rest using AES-256-GCM
    encrypted_street_address = models.TextField(
        help_text="AES-256-GCM encrypted street address",
        blank=True,
        default="",
    )
    encrypted_phone = models.TextField(help_text="AES-256-GCM encrypted customer phone number")
    encrypted_email = models.TextField(help_text="AES-256-GCM encrypted customer email address")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        verbose_name = "Order Address"
        verbose_name_plural = "Order Addresses"

    def __str__(self):
        return f"OrderAddress #{self.id} for Order #{self.order_id} ({self.recipient_name}, {self.city})"

    @property
    def full_name(self):
        return self.recipient_name

    @property
    def delivery_address(self):
        return self.street_address

    @property
    def delivery_city(self):
        return self.city

    @property
    def delivery_postal_code(self):
        return self.postal_code

    @property
    def decrypted_street_address(self):
        if self.encrypted_street_address:
            return get_cipher().decrypt_or_mask(self.encrypted_street_address)
        return self.street_address

    @property
    def decrypted_phone(self):
        return get_cipher().decrypt_or_mask(self.encrypted_phone)

    @property
    def decrypted_email(self):
        return get_cipher().decrypt_or_mask(self.encrypted_email)


# Alias Address to OrderAddress for flexible imports
Address = OrderAddress


@receiver(post_save, sender=Order)
def ensure_order_address_snapshot(sender, instance, created, **kwargs):
    """
    Automatic sync: When an order is created, if it doesn't already have an OrderAddress
    and has delivery information, create and link the OrderAddress snapshot automatically.
    """
    if created and not getattr(instance, "_skip_auto_address", False):
        if not instance.order_addresses.exists() and instance.delivery_address:
            enc_street = encrypt_value(instance.delivery_address) if instance.delivery_address else ""
            addr = OrderAddress.objects.create(
                order=instance,
                user=instance.user,
                recipient_name=instance.recipient_name,
                street_address=instance.delivery_address,
                city=instance.delivery_city,
                postal_code=instance.delivery_postal_code,
                encrypted_street_address=enc_street,
                encrypted_phone=instance.encrypted_phone,
                encrypted_email=instance.encrypted_email,
            )
            Order.objects.filter(pk=instance.pk).update(order_address=addr)
            instance.order_address = addr


class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(Product, on_delete=models.PROTECT, related_name="order_items")
    quantity = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    unit_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text="Product price at the moment of checkout (server-enforced).",
    )
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        ordering = ["id"]
        verbose_name = "Order Item"
        verbose_name_plural = "Order Items"

    def __str__(self):
        return f"{self.quantity}x {self.product.name} @ ${self.unit_price}"
