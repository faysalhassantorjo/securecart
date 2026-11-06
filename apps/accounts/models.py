"""
apps/accounts/models.py
=======================
Address model linked to Django's built-in User.
Sensitive fields (phone number and email) are encrypted at rest.
"""

from django.db import models
from django.contrib.auth.models import User


class Address(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="addresses")
    full_name = models.CharField(max_length=255)
    street_address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)

    # Sensitive fields stored strictly as AES-256-GCM ciphertext
    encrypted_phone = models.TextField(help_text="AES-256-GCM encrypted phone number")
    encrypted_email = models.TextField(help_text="AES-256-GCM encrypted email address")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-id"]
        verbose_name = "Address"
        verbose_name_plural = "Addresses"

    def __str__(self):
        return f"Address #{self.id} for {self.full_name} ({self.city})"
