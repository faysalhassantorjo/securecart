from django.contrib import admin
from apps.orders.models import Order, OrderItem, OrderAddress


@admin.register(OrderAddress)
class OrderAddressAdmin(admin.ModelAdmin):
    list_display = ("id", "order_id", "user", "recipient_name", "city", "created_at")
    search_fields = ("recipient_name", "city", "order__id", "user__username")
    readonly_fields = (
        "created_at",
        "updated_at",
        "encrypted_phone",
        "encrypted_email",
        "encrypted_street_address",
    )


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "status", "total_amount", "recipient_name", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("recipient_name", "user__username", "id")
    readonly_fields = ("created_at", "updated_at")


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    list_display = ("id", "order", "product", "quantity", "unit_price", "subtotal")
