"""
apps/orders/urls.py
===================
URL routes for Checkout and Orders.
"""

from django.urls import path
from apps.orders.views import (
    CheckoutAPIView,
    OrderListAPIView,
    OrderDetailAPIView,
    AdminOrderListAPIView,
    OrderAddressListAPIView,
    OrderAddressDetailAPIView,
    OrderAddressByOrderAPIView,
    AdminOrderAddressListAPIView,
    OrderAddressListAliasView,
    OrderAddressDetailAliasView,
    OrderAddressByOrderAliasView,
)

urlpatterns = [
    path("checkout/", CheckoutAPIView.as_view(), name="checkout"),
    path("orders/", OrderListAPIView.as_view(), name="order-list"),
    path("orders/<int:pk>/", OrderDetailAPIView.as_view(), name="order-detail"),
    path("orders/<int:order_id>/address/", OrderAddressByOrderAPIView.as_view(), name="order-address-by-order"),
    path("orders/<int:order_id>/addresses/", OrderAddressByOrderAliasView.as_view(), name="order-addresses-by-order"),
    path("order-addresses/", OrderAddressListAPIView.as_view(), name="order-address-list"),
    path("order-addresses/<int:pk>/", OrderAddressDetailAPIView.as_view(), name="order-address-detail"),
    path("order-address/", OrderAddressListAliasView.as_view(), name="order-address-list-alias"),
    path("order-address/<int:pk>/", OrderAddressDetailAliasView.as_view(), name="order-address-detail-alias"),
    path("admin/orders/", AdminOrderListAPIView.as_view(), name="admin-order-list"),
    path("admin/order-addresses/", AdminOrderAddressListAPIView.as_view(), name="admin-order-address-list"),
]
