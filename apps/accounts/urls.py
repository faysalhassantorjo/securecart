"""
apps/accounts/urls.py
=====================
URL routes for user addresses.
"""

from django.urls import path
from apps.accounts.views import AddressListCreateAPIView, AddressDetailAPIView

urlpatterns = [
    path("", AddressListCreateAPIView.as_view(), name="address-list-create"),
    path("<int:pk>/", AddressDetailAPIView.as_view(), name="address-detail"),
]
