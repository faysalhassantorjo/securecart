"""
apps/products/urls.py
=====================
URL routes for the product catalog.
"""

from django.urls import path
from apps.products.views import ProductListCreateAPIView, ProductDetailAPIView

urlpatterns = [
    path("", ProductListCreateAPIView.as_view(), name="product-list-create"),
    path("<int:pk>/", ProductDetailAPIView.as_view(), name="product-detail"),
]
