"""
apps/products/views.py
======================
Generic API Views for product catalog management.
Authenticated users can list and retrieve available products.
Admins holding specific model permissions can create, update, or delete products.
"""

from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from drf_spectacular.utils import extend_schema, extend_schema_view
from apps.products.models import Product
from apps.products.serializers import ProductSerializer
from apps.core.permissions import IsAdminOrReadOnly


@extend_schema_view(
    get=extend_schema(
        summary="List all catalog products",
        description="Returns list of all available products in the catalog. Requires authentication.",
        tags=["Products"],
    ),
    post=extend_schema(
        summary="Create a new catalog product",
        description="Adds a new product to the catalog. Restricted to administrators holding 'products.add_product'.",
        tags=["Products"],
    ),
)
class ProductListCreateAPIView(ListCreateAPIView):
    """
    GET /api/products/  -> List products (Authenticated users)
    POST /api/products/ -> Create a new product (Staff with 'products.add_product')
    """

    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAdminOrReadOnly]


@extend_schema_view(
    get=extend_schema(
        summary="Retrieve product by ID",
        description="Returns detailed information for a single catalog product.",
        tags=["Products"],
    ),
    put=extend_schema(
        summary="Update product (full)",
        description="Completely replaces product details. Restricted to administrators holding 'products.change_product'.",
        tags=["Products"],
    ),
    patch=extend_schema(
        summary="Update product (partial)",
        description="Partially updates product fields. Restricted to administrators holding 'products.change_product'.",
        tags=["Products"],
    ),
    delete=extend_schema(
        summary="Delete product",
        description="Deletes a product from the catalog. Restricted to administrators holding 'products.delete_product'.",
        tags=["Products"],
    ),
)
class ProductDetailAPIView(RetrieveUpdateDestroyAPIView):
    """
    GET /api/products/<id>/    -> Retrieve product details (Authenticated users)
    PUT /api/products/<id>/    -> Full update (Staff with 'products.change_product')
    PATCH /api/products/<id>/  -> Partial update (Staff with 'products.change_product')
    DELETE /api/products/<id>/ -> Delete product (Staff with 'products.delete_product')
    """

    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAdminOrReadOnly]
