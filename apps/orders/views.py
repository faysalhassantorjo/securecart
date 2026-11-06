"""
apps/orders/views.py
====================
API Views for Checkout and Order management using DRF APIView and Generic API Views.
Strictly avoids ViewSets to ensure clear, auditable authorization boundaries.
"""

from decimal import Decimal
from django.db import transaction
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse
from apps.orders.models import Order, OrderItem, OrderAddress
from apps.products.models import Product
from apps.orders.serializers import (
    CheckoutInputSerializer,
    OrderConfirmationSerializer,
    OrderListSerializer,
    OrderDetailSerializer,
    OrderAddressSerializer,
)
from apps.core.encryption import encrypt_value
from apps.core.permissions import (
    IsOwnerOrAdminWithPermission,
    HasAdminOrderPermission,
    CanViewOrderAddressPermission,
)
from apps.core.audit import record_security_event


class CheckoutAPIView(APIView):
    """
    POST /api/checkout/
    Custom checkout workflow executing within an atomic database transaction.
    - Validates product existence and stock availability with row-level locks.
    - Calculates server-side order total (never trusts client pricing).
    - Encrypts sensitive customer contact details (phone, email) with AES-256-GCM.
    - Atomically updates inventory and persists Order and OrderItems.
    - Automatically rolls back if any validation or stock check fails.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Execute checkout & place order",
        description="Processes checkout: validates inventory with row-level locks, calculates server-side totals, encrypts customer PII and delivery address with AES-256-GCM, and creates Order and OrderAddress atomically.",
        request=CheckoutInputSerializer,
        responses={201: OrderConfirmationSerializer},
        tags=["Orders"],
    )
    def post(self, request):
        serializer = CheckoutInputSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        items_data = data["items"]

        try:
            with transaction.atomic():
                # Extract and lock requested products to prevent stock race conditions
                product_ids = [item["product_id"] for item in items_data]
                products_by_id = {
                    p.id: p
                    for p in Product.objects.select_for_update().filter(id__in=product_ids)
                }

                # Validate product existence
                for item in items_data:
                    p_id = item["product_id"]
                    if p_id not in products_by_id:
                        return Response(
                            {"error": "Validation Error", "detail": f"Product with ID {p_id} does not exist."},
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                # Validate inventory availability
                for item in items_data:
                    p = products_by_id[item["product_id"]]
                    qty = item["quantity"]
                    if p.stock_quantity < qty:
                        return Response(
                            {
                                "error": "Insufficient Stock",
                                "detail": f"Product '{p.name}' only has {p.stock_quantity} item(s) in stock (requested {qty}).",
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                        )

                # Calculate order totals on server (Never trust client prices)
                calculated_total = Decimal("0.00")
                order_items_to_create = []

                for item in items_data:
                    p = products_by_id[item["product_id"]]
                    qty = item["quantity"]
                    unit_price = p.price
                    subtotal = unit_price * qty
                    calculated_total += subtotal

                    order_items_to_create.append(
                        {
                            "product": p,
                            "quantity": qty,
                            "unit_price": unit_price,
                            "subtotal": subtotal,
                        }
                    )

                # Encrypt sensitive customer contact details and delivery address before saving
                encrypted_phone = encrypt_value(data["phone_number"])
                encrypted_email = encrypt_value(data["email"])
                encrypted_street = encrypt_value(data["delivery_address"])

                # Create Order snapshot
                order = Order(
                    user=request.user,
                    status="confirmed",
                    total_amount=calculated_total,
                    recipient_name=data["recipient_name"],
                    delivery_address=data["delivery_address"],
                    delivery_city=data["delivery_city"],
                    delivery_postal_code=data["delivery_postal_code"],
                    encrypted_phone=encrypted_phone,
                    encrypted_email=encrypted_email,
                )
                order._skip_auto_address = True
                order.save()

                # Create dedicated OrderAddress snapshot with bidirectional relationship
                order_address = OrderAddress.objects.create(
                    order=order,
                    user=request.user,
                    recipient_name=data["recipient_name"],
                    street_address=data["delivery_address"],
                    city=data["delivery_city"],
                    postal_code=data["delivery_postal_code"],
                    encrypted_street_address=encrypted_street,
                    encrypted_phone=encrypted_phone,
                    encrypted_email=encrypted_email,
                )
                order.order_address = order_address
                order.save(update_fields=["order_address"])

                # Deduct inventory and persist OrderItems
                for item_info in order_items_to_create:
                    p = item_info["product"]
                    p.stock_quantity -= item_info["quantity"]
                    p.save(update_fields=["stock_quantity"])

                    OrderItem.objects.create(
                        order=order,
                        product=p,
                        quantity=item_info["quantity"],
                        unit_price=item_info["unit_price"],
                        subtotal=item_info["subtotal"],
                    )

                # Record security audit event
                record_security_event(
                    event_type="CHECKOUT_SUCCESS",
                    request=request,
                    order_id=order.id,
                    description=f"Order #{order.id} placed successfully by '{request.user.username}' for ${calculated_total}",
                )

                return Response(
                    OrderConfirmationSerializer(order).data,
                    status=status.HTTP_201_CREATED,
                )

        except Exception as e:
            # Re-raise to ensure transaction rollback
            raise e


@extend_schema_view(
    get=extend_schema(
        summary="List customer orders",
        description="Lists all orders placed by the currently authenticated customer. Customers cannot view orders belonging to other accounts.",
        tags=["Orders"],
    )
)
class OrderListAPIView(ListAPIView):
    """
    GET /api/orders/
    Lists all orders placed by the currently authenticated customer.
    Customers cannot view orders belonging to other accounts.
    """

    serializer_class = OrderListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Strict user scoping ensures IDOR/BOLA protection
        return Order.objects.filter(user=self.request.user).prefetch_related("items")


@extend_schema_view(
    get=extend_schema(
        summary="Retrieve order details by ID",
        description="Retrieves full details of a single order including items and linked OrderAddress. Decrypted customer PII is only returned for the owner or authorized staff.",
        tags=["Orders"],
    )
)
class OrderDetailAPIView(RetrieveAPIView):
    """
    GET /api/orders/<id>/
    Retrieves full details of a single order.
    - Customers can only retrieve their own orders.
    - Admins holding 'orders.view_order' can inspect any order.
    - Decrypted customer PII is only returned when authorized.
    """

    serializer_class = OrderDetailSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdminWithPermission]

    def get_queryset(self):
        return Order.objects.all().select_related("user").prefetch_related("items__product")

    def get_object(self):
        from django.http import Http404

        pk = self.kwargs.get("pk")
        user = self.request.user

        # Fetch order across system to detect IDOR attempts
        order = Order.objects.filter(pk=pk).select_related("user").prefetch_related("items__product").first()
        if order is None:
            raise Http404("No Order matches the given query.")

        # Check authorization: owner or staff with view_order permission
        is_owner = order.user == user
        is_authorized_staff = user.is_staff and user.has_perm("orders.view_order")

        if not (is_owner or is_authorized_staff):
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                request=self.request,
                user=user,
                order_id=order.id,
                description=f"User '{user.username}' attempted unauthorized access to Order #{order.id} owned by '{order.user.username}'",
            )
            # Return 404 to avoid leaking resource existence
            raise Http404("No Order matches the given query.")

        self.check_object_permissions(self.request, order)
        return order


class AdminOrderListAPIView(ListAPIView):
    """
    GET /api/admin/orders/
    Administrative endpoint to view all orders across all customers.
    Restricted to staff users holding 'orders.view_order'.
    """

    serializer_class = OrderDetailSerializer
    permission_classes = [IsAuthenticated, HasAdminOrderPermission]
    queryset = Order.objects.all().select_related("user").prefetch_related("items__product")

    @extend_schema(
        summary="Admin list all customer orders",
        description="Administrative endpoint to inspect all customer orders across the system. Restricted to staff with Admin role.",
        responses={200: OrderDetailSerializer(many=True)},
        tags=["Admin"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class OrderAddressListAPIView(ListAPIView):
    """
    GET /api/order-addresses/
    Lists order addresses.
    - Regular customers only see order addresses for orders they placed.
    - Superadmins and users with Admin role can see all order addresses.
    """

    serializer_class = OrderAddressSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="List user order addresses",
        description="Lists order addresses. Regular users only see addresses for orders they placed. Superadmins and Admins can see all order addresses.",
        responses={200: OrderAddressSerializer(many=True)},
        tags=["Order Addresses"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        if (
            user.is_superuser
            or user.groups.filter(name="Admin").exists()
            or (user.is_staff and user.has_perm("orders.view_order"))
        ):
            return OrderAddress.objects.all().select_related("order", "user")
        return OrderAddress.objects.filter(user=user).select_related("order", "user")


class OrderAddressDetailAPIView(RetrieveAPIView):
    """
    GET /api/order-addresses/<id>/
    Retrieves a single order address by ID.
    - Restricted to the user who ordered, superadmins, and users with Admin role.
    - Unauthorized access attempts return 404 (IDOR defense) and record an audit event.
    """

    serializer_class = OrderAddressSerializer
    permission_classes = [IsAuthenticated, CanViewOrderAddressPermission]

    @extend_schema(
        summary="Retrieve order address by ID",
        description="Retrieves a specific order address. Only the user who ordered, superadmin, and users with the Admin role can view this address.",
        responses={
            200: OrderAddressSerializer,
            404: OpenApiResponse(description="Order address not found or unauthorized access attempt."),
        },
        tags=["Order Addresses"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return OrderAddress.objects.all().select_related("order", "user")

    def get_object(self):
        from django.http import Http404

        pk = self.kwargs.get("pk")
        user = self.request.user

        order_address = (
            OrderAddress.objects.filter(pk=pk).select_related("order", "user").first()
        )
        if order_address is None:
            raise Http404("No OrderAddress matches the given query.")

        is_owner = (order_address.user == user) or (
            order_address.order and order_address.order.user == user
        )
        is_admin = (
            user.is_superuser
            or user.groups.filter(name="Admin").exists()
            or (user.is_staff and user.has_perm("orders.view_order"))
        )

        if not (is_owner or is_admin):
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                request=self.request,
                user=user,
                order_id=order_address.order_id,
                description=(
                    f"User '{user.username}' attempted unauthorized access to "
                    f"OrderAddress #{order_address.id} owned by '{order_address.user.username}'"
                ),
            )
            raise Http404("No OrderAddress matches the given query.")

        self.check_object_permissions(self.request, order_address)
        return order_address


class OrderAddressByOrderAPIView(RetrieveAPIView):
    """
    GET /api/orders/<order_id>/address/ (and /addresses/)
    Retrieves the order address associated with a specific Order ID.
    - Restricted to the user who ordered, superadmins, and users with Admin role.
    """

    serializer_class = OrderAddressSerializer
    permission_classes = [IsAuthenticated, CanViewOrderAddressPermission]

    @extend_schema(
        summary="Retrieve order address for an order",
        description="Retrieves the order address associated with the given Order ID. Restricted to the user who placed the order, superadmin, and users with Admin role.",
        responses={
            200: OrderAddressSerializer,
            404: OpenApiResponse(description="Order or order address not found or unauthorized access attempt."),
        },
        tags=["Order Addresses"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def get_object(self):
        from django.http import Http404

        order_id = self.kwargs.get("order_id")
        user = self.request.user

        order = Order.objects.filter(pk=order_id).select_related("user").first()
        if order is None:
            raise Http404("No Order matches the given query.")

        is_owner = order.user == user
        is_admin = (
            user.is_superuser
            or user.groups.filter(name="Admin").exists()
            or (user.is_staff and user.has_perm("orders.view_order"))
        )

        if not (is_owner or is_admin):
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                request=self.request,
                user=user,
                order_id=order.id,
                description=(
                    f"User '{user.username}' attempted unauthorized access to order address for "
                    f"Order #{order.id} owned by '{order.user.username}'"
                ),
            )
            raise Http404("No Order matches the given query.")

        order_address = order.address
        if order_address is None:
            raise Http404("No OrderAddress found for this Order.")

        self.check_object_permissions(self.request, order_address)
        return order_address


class AdminOrderAddressListAPIView(ListAPIView):
    """
    GET /api/admin/order-addresses/
    Administrative endpoint to view all order addresses across all customer orders.
    Restricted to superadmins and users with Admin role / 'orders.view_order'.
    """

    serializer_class = OrderAddressSerializer
    permission_classes = [IsAuthenticated, HasAdminOrderPermission]
    queryset = OrderAddress.objects.all().select_related("order", "user")

    @extend_schema(
        summary="Admin list all customer order addresses",
        description="Administrative endpoint to inspect all customer order addresses across the system. Restricted to staff with Admin role.",
        responses={200: OrderAddressSerializer(many=True)},
        tags=["Admin"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


@extend_schema(exclude=True)
class OrderAddressListAliasView(OrderAddressListAPIView):
    pass


@extend_schema(exclude=True)
class OrderAddressDetailAliasView(OrderAddressDetailAPIView):
    pass


@extend_schema(exclude=True)
class OrderAddressByOrderAliasView(OrderAddressByOrderAPIView):
    pass
