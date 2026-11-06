"""
apps/core/permissions.py
========================
DRF Permission classes enforcing Role-Based Access Control (RBAC)
and Object-Level Access Control (OLAC) to prevent BOLA / IDOR.
"""

from rest_framework import permissions
from apps.core.audit import record_security_event


class IsOwner(permissions.BasePermission):
    """
    Object-level permission allowing only the owner of the object to access it.
    Assumes the model instance has a `user` attribute.
    Records an unauthorized access audit event upon violation.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        is_owner = hasattr(obj, "user") and obj.user == request.user
        if not is_owner:
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                request=request,
                order_id=obj.id if hasattr(obj, "id") and "Order" in type(obj).__name__ else None,
                description=f"User '{request.user.username}' attempted unauthorized access to {type(obj).__name__} id={getattr(obj, 'id', None)}",
            )
        return is_owner


class IsOwnerOrAdminWithPermission(permissions.BasePermission):
    """
    Allows access if the user is the owner, OR if the user is staff/admin
    holding the required Django permission.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # 1. Check if user is owner
        if hasattr(obj, "user") and obj.user == request.user:
            return True

        # 2. Check if admin has explicit permission to view order
        if request.user.is_staff and request.user.has_perm("orders.view_order"):
            return True

        # Log unauthorized attempt
        record_security_event(
            event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
            request=request,
            order_id=getattr(obj, "id", None) if "Order" in type(obj).__name__ else None,
            description=f"User '{request.user.username}' denied access to {type(obj).__name__} id={getattr(obj, 'id', None)}",
        )
        return False


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Role-based permission for product catalog management:
    - Safe methods (GET, HEAD, OPTIONS): Authenticated users (Customer, Moderator, Admin, Superadmin).
    - POST (create product): Admin, Superadmin, and Moderator.
    - PUT, PATCH (update product): Admin, Superadmin, and Moderator.
    - DELETE (delete product): ONLY Admin and Superadmin. (Moderators CANNOT delete).
    - Customers cannot create, modify, or delete products.
    """

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False

        if request.method in permissions.SAFE_METHODS:
            return True

        user = request.user
        if user.is_superuser:
            return True

        is_admin = (
            user.groups.filter(name="Admin").exists()
            or (user.is_staff and user.has_perm("products.delete_product"))
        )
        is_moderator = (
            user.groups.filter(name="Moderator").exists()
            or user.has_perm("products.add_product")
        )

        if request.method == "POST":
            return is_admin or is_moderator

        if request.method in ["PUT", "PATCH"]:
            return is_admin or is_moderator

        if request.method == "DELETE":
            # Moderator CANNOT delete; only Admin and Superadmin can delete
            return is_admin

        return False


class IsSuperadmin(permissions.BasePermission):
    """Allows access strictly to system superusers (is_superuser=True)."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)


class IsAdminOrSuperadmin(permissions.BasePermission):
    """Allows access to users in the Admin group or system superusers."""

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and (
                request.user.is_superuser
                or request.user.groups.filter(name="Admin").exists()
                or (request.user.is_staff and request.user.has_perm("orders.view_order"))
            )
        )


def get_user_role(user) -> str:
    """Returns the primary role of a user: SUPERADMIN, ADMIN, MODERATOR, or CUSTOMER."""
    if not user or not user.is_authenticated:
        return "ANONYMOUS"
    if user.is_superuser:
        return "SUPERADMIN"
    if user.groups.filter(name="Admin").exists():
        return "ADMIN"
    if user.groups.filter(name="Moderator").exists():
        return "MODERATOR"
    return "CUSTOMER"


class HasAdminOrderPermission(permissions.BasePermission):
    """
    Allows access only to staff members holding 'orders.view_order'.
    """

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_staff
            and request.user.has_perm("orders.view_order")
        )


class HasSecurityAuditPermission(permissions.BasePermission):
    """
    Allows access only to staff members holding 'audit_logs.view_auditlog'.
    """

    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_staff
            and request.user.has_perm("audit_logs.view_auditlog")
        )


class CanViewOrderAddressPermission(permissions.BasePermission):
    """
    Object-level permission allowing access to order addresses only for:
    - The customer who placed the order
    - Superadmin (is_superuser=True)
    - User with the Admin role (in 'Admin' group or staff with orders.view_order)
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        user = request.user
        if not (user and user.is_authenticated):
            return False

        # 1. Superadmin has full access
        if user.is_superuser:
            return True

        # 2. User with Admin role has access
        if user.groups.filter(name="Admin").exists() or (user.is_staff and user.has_perm("orders.view_order")):
            return True

        # 3. Customer who placed the order
        order_user = getattr(obj, "user", None)
        if order_user is None and hasattr(obj, "order"):
            order_user = getattr(obj.order, "user", None)

        if order_user == user:
            return True

        # Unauthorized access attempt
        order_id = getattr(obj, "order_id", None) or getattr(getattr(obj, "order", None), "id", None)
        record_security_event(
            event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
            request=request,
            user=user,
            order_id=order_id,
            description=f"User '{user.username}' denied access to OrderAddress #{getattr(obj, 'id', None)}",
        )
        return False


def can_view_sensitive_data(user, obj) -> bool:
    """
    Helper function used inside serializers to determine whether
    sensitive fields (phone, email, street address) should be decrypted.

    Returns True if:
    - User is superadmin, OR
    - User has the 'Admin' role group, OR
    - User is the owner of the object (or owner of the linked order), OR
    - User is staff/admin and holds explicit permission 'orders.view_sensitive_customer_data'.
    """
    if not (user and user.is_authenticated):
        return False

    if user.is_superuser:
        return True

    if user.groups.filter(name="Admin").exists():
        return True

    if hasattr(obj, "user") and obj.user == user:
        return True

    if hasattr(obj, "order") and getattr(obj.order, "user", None) == user:
        return True

    if user.is_staff and user.has_perm("orders.view_sensitive_customer_data"):
        return True

    return False
