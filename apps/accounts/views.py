"""
apps/accounts/views.py
======================
Generic API Views for customer address management and user registration.
Enforces object-level ownership and prevents IDOR.
"""

from django.contrib.auth.models import User, Group
from django.db import transaction
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse

from apps.accounts.models import Address
from apps.accounts.serializers import (
    AddressSerializer,
    UserRegistrationSerializer,
    UserRegistrationResponseSerializer,
    UserSummarySerializer,
    UserRoleAssignmentSerializer,
    UserRoleResponseSerializer,
    UserRoleDetailSerializer,
    RoleBoundarySerializer,
)
from apps.core.permissions import (
    IsOwnerOrAdminWithPermission,
    get_user_role,
    IsAdminOrSuperadmin,
)
from apps.core.audit import record_security_event


class UserRegistrationAPIView(APIView):
    """
    POST /api/auth/register/
    Public user registration endpoint.
    - Validates username, email, and password complexity.
    - Ensures password confirmation matches.
    - Prevents privilege escalation and assigns user to the 'Customer' group.
    - Emits a USER_REGISTRATION audit event.
    - Issues JWT token pair (access + refresh) for immediate authenticated access.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        summary="Register a new customer account",
        description=(
            "Creates a new customer account. Enforces password security rules, assigns the default 'Customer' "
            "role group, records an audit log entry, and returns JWT tokens."
        ),
        request=UserRegistrationSerializer,
        responses={
            201: UserRegistrationResponseSerializer,
            400: OpenApiResponse(description="Validation error: invalid credentials, username/email conflict, or password mismatch."),
        },
        tags=["Auth"],
    )
    def post(self, request, *args, **kwargs):
        serializer = UserRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()

        # Generate JWT tokens for immediate access
        refresh = RefreshToken.for_user(user)
        tokens = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }

        # Record security event
        record_security_event(
            event_type="USER_REGISTRATION",
            request=request,
            user=user,
            description=f"New customer account '{user.username}' registered successfully.",
        )

        response_data = {
            "message": "User registered successfully.",
            "user": UserSummarySerializer(user).data,
            "tokens": tokens,
        }
        return Response(response_data, status=status.HTTP_201_CREATED)


@extend_schema_view(
    get=extend_schema(
        summary="List customer saved addresses",
        description="Lists saved delivery addresses. Regular customers only see their own addresses; staff holding 'accounts.view_address' can list all.",
        tags=["Addresses"],
    ),
    post=extend_schema(
        summary="Create a new saved address",
        description="Adds a new delivery address to the customer address book. Phone number and email are encrypted at rest with AES-256-GCM.",
        tags=["Addresses"],
    ),
)
class AddressListCreateAPIView(ListCreateAPIView):
    """
    GET /api/addresses/  -> List authenticated user's saved addresses
    POST /api/addresses/ -> Create a new address for authenticated user
    """

    serializer_class = AddressSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Admins holding 'accounts.view_address' can list all addresses
        if user.is_staff and user.has_perm("accounts.view_address"):
            return Address.objects.all().select_related("user")
        # Regular customers can only access their own addresses
        return Address.objects.filter(user=user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


@extend_schema_view(
    get=extend_schema(
        summary="Retrieve saved address by ID",
        description="Retrieves a saved address. Contact details (phone/email) are decrypted only for the address owner or authorized staff.",
        tags=["Addresses"],
    ),
    put=extend_schema(
        summary="Update saved address (full)",
        description="Updates all fields of an existing saved address belonging to the authenticated customer.",
        tags=["Addresses"],
    ),
    patch=extend_schema(
        summary="Update saved address (partial)",
        description="Partially updates fields of an existing saved address belonging to the authenticated customer.",
        tags=["Addresses"],
    ),
    delete=extend_schema(
        summary="Delete saved address",
        description="Permanently deletes a saved address belonging to the authenticated customer.",
        tags=["Addresses"],
    ),
)
class AddressDetailAPIView(RetrieveUpdateDestroyAPIView):
    """
    GET /api/addresses/<id>/    -> Retrieve owned address
    PUT/PATCH /api/addresses/<id>/ -> Update owned address
    DELETE /api/addresses/<id>/ -> Delete owned address
    """

    serializer_class = AddressSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdminWithPermission]

    def get_queryset(self):
        return Address.objects.all().select_related("user")

    def get_object(self):
        from django.http import Http404

        pk = self.kwargs.get("pk")
        user = self.request.user

        address = Address.objects.filter(pk=pk).select_related("user").first()
        if address is None:
            raise Http404("No Address matches the given query.")

        is_owner = address.user == user
        is_authorized_staff = user.is_staff and user.has_perm("accounts.view_address")

        if not (is_owner or is_authorized_staff):
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                request=self.request,
                user=user,
                description=f"User '{user.username}' attempted unauthorized access to Address #{address.id} owned by '{address.user.username}'",
            )
            raise Http404("No Address matches the given query.")

        self.check_object_permissions(self.request, address)
        return address


class UserRoleAssignmentAPIView(APIView):
    """
    POST/PUT /api/admin/users/<id>/role/
    GET /api/admin/users/<id>/role/
    Role-Based Access Control (RBAC) assignment endpoint.
    Permission boundaries enforced:
    - CUSTOMER: Default assigned automatically on registration. Can be assigned by Superadmin or ADMIN.
    - MODERATOR: Only system superadmin or ADMIN can assign this role.
    - ADMIN: Only system superadmin can assign this role.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Assign role to user (RBAC)",
        description=(
            "Assigns a user to a specific role. Enforces hierarchical role boundary rules:\n"
            "- **CUSTOMER**: Default on registration; can be assigned by Superadmin or ADMIN.\n"
            "- **MODERATOR**: Only system superadmin or ADMIN can assign this role.\n"
            "- **ADMIN**: Only system superadmin can assign this role (regular Admins cannot elevate to Admin).\n"
            "Records immutable audit logs on success and unauthorized attempts."
        ),
        request=UserRoleAssignmentSerializer,
        responses={
            200: UserRoleResponseSerializer,
            400: OpenApiResponse(description="Invalid role provided."),
            403: OpenApiResponse(description="Permission denied. Role hierarchy violation."),
            404: OpenApiResponse(description="Target user not found."),
        },
        tags=["Admin"],
    )
    def post(self, request, user_id):
        caller = request.user
        is_admin_or_super = caller.is_superuser or caller.groups.filter(name="Admin").exists()

        if not is_admin_or_super:
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                request=request,
                user=caller,
                description=f"User '{caller.username}' denied access to role management endpoint.",
            )
            return Response(
                {"detail": "Only system superadmin or Admin can manage user roles."},
                status=status.HTTP_403_FORBIDDEN,
            )

        target_user = User.objects.filter(pk=user_id).first()
        if not target_user:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserRoleAssignmentSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        desired_role = serializer.validated_data["role"].upper()

        # Rule 1: Cannot change the role of a system superadmin unless the caller is a superadmin
        if target_user.is_superuser and not caller.is_superuser:
            record_security_event(
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                request=request,
                user=caller,
                description=f"Admin '{caller.username}' attempted to modify system superadmin '{target_user.username}'.",
            )
            return Response(
                {"detail": "Cannot modify role of a system superadmin."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Rule 2: ADMIN role can ONLY be assigned by system superadmin
        if desired_role == "ADMIN":
            if not caller.is_superuser:
                record_security_event(
                    event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                    request=request,
                    user=caller,
                    description=(
                        f"Admin '{caller.username}' attempted to promote user '{target_user.username}' "
                        f"to ADMIN without superadmin privileges."
                    ),
                )
                return Response(
                    {"detail": "Only system superadmin can assign the ADMIN role."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        # Rule 3: MODERATOR and CUSTOMER can be assigned by Superadmin or ADMIN
        elif desired_role in ["MODERATOR", "CUSTOMER"]:
            if not is_admin_or_super:
                return Response(
                    {"detail": "Only system superadmin or Admin can assign this role."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        # Perform atomic role update
        with transaction.atomic():
            previous_role = get_user_role(target_user)

            # Clear current security role groups
            role_groups = Group.objects.filter(name__in=["Customer", "Moderator", "Admin"])
            target_user.groups.remove(*role_groups)

            if desired_role == "ADMIN":
                admin_group, _ = Group.objects.get_or_create(name="Admin")
                target_user.groups.add(admin_group)
                target_user.is_staff = True
                target_user.save(update_fields=["is_staff"])

            elif desired_role == "MODERATOR":
                mod_group, _ = Group.objects.get_or_create(name="Moderator")
                target_user.groups.add(mod_group)
                target_user.is_staff = False
                target_user.is_superuser = False
                target_user.save(update_fields=["is_staff", "is_superuser"])

            elif desired_role == "CUSTOMER":
                cust_group, _ = Group.objects.get_or_create(name="Customer")
                target_user.groups.add(cust_group)
                target_user.is_staff = False
                target_user.is_superuser = False
                target_user.save(update_fields=["is_staff", "is_superuser"])

        record_security_event(
            event_type="ROLE_ASSIGNMENT_SUCCESS",
            request=request,
            user=caller,
            description=(
                f"User '{target_user.username}' role changed from {previous_role} "
                f"to {desired_role} by '{caller.username}'."
            ),
        )

        return Response(
            {
                "message": f"User '{target_user.username}' role successfully updated to {desired_role}.",
                "user_id": target_user.id,
                "username": target_user.username,
                "role": desired_role,
                "previous_role": previous_role,
            },
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        summary="Update role of user (PUT alias)",
        description="Idempotent role assignment alias.",
        request=UserRoleAssignmentSerializer,
        responses={200: UserRoleResponseSerializer},
        tags=["Admin"],
    )
    def put(self, request, user_id):
        return self.post(request, user_id)

    @extend_schema(
        summary="Retrieve user role and permissions",
        description="Returns the primary role, group memberships, and effective permissions for a user.",
        responses={
            200: UserRoleDetailSerializer,
            403: OpenApiResponse(description="Permission denied."),
            404: OpenApiResponse(description="Target user not found."),
        },
        tags=["Admin"],
    )
    def get(self, request, user_id):
        caller = request.user
        is_admin_or_super = caller.is_superuser or caller.groups.filter(name="Admin").exists()

        if not is_admin_or_super:
            return Response(
                {"detail": "Only system superadmin or Admin can inspect user roles."},
                status=status.HTTP_403_FORBIDDEN,
            )

        target_user = User.objects.filter(pk=user_id).prefetch_related("groups").first()
        if not target_user:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        role = get_user_role(target_user)
        group_names = list(target_user.groups.values_list("name", flat=True))
        permissions_list = list(target_user.get_all_permissions())

        return Response(
            {
                "user_id": target_user.id,
                "username": target_user.username,
                "email": target_user.email,
                "role": role,
                "is_staff": target_user.is_staff,
                "is_superuser": target_user.is_superuser,
                "groups": group_names,
                "permissions": permissions_list,
            },
            status=status.HTTP_200_OK,
        )


class RoleListAPIView(APIView):
    """
    GET /api/admin/roles/
    Public/Documented view returning the system's 3 roles, who can assign them,
    and their exact permission boundaries.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        summary="List system roles & permission boundaries",
        description=(
            "Returns official specifications of the 3 system roles:\n"
            "1. **CUSTOMER**: Default upon registration. Can create/view own orders and addresses. Cannot create/modify/delete products.\n"
            "2. **MODERATOR**: Assigned by Superadmin or ADMIN. Can create and update products, but CANNOT delete products.\n"
            "3. **ADMIN**: Assigned ONLY by system superadmin. Full access to catalog (including product deletion), orders, decrypted PII, and audit logs."
        ),
        responses={200: RoleBoundarySerializer(many=True)},
        tags=["Admin"],
    )
    def get(self, request):
        roles_data = [
            {
                "role": "CUSTOMER",
                "title": "Registered Customer",
                "assigned_by": "System (automatically created upon registration) or Superadmin/Admin",
                "description": (
                    "Regular shopper account. Can browse products, manage own saved addresses, and create/view own orders. "
                    "Cannot create, modify, or delete products. Cannot access administrative endpoints."
                ),
                "can_browse_products": True,
                "can_create_products": False,
                "can_update_products": False,
                "can_delete_products": False,
                "can_create_orders": True,
                "can_create_addresses": True,
                "can_view_all_orders": False,
                "can_view_all_order_addresses": False,
                "can_view_audit_logs": False,
                "can_assign_moderator_role": False,
                "can_assign_admin_role": False,
            },
            {
                "role": "MODERATOR",
                "title": "Catalog Moderator",
                "assigned_by": "System Superadmin or ADMIN",
                "description": (
                    "Product catalog manager. Can browse, create, and update product catalog objects. "
                    "CANNOT delete products. Cannot view cross-customer orders or audit logs."
                ),
                "can_browse_products": True,
                "can_create_products": True,
                "can_update_products": True,
                "can_delete_products": False,
                "can_create_orders": True,
                "can_create_addresses": True,
                "can_view_all_orders": False,
                "can_view_all_order_addresses": False,
                "can_view_audit_logs": False,
                "can_assign_moderator_role": False,
                "can_assign_admin_role": False,
            },
            {
                "role": "ADMIN",
                "title": "System Administrator",
                "assigned_by": "System Superadmin ONLY",
                "description": (
                    "Full administrative privilege. Can manage products (including deletion), view all customer orders, "
                    "inspect decrypted customer PII, audit logs, and assign MODERATOR and CUSTOMER roles."
                ),
                "can_browse_products": True,
                "can_create_products": True,
                "can_update_products": True,
                "can_delete_products": True,
                "can_create_orders": True,
                "can_create_addresses": True,
                "can_view_all_orders": True,
                "can_view_all_order_addresses": True,
                "can_view_audit_logs": True,
                "can_assign_moderator_role": True,
                "can_assign_admin_role": False,  # Only superadmin can assign Admin
            },
        ]
        return Response(roles_data, status=status.HTTP_200_OK)


class UserListWithRolesAPIView(APIView):
    """
    GET /api/admin/users/
    Administrative endpoint to list all registered users along with their primary roles.
    Restricted to Admins and Superadmins.
    """

    permission_classes = [IsAuthenticated, IsAdminOrSuperadmin]

    @extend_schema(
        summary="Admin list all users with roles",
        description="Administrative directory of registered accounts with their primary RBAC role.",
        responses={200: UserSummarySerializer(many=True)},
        tags=["Admin"],
    )
    def get(self, request):
        users = User.objects.all().prefetch_related("groups").order_by("id")
        return Response(UserSummarySerializer(users, many=True).data, status=status.HTTP_200_OK)
