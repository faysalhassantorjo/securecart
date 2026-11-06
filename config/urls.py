"""
URL configuration for SecureCart project.
"""

from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from drf_spectacular.utils import extend_schema, extend_schema_view
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)
from apps.accounts.views import (
    UserRegistrationAPIView,
    UserRoleAssignmentAPIView,
    RoleListAPIView,
    UserListWithRolesAPIView,
)


@extend_schema_view(
    post=extend_schema(
        summary="Obtain JWT token pair (login)",
        description="Authenticates customer credentials (username & password) and returns an access and refresh JWT token pair.",
        tags=["Auth"],
    )
)
class DecoratedTokenObtainPairView(TokenObtainPairView):
    pass


@extend_schema_view(
    post=extend_schema(
        summary="Refresh JWT access token",
        description="Takes a valid refresh token and returns a newly minted access token without re-entering credentials.",
        tags=["Auth"],
    )
)
class DecoratedTokenRefreshView(TokenRefreshView):
    pass


@extend_schema(exclude=True)
class RegistrationAliasView(UserRegistrationAPIView):
    pass


urlpatterns = [
    path("admin/", admin.site.urls),

    # Authentication & Registration Endpoints
    path("api/auth/register/", UserRegistrationAPIView.as_view(), name="user_register"),
    path("api/auth/token/", DecoratedTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/auth/token/refresh/", DecoratedTokenRefreshView.as_view(), name="token_refresh"),
    path("api/register/", RegistrationAliasView.as_view(), name="user_register_alias"),

    # Application Domain Endpoints
    path("api/products/", include("apps.products.urls")),
    path("api/addresses/", include("apps.accounts.urls")),
    path("api/", include("apps.orders.urls")),
    path("api/admin/", include("apps.audit_logs.urls")),

    # Role-Based Access Control (RBAC) Management
    path("api/admin/roles/", RoleListAPIView.as_view(), name="admin_roles_list"),
    path("api/admin/users/", UserListWithRolesAPIView.as_view(), name="admin_users_list"),
    path("api/admin/users/<int:user_id>/role/", UserRoleAssignmentAPIView.as_view(), name="admin_user_role"),

    # OpenAPI / Swagger Documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/swagger/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui-alias"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui-root"),
    path("swagger/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui-root-alias"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc-root"),
]
