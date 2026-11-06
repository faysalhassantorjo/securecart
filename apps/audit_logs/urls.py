"""
apps/audit_logs/urls.py
=======================
URL routing for security event auditing.
"""

from django.urls import path
from apps.audit_logs.views import SecurityEventListAPIView

urlpatterns = [
    path("security-events/", SecurityEventListAPIView.as_view(), name="security-events-list"),
]
