"""
apps/core/exceptions.py
=======================
Custom DRF exception handler providing consistent and safe API error responses.
Ensures internal cryptographic errors do not leak stack traces or secret data.
"""

import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from apps.core.encryption import DecryptionError
from apps.core.audit import record_security_event

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler for Django REST Framework.
    """
    request = context.get("request")

    # Handle decryption failures safely
    if isinstance(exc, DecryptionError):
        logger.error(f"DecryptionError caught in API view: {exc}")
        record_security_event(
            event_type="DECRYPTION_FAILURE",
            request=request,
            description="Decryption failure: tampered ciphertext or key mismatch detected",
        )
        return Response(
            {
                "error": "Decryption Error",
                "detail": "Failed to decrypt secure data. The record may have been tampered with or the encryption key is invalid.",
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Call REST framework's default exception handler first to get the standard error response.
    response = exception_handler(exc, context)

    if response is not None:
        # Standardize error envelope
        if isinstance(response.data, dict) and "detail" in response.data:
            formatted_data = {"error": response.status_text, "detail": response.data["detail"]}
            response.data = formatted_data
        elif isinstance(response.data, list):
            response.data = {"error": "Validation Error", "detail": response.data}
        elif isinstance(response.data, dict):
            response.data = {"error": "Validation Error", "details": response.data}

    return response
