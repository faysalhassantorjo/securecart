"""
AES-256-GCM authenticated encryption service for sensitive data (PII).
"""

import base64
import logging
import os
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)


class DecryptionError(Exception):
    """Raised when decryption or authentication tag verification fails."""
    pass


class AESCipher:
    """AES-256-GCM cipher for authenticated encryption and decryption."""

    def __init__(self, key: Optional[Union[bytes, str]] = None):
        self._key = self._normalize_key(key) if key is not None else self._load_key()
        self._aesgcm = AESGCM(self._key)

    @staticmethod
    def _normalize_key(raw_key: Union[bytes, str]) -> bytes:
        if isinstance(raw_key, str):
            raw_key = raw_key.strip().encode("utf-8")

        if len(raw_key) == 32:
            return raw_key

        for decoder in (bytes.fromhex, base64.b64decode):
            try:
                decoded = decoder(raw_key.decode("ascii"))
                if len(decoded) == 32:
                    return decoded
            except Exception:
                pass

        raise ImproperlyConfigured(
            "AES_SECRET_KEY must resolve to exactly 32 bytes (raw bytes, 64-char hex, or base64)."
        )

    @classmethod
    def _load_key(cls) -> bytes:
        key = getattr(settings, "AES_SECRET_KEY", None) or os.environ.get("AES_SECRET_KEY")
        if not key:
            raise ImproperlyConfigured("AES_SECRET_KEY is not set in settings or environment.")
        return cls._normalize_key(key)

    def encrypt(self, plaintext: Optional[str]) -> str:
        """Encrypts plaintext string using AES-256-GCM."""
        if not plaintext:
            return ""

        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, ciphertext: Optional[str]) -> str:
        """Decrypts AES-256-GCM ciphertext, verifying the authentication tag."""
        if not ciphertext:
            return ""

        try:
            payload = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
            if len(payload) < 28:
                raise ValueError("Payload shorter than 28 bytes (12-byte nonce + 16-byte tag)")
            return self._aesgcm.decrypt(payload[:12], payload[12:], None).decode("utf-8")
        except Exception as e:
            logger.warning("Decryption failed: %s", e)
            raise DecryptionError("Failed to decrypt ciphertext.") from e

    def decrypt_or_mask(self, ciphertext: Optional[str], mask: str = "[DECRYPTION FAILED]") -> str:
        """Decrypts ciphertext or returns fallback mask on failure."""
        try:
            return self.decrypt(ciphertext)
        except DecryptionError:
            return mask


# Singleton cipher instance
_cipher_instance: Optional[AESCipher] = None


def get_cipher() -> AESCipher:
    """Returns a cached AESCipher instance."""
    global _cipher_instance
    if _cipher_instance is None:
        _cipher_instance = AESCipher()
    return _cipher_instance


def encrypt_value(plaintext: Optional[str]) -> str:
    """Convenience helper to encrypt plaintext."""
    return get_cipher().encrypt(plaintext)


def decrypt_value(ciphertext: Optional[str]) -> str:
    """Convenience helper to decrypt ciphertext."""
    return get_cipher().decrypt(ciphertext)
