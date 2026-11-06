"""
apps/core/encryption.py
=======================
Reusable AES-256-GCM authenticated encryption service.
Provides application-level encryption for sensitive PII (phone number, email).

Design & Security Guarantees:
- Algorithm: AES-256 in Galois/Counter Mode (GCM).
- Authenticated Encryption: Every ciphertext includes an authentication tag (128-bit)
  that guarantees both confidentiality and integrity/authenticity.
- Nonce / IV: 96-bit (12-byte) unique cryptographically secure random nonce generated
  via os.urandom(12) per encryption.
- Key: 256-bit (32 bytes) loaded strictly from environment/settings.
- Tamper Resistance: Any bit-flip in ciphertext or tag triggers InvalidTag,
  which is converted into a safe DecryptionError without leaking stack traces or keys.
- Logging: Plaintext secrets and cryptographic keys are strictly never logged.
"""

import os
import base64
import logging
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)


class DecryptionError(Exception):
    """Raised when decryption fails due to corrupted data, tampered tag, or key mismatch."""
    pass


class AESCipher:
    """
    AES-256-GCM Cipher wrapper for authenticated encryption and decryption.
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initializes the cipher with a 256-bit (32-byte) key.
        If no key is provided, loads from Django settings or environment.
        """
        if key is None:
            self._key = self._load_key()
        else:
            self._key = self._normalize_key(key)

        self._aesgcm = AESGCM(self._key)

    @staticmethod
    def _normalize_key(raw_key: any) -> bytes:
        """
        Normalizes hex or base64 string or bytes to exactly 32 bytes (256 bits).
        """
        if isinstance(raw_key, bytes):
            if len(raw_key) == 32:
                return raw_key
            try:
                # Try hex decode
                decoded = bytes.fromhex(raw_key.decode("ascii"))
                if len(decoded) == 32:
                    return decoded
            except Exception:
                pass
            try:
                decoded = base64.b64decode(raw_key)
                if len(decoded) == 32:
                    return decoded
            except Exception:
                pass

        if isinstance(raw_key, str):
            raw_key_str = raw_key.strip()
            # If 64 hex characters (32 bytes * 2 hex chars)
            if len(raw_key_str) == 64:
                try:
                    decoded = bytes.fromhex(raw_key_str)
                    if len(decoded) == 32:
                        return decoded
                except ValueError:
                    pass

            # Try base64
            try:
                decoded = base64.b64decode(raw_key_str)
                if len(decoded) == 32:
                    return decoded
            except Exception:
                pass

            # Raw string of 32 chars
            if len(raw_key_str.encode("utf-8")) == 32:
                return raw_key_str.encode("utf-8")

        raise ImproperlyConfigured(
            "AES_SECRET_KEY must be exactly 32 bytes (256 bits). "
            "Provide a 64-character hex string or 32-byte base64 string."
        )

    @classmethod
    def _load_key(cls) -> bytes:
        """
        Loads the AES secret key from Django settings or environment variable.
        """
        key_str = getattr(settings, "AES_SECRET_KEY", None) or os.environ.get("AES_SECRET_KEY")
        if not key_str:
            raise ImproperlyConfigured(
                "AES_SECRET_KEY is not set in settings or environment. "
                "Application cannot run without an encryption key."
            )
        return cls._normalize_key(key_str)

    def encrypt(self, plaintext: Optional[str]) -> str:
        """
        Encrypts plaintext string using AES-256-GCM.
        Returns a URL-safe Base64 encoded string containing:
        [12 bytes Nonce] + [Ciphertext] + [16 bytes Auth Tag]
        """
        if plaintext is None or plaintext == "":
            return ""

        plaintext_bytes = plaintext.encode("utf-8")
        # 12-byte nonce (96 bits recommended for AES-GCM)
        nonce = os.urandom(12)
        # AESGCM.encrypt appends the 16-byte authentication tag to the ciphertext
        ciphertext_with_tag = self._aesgcm.encrypt(nonce, plaintext_bytes, None)
        # Combine nonce and ciphertext+tag
        payload = nonce + ciphertext_with_tag
        return base64.urlsafe_b64encode(payload).decode("ascii")

    def decrypt(self, ciphertext: Optional[str]) -> str:
        """
        Decrypts an AES-256-GCM encrypted payload.
        Verifies the authentication tag before returning plaintext.
        Raises DecryptionError on tampering or wrong key.
        """
        if ciphertext is None or ciphertext == "":
            return ""

        try:
            raw_payload = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
        except Exception as e:
            logger.warning("Decryption failed: Malformed base64 input.")
            raise DecryptionError("Malformed ciphertext payload.") from e

        # 12 bytes nonce + 16 bytes tag = at least 28 bytes
        if len(raw_payload) < 28:
            logger.warning("Decryption failed: Payload shorter than minimum required length.")
            raise DecryptionError("Ciphertext payload is truncated or invalid.")

        nonce = raw_payload[:12]
        data_with_tag = raw_payload[12:]

        try:
            plaintext_bytes = self._aesgcm.decrypt(nonce, data_with_tag, None)
            return plaintext_bytes.decode("utf-8")
        except InvalidTag as e:
            logger.warning("Decryption failed: InvalidTag (ciphertext tampered or incorrect key).")
            raise DecryptionError("Decryption authentication failed: data tampered or invalid key.") from e
        except Exception as e:
            logger.warning("Decryption failed: Unexpected decoding error.")
            raise DecryptionError("Failed to decrypt ciphertext.") from e

    def decrypt_or_mask(self, ciphertext: Optional[str], mask: str = "[DECRYPTION FAILED]") -> str:
        """
        Decrypts ciphertext, returning a safe mask string if decryption fails
        instead of propagating an unhandled exception.
        """
        try:
            return self.decrypt(ciphertext)
        except DecryptionError:
            return mask


# Singleton instance helper
_cipher_instance: Optional[AESCipher] = None


def get_cipher() -> AESCipher:
    """
    Returns a cached instance of AESCipher.
    """
    global _cipher_instance
    if _cipher_instance is None:
        _cipher_instance = AESCipher()
    return _cipher_instance


def encrypt_value(plaintext: Optional[str]) -> str:
    """Convenience function to encrypt plaintext."""
    return get_cipher().encrypt(plaintext)


def decrypt_value(ciphertext: Optional[str]) -> str:
    """Convenience function to decrypt ciphertext."""
    return get_cipher().decrypt(ciphertext)
