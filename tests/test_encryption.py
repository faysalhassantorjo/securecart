"""
tests/test_encryption.py
========================
Unit tests for AES-256-GCM authenticated encryption and decryption.
Verifies semantic security, tamper detection, and safe failure modes.
"""

import os
import base64
from django.test import TestCase
from apps.core.encryption import AESCipher, DecryptionError, encrypt_value, decrypt_value


class EncryptionServiceTests(TestCase):
    def setUp(self):
        # 32 bytes (256-bit) test key
        self.test_key = os.urandom(32)
        self.cipher = AESCipher(key=self.test_key)

    def test_encryption_and_decryption_roundtrip(self):
        """Plaintext should encrypt and decrypt cleanly to original string."""
        plaintext = "+1-555-867-5309"
        ciphertext = self.cipher.encrypt(plaintext)

        self.assertNotEqual(ciphertext, plaintext)
        decrypted = self.cipher.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_semantic_security_fresh_nonce(self):
        """Encrypting the same plaintext twice must produce different ciphertexts."""
        plaintext = "alice@example.com"
        c1 = self.cipher.encrypt(plaintext)
        c2 = self.cipher.encrypt(plaintext)

        self.assertNotEqual(c1, c2, "Ciphertexts must be non-deterministic due to random nonces")
        self.assertEqual(self.cipher.decrypt(c1), plaintext)
        self.assertEqual(self.cipher.decrypt(c2), plaintext)

    def test_empty_string_handling(self):
        """Empty or None input should return empty string without error."""
        self.assertEqual(self.cipher.encrypt(""), "")
        self.assertEqual(self.cipher.encrypt(None), "")
        self.assertEqual(self.cipher.decrypt(""), "")
        self.assertEqual(self.cipher.decrypt(None), "")

    def test_tamper_detection_raises_decryption_error(self):
        """Tampering with a single byte in ciphertext must fail authenticated tag check."""
        plaintext = "TopSecretCustomerData"
        ciphertext = self.cipher.encrypt(plaintext)

        # Decode base64, flip one bit in ciphertext, re-encode
        raw = bytearray(base64.urlsafe_b64decode(ciphertext.encode("ascii")))
        # Flip a bit in the data portion (after 12-byte nonce)
        raw[15] ^= 0x01
        tampered_ciphertext = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")

        with self.assertRaises(DecryptionError):
            self.cipher.decrypt(tampered_ciphertext)

    def test_tamper_detection_in_auth_tag(self):
        """Tampering with authentication tag at end of payload must fail safely."""
        plaintext = "+1-800-SECURE"
        ciphertext = self.cipher.encrypt(plaintext)

        raw = bytearray(base64.urlsafe_b64decode(ciphertext.encode("ascii")))
        # Flip bit in the last byte (auth tag)
        raw[-1] ^= 0x01
        tampered_ciphertext = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")

        with self.assertRaises(DecryptionError):
            self.cipher.decrypt(tampered_ciphertext)

    def test_invalid_key_fails_decryption(self):
        """Attempting to decrypt with a different 256-bit key must fail authentication."""
        plaintext = "sensitive-email@domain.com"
        ciphertext = self.cipher.encrypt(plaintext)

        different_key = os.urandom(32)
        different_cipher = AESCipher(key=different_key)

        with self.assertRaises(DecryptionError):
            different_cipher.decrypt(ciphertext)

    def test_truncated_payload_fails_safely(self):
        """Payload shorter than nonce + auth tag (28 bytes) must fail safely."""
        too_short_bytes = os.urandom(20)
        short_payload = base64.urlsafe_b64encode(too_short_bytes).decode("ascii")

        with self.assertRaises(DecryptionError):
            self.cipher.decrypt(short_payload)

    def test_convenience_functions(self):
        """Global convenience functions encrypt_value and decrypt_value work with settings key."""
        text = "Hello SecureCart"
        enc = encrypt_value(text)
        self.assertNotEqual(enc, text)
        dec = decrypt_value(enc)
        self.assertEqual(dec, text)
