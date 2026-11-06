# Security Architecture & Cryptography Policy: SecureCart

This document describes the security controls, cryptographic design, key management practices, and known limitations for the **SecureCart** demonstration platform.

---

## 1. Threat Model & Scope

### Protected Assets
- **Personally Identifiable Information (PII)**: Customer phone numbers and email addresses.
- **Order Snapshots**: Historical delivery contact details associated with financial transactions.
- **Data Integrity**: Prevention of database tampering, price manipulation, and stock overselling.
- **Authorization Boundaries**: Protection against Insecure Direct Object References (IDOR/BOLA).

### Adversary Assumptions
- **Compromised Database / Storage Dump**: If an attacker gains read access to the PostgreSQL database or a backup file, customer phone numbers and email addresses remain encrypted at rest and unreadable without the encryption key.
- **Malicious API Clients**: Attackers attempting to modify product prices, inject fake order totals, or tamper with order IDs in API paths.
- **Untrusted Staff**: Non-compliance administrative staff cannot view decrypted customer PII without explicit Django permissions, and all administrative access to decrypted data is permanently audited.

---

## 2. Cryptographic Design: AES-256-GCM

SecureCart implements **Application-Level Field Encryption** using Authenticated Encryption with Associated Data (AEAD).

| Parameter | Specification | Purpose |
|---|---|---|
| **Algorithm** | **AES-256-GCM** | Advanced Encryption Standard in Galois/Counter Mode. |
| **Key Size** | 256 bits (32 bytes) | Maximum cryptographic resistance against brute-force attacks. |
| **Nonce / IV** | 96 bits (12 bytes) | Generated dynamically using `os.urandom(12)` per encryption. Guarantees semantic security. |
| **Authentication Tag** | 128 bits (16 bytes) | Verifies ciphertext integrity and authenticity prior to decryption. |
| **Payload Envelope** | `Base64( Nonce [12B] + Ciphertext [NB] + Tag [16B] )` | Compact, URL-safe database storage format. |

### Semantic Security (Fresh Nonces)
Encrypting the identical phone number or email multiple times produces completely different ciphertexts. This prevents traffic analysis and database-level frequency analysis attacks.

### Tamper Resistance (Fail-Safe Verification)
If a single bit in the ciphertext or authentication tag is modified (e.g. by an attacker with direct SQL access), `cryptography.exceptions.InvalidTag` is raised immediately. Decryption fails safely without returning corrupted plaintext or leaking internal stack traces.

---

## 3. Key Management

### Development & Demo
- The key is supplied via the `AES_SECRET_KEY` environment variable.
- Stored as a 64-character hexadecimal string (32 bytes = 256 bits).
- A `.env.example` file provides a placeholder key. **The `.env` file is git-ignored and never committed.**

### Generating an Encryption Key
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Production Security Recommendations
In a production deployment, environment-variable key storage should be replaced with an enterprise key management solution:
1. **Cloud KMS Integration**: Use AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault.
2. **Envelope Encryption (DEK/KEK)**: Encrypt customer records using a unique Data Encryption Key (DEK), while the Key Encryption Key (KEK) is protected and rotated inside Hardware Security Modules (HSMs).
3. **Key Rotation Strategy**: Support dual-key decryption to re-encrypt existing database records progressively when transitioning keys.

---

## 4. Role-Based Access Control & Decryption Gating

1. **Authentication**: All sensitive endpoints require JSON Web Tokens (JWT) signed using HMAC-SHA256 (`djangorestframework-simplejwt`).
2. **Object-Level Authorization**:
   - `get_queryset()` scopes customer queries strictly to `user=request.user`.
   - Access attempts to other customers' orders return `404 Not Found` (rather than 403) to prevent IDOR resource enumeration.
3. **Permission-Gated Decryption**:
   - Customer owners can view their own decrypted contact information.
   - Administrative users **only** receive decrypted customer PII if they hold the explicit Django permission `orders.view_sensitive_customer_data`.
   - Staff without this permission receive `"[MASKED - INSUFFICIENT PERMISSION]"`.
4. **Audit Logging**:
   - Every administrative access to decrypted customer data triggers an immutable `ADMIN_SENSITIVE_DATA_ACCESS` audit event.
   - Unauthorized IDOR attempts trigger `UNAUTHORIZED_ACCESS_ATTEMPT`.
   - Decryption failures trigger `DECRYPTION_FAILURE`.
   - **Plaintext PII and cryptographic keys are strictly never written to logs.**

---

## 5. Known Limitations & Trade-Offs

- **Exact Searchability**: Because AES-GCM ciphertexts are non-deterministic (randomized nonces), SQL queries like `WHERE encrypted_phone = '...'` or `LIKE '%search%'` cannot be performed directly in PostgreSQL. For production systems requiring customer search by phone/email, a **Blind Index** (HMAC-SHA256 hash using a separate salt/key) or deterministic tokenization should be introduced.
- **Key In-Memory Footprint**: In this demo, the encryption key is held in Python memory by `AESCipher`. In high-assurance environments, KMS RPC calls or ephemeral session memory should be utilized.
