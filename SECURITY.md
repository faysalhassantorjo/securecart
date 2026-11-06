# Security Architecture & Cryptography Policy: SecureCart

This document outlines the cryptographic specifications, key management practices, authorization boundaries, and security controls implemented in **SecureCart**.

---

## 1. Threat Model & Protected Assets

SecureCart is designed to protect customer data under the following threat assumptions:

- **Compromised Storage / Database Dump**: If an adversary gains unauthorized read access to the database or backups, customer Personally Identifiable Information (PII) remains encrypted at rest and unreadable without the secret key.
- **Malicious API Clients / Tampering**: Prevention of client-side price modification, quantity manipulation, and bit-level ciphertext alteration.
- **Insecure Direct Object References (IDOR/BOLA)**: Strict query scoping prevents unauthorized users from inspecting or enumerating other users' orders and addresses.
- **Untrusted Staff / Internal Privilege Abuse**: Administrative users cannot view decrypted customer PII without explicit permissions, and all administrative reads are audited.

### Protected Data Fields
- **Customer Addresses**: `encrypted_phone`, `encrypted_email`, and order street address snapshots.
- **Orders**: `encrypted_phone` and `encrypted_email` captured as immutable snapshots during checkout.

---

## 2. Cryptographic Design (AES-256-GCM)

SecureCart uses **Application-Level Field Encryption** via Authenticated Encryption with Associated Data (AEAD).

| Parameter | Specification | Purpose |
|---|---|---|
| **Cipher** | **AES-256-GCM** | Authenticated symmetric encryption combining confidentiality and integrity. |
| **Key Size** | 256 bits (32 bytes) | High-strength resistance against brute-force attacks. |
| **Nonce / IV** | 96 bits (12 bytes) | Generated dynamically via `os.urandom(12)` per encryption. Guarantees semantic security. |
| **Auth Tag** | 128 bits (16 bytes) | Verifies ciphertext integrity and authenticity prior to decryption. |
| **Payload Envelope** | `Base64( Nonce [12B] + Ciphertext [NB] + Tag [16B] )` | Compact, URL-safe string representation for database storage. |

### Security Guarantees
- **Semantic Security**: Encrypting identical plaintext multiple times yields completely distinct ciphertexts due to fresh nonces, mitigating frequency analysis.
- **Tamper Resistance**: If any bit of the ciphertext or tag is modified, decryption immediately raises `InvalidTag` and safely outputs `[DECRYPTION FAILED]` without leaking plaintext or internal stack traces.

---

## 3. Key Management

### Key Generation & Configuration
The encryption key is supplied via the `AES_SECRET_KEY` environment variable as a 64-character hex string (32 bytes):

```bash
# Generate a secure 256-bit encryption key
python -c "import secrets; print(secrets.token_hex(32))"
```

> **Warning:** Never commit `.env` or hardcode cryptographic keys into source control.

### Production Recommendations
- **KMS / HSM**: Use a hardware-backed key management service (AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault).
- **Envelope Encryption**: Implement a Data Encryption Key (DEK) / Key Encryption Key (KEK) hierarchy.
- **Key Rotation**: Implement key version identifiers within payload envelopes to support dual-key decryption and gradual re-encryption during key rotation.

---

## 4. Authorization & Decryption Gating

Access to sensitive decrypted fields is gated by strict role and object-level permissions:

```
[Incoming Request]
        │
        ▼
Is User Authenticated? ──(No)──► 401 Unauthorized
        │ (Yes)
        ▼
Does User Own Object? ───(Yes)─► Return Decrypted PII
        │ (No)
        ▼
Is User Staff with 'orders.view_sensitive_customer_data'?
        │
        ├──(Yes)──► Return Decrypted PII + Log Audit Event
        │
        └──(No)───► Return '[MASKED - INSUFFICIENT PERMISSION]'
```

- **Object-Level Isolation (IDOR Defense)**: `get_queryset()` filters results to `user=request.user`. Queries attempting to access other users' entities return `404 Not Found` rather than `403` to prevent object enumeration.
- **Permission Gating**: Customers can only view their own decrypted PII. Staff members without `orders.view_sensitive_customer_data` receive masked strings.

---

## 5. Security Audit Logging

Critical events are permanently recorded in an immutable audit log (`AuditLog`):

| Event Type | Trigger Condition |
|---|---|
| `CHECKOUT_SUCCESS` | Customer successfully places an order. |
| `UNAUTHORIZED_ACCESS_ATTEMPT` | User attempts to access a resource belonging to another account (IDOR). |
| `ADMIN_SENSITIVE_DATA_ACCESS` | Staff member views decrypted customer PII. |
| `DECRYPTION_FAILURE` | Ciphertext tampering or invalid tag encountered during decryption. |
| `USER_REGISTRATION` | New customer account registered. |

> **Strict Policy:** Plaintext PII, user passwords, and cryptographic keys are **never** written to application logs or audit tables.

---

## 6. Known Limitations & Trade-Offs

1. **Non-Searchable Ciphertexts**: Because AES-GCM uses non-deterministic nonces, encrypted columns cannot be searched with SQL `WHERE encrypted_phone = '...'` or `LIKE` queries. For environments requiring exact-match lookups, implement an HMAC-SHA256 **Blind Index** with a separate dedicated salt/secret.
2. **Process Memory Footprint**: The secret key is loaded into application memory. In ultra-secure deployments, consider offloading cryptographic operations to a dedicated KMS RPC endpoint.
