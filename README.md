# SecureCart — E-Commerce Backend with Field-Level Encryption & RBAC

SecureCart is a secure e-commerce backend built with **Django**, **Django REST Framework (DRF)**, **PostgreSQL/SQLite**, and **JWT Authentication**.

---

## 📝 What You Have Built

SecureCart is a security-hardened e-commerce backend designed to prevent common API vulnerabilities (IDOR/BOLA, price tampering, data leaks at rest):
- **Field-Level Encryption at Rest (AES-256-GCM)**: Sensitive customer PII (phone number, email, address snapshots) is encrypted with authenticated symmetric encryption before database storage.
- **Role-Based Access Control (RBAC)**: Enforces clear boundaries between Customer, Moderator, and Admin roles.
- **Anti-IDOR / Object-Level Authorization**: Prevents resource enumeration by returning `404 Not Found` for unauthorized object queries.
- **Atomic Checkout Engine**: Enforces server-side price calculation and real-time inventory locking inside `transaction.atomic()`.
- **Security Audit Logging**: Immutable ledger tracking security-critical events without logging plaintext secrets.

---

## 🔑 Login Credentials or Access Instructions

### Testing Credentials

| Role | Username | Password | Scope |
|---|---|---|---|
| **CUSTOMER** | `nami` | `nami@1234` | Browse catalog, manage own addresses & orders |
| **MODERATOR** | `zoro` | `zoro@1234` | Add & update products (cannot delete or view PII) |
| **ADMIN** | `demo_admin` | `admin1234` | Full access, product deletion, decrypted PII, audit logs |

### Access Instructions

1. **Obtain JWT Token (Login)**:
   ```bash
   curl -X POST http://localhost:8000/api/auth/token/ \
     -H "Content-Type: application/json" \
     -d '{"username": "nami", "password": "nami@1234"}'
   ```
2. **Authenticate Requests**: Include `Authorization: Bearer <access_token>` header in API calls.
3. **Swagger UI**: Visit [http://localhost:8000/api/docs/](http://localhost:8000/api/docs/), click **Authorize**, and enter `Bearer <access_token>`.
4. **Django Admin**: Access [http://localhost:8000/admin/](http://localhost:8000/admin/) with `demo_admin` credentials.

---

## ⚙️ Implemented Features

- **Authentication & RBAC**: JWT login (`/api/auth/token/`), token refresh, self-registration (`/api/auth/register/`), and role management (`/api/admin/users/<id>/role/`).
- **Product Catalog**: Public product browsing, Moderator product creation/updates, and Admin-only product deletion.
- **Customer Addresses**: Address book with transparent AES-256-GCM encryption for phone and email.
- **Atomic Checkout**: Transaction-safe order placement (`/api/checkout/`) with server-side totals, stock deduction, and immutable address snapshots.
- **Anti-IDOR Protection**: Strict tenant isolation returning `404` for unauthorized cross-user queries.
- **PII Decryption Gating**: Only resource owners and authorized admins can view decrypted PII; others receive `[MASKED - INSUFFICIENT PERMISSION]`.
- **Audit Logging**: Immutable trail for checkouts, IDOR attempts, decryption failures, and role changes (`/api/admin/security-events/`).
- **OpenAPI 3.0 Documentation**: Swagger UI (`/api/docs/`) and ReDoc (`/api/redoc/`).

---

## 💡 How the Key Features Work

- **Field-Level Encryption (AES-256-GCM)**:
  - Generates a fresh 12-byte nonce (`os.urandom(12)`) per encryption.
  - Produces ciphertext and a 16-byte authentication tag packed as:
    $$\text{Payload} = \text{Base64}(\text{Nonce} \,\|\, \text{Ciphertext} \,\|\, \text{Tag})$$
  - Any ciphertext tampering fails tag verification, logs `DECRYPTION_FAILURE`, and returns `[DECRYPTION FAILED]`.
- **RBAC & Permission Boundaries**:
  - Mapped via Django Groups (`Customer`, `Moderator`, `Admin`).
  - Moderators have `add_product` and `change_product`, but lack `delete_product` (returns `403 Forbidden` on deletion attempts).
  - Role promotion to Admin is restricted strictly to Superadmins.
- **Anti-IDOR Defense**:
  - Endpoints scope queries to `user=request.user`.
  - Accessing another user's entity returns `404 Not Found` (rather than `403`) to prevent IDOR object enumeration and logs an `UNAUTHORIZED_ACCESS_ATTEMPT`.
- **Atomic Checkout & Anti-Price Tampering**:
  - Entire checkout runs in `transaction.atomic()`.
  - Item totals are recalculated from database prices: $\text{Total} = \sum (\text{Product.price} \times \text{quantity})$, ignoring client-provided amounts.
  - Insufficient stock rolls back the transaction.
- **Security Audit Logging**:
  - `record_security_event()` captures IP, User-Agent, user ID, and event type.
  - Plaintext PII, passwords, and encryption keys are strictly excluded from logs.

---

## 🚀 Quickstart

```bash
# Setup environment & install dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env

# Migrate and seed demo data (creates nami, zoro, demo_admin)
python manage.py migrate
python manage.py setup_roles
python manage.py seed_demo_data

# Run dev server
python manage.py runserver
```

Run test suite (67 tests):
```bash
python manage.py test
```
