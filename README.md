# SecureCart — E-Commerce Backend with Field-Level Encryption & RBAC

SecureCart is a demonstration e-commerce backend built with **Django**, **Django REST Framework (DRF)**, **PostgreSQL**, and **JWT authentication**. It showcases how to secure sensitive customer Personally Identifiable Information (PII) at rest using **authenticated application-level encryption (AES-256-GCM)** while enforcing strict **Role-Based Access Control (RBAC)** and **Object-Level Authorization** to prevent Insecure Direct Object References (IDOR/BOLA).

---

## Features & Capabilities

- **JWT Authentication & Account Management**: Token-based authentication using `djangorestframework-simplejwt` supporting user registration, credential login (pair generation), and access token refresh.
- **Granular Role-Based Access Control (RBAC)**:
  - **Superadmin**: Full administrative and system control.
  - **Admin**: Catalog management, order management, role assignments, audit log review, and sensitive data inspection (with explicit permissions).
  - **Moderator**: Product catalog creation and updates; cannot delete products or view sensitive PII.
  - **Customer**: Standard shopping account; restricted strictly to self-owned cart, orders, and addresses.
- **Product Catalog & Stock Management**: Product browsing with real-time stock tracking. Product mutations (create/update/delete) are restricted by role.
- **Customer Address Management**: Customers can store and manage multiple shipping profiles. Sensitive contact data is encrypted before persisting to the database.
- **Checkout & Order Processing**:
  - Atomic database transactions (`transaction.atomic`) guarantee inventory consistency and eliminate race conditions.
  - Server-calculated pricing ensures order totals are calculated exclusively from database records, blocking client-side price tampering.
  - Generates immutable delivery and contact snapshots at checkout time.
- **Field-Level Data Encryption**: Sensitive customer PII (phone number, email address, delivery street details) is encrypted at rest using AES-256-GCM. Decryption is permission-gated; users without required privileges receive masked placeholders (`[MASKED - INSUFFICIENT PERMISSION]`). *(See [SECURITY.md](SECURITY.md) for cryptographic details).*
- **Object-Level Authorization & IDOR Defense**: All order and address queries are strictly scoped to the authenticated user (`user=request.user`). Unauthorized access attempts to other users' entities return `404 Not Found` rather than `403` to prevent IDOR resource enumeration.
- **Security Audit Logging**: Immutable audit logging for critical security events (`CHECKOUT_SUCCESS`, `UNAUTHORIZED_ACCESS_ATTEMPT`, `ADMIN_SENSITIVE_DATA_ACCESS`, `DECRYPTION_FAILURE`, `USER_REGISTRATION`). Plaintext PII and keys are never logged.

---

## API Documentation

All API endpoints, request/response schemas, parameter validations, and interactive testing forms are self-documented via OpenAPI 3.0:

- **Swagger UI (Interactive API Tester):** [`/api/docs/`](http://localhost:8000/api/docs/) *(also available at `/docs/` and `/swagger/`)*
- **ReDoc UI (Document View):** [`/api/redoc/`](http://localhost:8000/api/redoc/) *(also available at `/redoc/`)*
- **OpenAPI Schema (JSON / YAML):** [`/api/schema/`](http://localhost:8000/api/schema/)

> *Note: Individual endpoint definitions are omitted from this README in favor of the live, interactive Swagger documentation above.*

---

## Security Architecture

For detailed information regarding the cryptographic design (AES-256-GCM specification, nonce handling, tamper verification, key generation, and threat model), refer directly to:

👉 **[SECURITY.md](SECURITY.md)**

---

## Quickstart & Setup

### Option 1: Docker (Recommended)

Run the backend and PostgreSQL database in isolated containers:

```bash
# Build and run containers
docker compose up --build

# In a separate terminal, seed initial roles and demo data
docker compose exec web python manage.py seed_demo_data
```

The API and documentation will be accessible at `http://localhost:8000`.

---

### Option 2: Local Setup

#### 1. Prerequisites & Environment
Ensure Python 3.11+ is installed.

```bash
# Create and activate virtual environment
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### 2. Environment Variables
Copy the template configuration file:

```bash
cp .env.example .env
```

Ensure `.env` contains a valid 256-bit AES key. You can generate one via:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

#### 3. Database Setup & Seeding
Apply migrations, provision default security groups, and populate demo records:

```bash
python manage.py migrate
python manage.py setup_roles
python manage.py seed_demo_data
```

#### 4. Run the Development Server
```bash
python manage.py runserver
```

---

## Demo Accounts

When seeded via `seed_demo_data`, the following test accounts are available:

| Role | Username | Password | Notes |
|---|---|---|---|
| **Superadmin / Admin** | `admin` | `AdminPass123!` | Full admin access, audit logs, sensitive data permissions |
| **Customer** | `customer1` | `CustomerPass123!` | Standard customer account with pre-seeded address |
| **Customer** | `customer2` | `CustomerPass123!` | Secondary customer account (ideal for testing IDOR defense) |

---

## Automated Test Suite

Run the full automated test suite (covering encryption, RBAC, checkout atomicity, IDOR protection, and audit logging):

```bash
# Local environment:
python manage.py test

# Docker:
docker compose exec web python manage.py test
```
