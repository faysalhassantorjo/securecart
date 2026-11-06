# SecureCart — E-Commerce Backend with Encrypted Customer Data

SecureCart is a demonstration e-commerce backend built with **Django, Django REST Framework, PostgreSQL, and JWT authentication**.

The core mission of SecureCart is to demonstrate how sensitive customer Personally Identifiable Information (PII) — specifically **phone numbers** and **email addresses** — can be protected using **authenticated application-level encryption at rest (AES-256-GCM)**, coupled with **granular role-based authorization (RBAC) and object-level permissions** to prevent Insecure Direct Object References (IDOR/BOLA).

---

## Table of Contents
1. [Project Overview & Problem Statement](#1-project-overview--problem-statement)
2. [How SecureCart Protects Customer Information](#2-how-securecart-protects-customer-information)
3. [Technology Stack & Rationale](#3-technology-stack--rationale)
4. [Architecture & DRF View Style](#4-architecture--drf-view-style)
5. [Installation & Local Setup](#5-installation--local-setup)
6. [Docker & Containerized Setup](#6-docker--containerized-setup)
7. [Environment Variables & Key Generation](#7-environment-variables--key-generation)
8. [Database Setup, Migrations & Role Seeding](#8-database-setup-migrations--role-seeding)
9. [JWT Authentication Instructions](#9-jwt-authentication-instructions)
10. [API Endpoints & Documentation](#10-api-endpoints--documentation)
11. [Checkout Flow: Encryption & Decryption Points](#11-checkout-flow-encryption--decryption-points)
12. [Role-Based Access Control (RBAC) & Permission Boundaries](#12-role-based-access-control-rbac--permission-boundaries)
13. [Authorization & Object-Level Access Control (IDOR Defense)](#13-authorization--object-level-access-control-idor-defense)
14. [Security Audit Logging](#14-security-audit-logging)
15. [Automated Test Suite](#15-automated-test-suite)
16. [Interactive Demo Walkthrough](#16-interactive-demo-walkthrough)
17. [Security Limitations & Future Improvements](#17-security-limitations--future-improvements)

---

## 1. Project Overview & Problem Statement

In standard web applications, sensitive customer PII is frequently stored in plaintext in relational databases. If a database backup is leaked, a SQL injection occurs, or an internal database dump is accessed by untrusted third parties, customer data is instantly compromised.

Furthermore, traditional access control implementations frequently suffer from **BOLA / IDOR (Broken Object Level Authorization)**: when an API allows a user to access an order simply by passing an order ID in the URL without strict object ownership verification.

**SecureCart addresses these challenges by:**
1. Encrypting customer phone numbers and emails at the application level prior to database persistence using **AES-256-GCM**.
2. Rejecting tampered ciphertext automatically via 128-bit authentication tags.
3. Enforcing object-level permissions so customers can only access their own orders and addresses.
4. Gating decryption behind explicit Django permissions (`orders.view_sensitive_customer_data`) and logging administrative access to sensitive data in an immutable audit trail.

---

## 2. How SecureCart Protects Customer Information

```
                       APPLICATION BOUNDARY
 [Client Request] ──> [Input Validation] ──> [AES-256-GCM Encryptor]
  (Plaintext PII)                                   │
                                                    ▼
                                            [Ciphertext Payload]
                                                    │
 ───────────────────────────────────────────────────┼────────────────
                DATABASE STORAGE                    ▼
                                            [PostgreSQL Database]
                                       (Stores ONLY Base64 Ciphertext)
 ───────────────────────────────────────────────────┬────────────────
                                                    │
 [Client Response] <── [Permission Gating] <── [AES-256-GCM Decryptor]
 (Plaintext only if       (Owner OR Admin
  authorized)               with Perm)
```

1. **Authenticated Encryption (AES-256-GCM)**: Every sensitive field is encrypted using a unique, 96-bit cryptographically secure random nonce (`os.urandom(12)`) and authenticated with a 128-bit GCM tag.
2. **Database Contains Only Ciphertext**: Inspecting the `orders_order` or `accounts_address` tables in PostgreSQL reveals only URL-safe Base64 strings, never plaintext phone numbers or emails.
3. **Fail-Safe Tamper Detection**: If any byte in the ciphertext or tag is modified, decryption immediately raises `InvalidTag` and fails safely without returning corrupted data or leaking keys.
4. **No Secrets in Logs**: All audit loggers and system handlers sanitize output so encryption keys and plaintext PII never touch log files.

---

## 3. Technology Stack & Rationale

| Technology | Selection Rationale |
|---|---|
| **Python 3.12** | Modern, stable runtime with standard typing and performance optimizations. |
| **Django 5.1** | Robust, mature web framework with battle-tested ORM, migrations, and built-in User & Permission model. |
| **Django REST Framework (DRF)** | Standard API toolkit providing serialization, permission classes, and view hierarchy. |
| **PostgreSQL 16** | Production-ready ACID relational database supporting row-level locking (`SELECT FOR UPDATE`). |
| **`cryptography` library** | Official, maintained Python Cryptographic Authority package providing verified `AESGCM` primitives. |
| **`djangorestframework-simplejwt`** | Stateless, standard JWT authentication for modern APIs. |
| **`drf-spectacular`** | Generates OpenAPI 3.0 schema and interactive Swagger UI documentation. |
| **Docker & Docker Compose** | Multi-container orchestration providing reproducible PostgreSQL and Django services. |

---

## 4. Architecture & DRF View Style

All domain applications are organized inside the `apps/` directory, and each app defines its own routing in `urls.py`:

```
SecureCart/
├── config/              # Root settings, root URLs, WSGI/ASGI
├── apps/
│   ├── core/            # AES-256-GCM cipher utility, custom permissions, audit logging
│   ├── accounts/        # Address model (encrypted), serializers, views, role setup
│   ├── products/        # Product catalog model, serializers, generic views
│   ├── orders/          # Order snapshot model, checkout APIView, order views
│   └── audit_logs/      # AuditLog model, serializers, compliance views
├── tests/               # 67 automated security, checkout, registration, order address, and RBAC tests
├── Dockerfile           # Multi-stage container definition
├── docker-compose.yml   # PostgreSQL + Django web service configuration
├── requirements.txt     # Locked dependencies
├── .env.example         # Environment template with placeholder key
├── SECURITY.md          # Cryptography and security policy
└── postman_collection.json # Ready-to-import API collection
```

### Why DRF `APIView` and Generic Views (No ViewSets)?
As requested by architectural guidelines, **ViewSets and ModelViewSets are intentionally avoided**:
- **`APIView` for Custom Workflows (`CheckoutAPIView`)**: Checkout requires complex transactional orchestration (row-level locking on inventory, server-side pricing, PII encryption, order item creation, and audit logging). `APIView` keeps this business logic explicit and easy to audit.
- **Generic Views for CRUD Operations**:
  - `ProductListCreateAPIView` (`ListCreateAPIView`) & `ProductDetailAPIView` (`RetrieveUpdateDestroyAPIView`)
  - `AddressListCreateAPIView` (`ListCreateAPIView`) & `AddressDetailAPIView` (`RetrieveUpdateDestroyAPIView`)
  - `OrderListAPIView` (`ListAPIView`) & `OrderDetailAPIView` (`RetrieveAPIView`)
  - `SecurityEventListAPIView` (`ListAPIView`)
- **Explicit Security Auditing**: Generic API Views provide clear lifecycle hooks (`get_queryset`, `get_object`, `perform_create`) where permission checks and audit logs can be verified without the implicit routing and magic of ModelViewSets.

---

## 5. Installation & Local Setup

### Prerequisites
- Python 3.12+
- Git

### 1. Clone & Create Virtual Environment
```bash
git clone <repository_url> SecureCart
cd SecureCart

python -m venv .venv
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Generate an AES-256-GCM key and set it in `.env`:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 6. Docker & Containerized Setup

The easiest way to run SecureCart with PostgreSQL is via Docker Compose:

### 1. Build and Start Containers
```bash
docker compose up --build
```
This automatically:
- Starts PostgreSQL 16 on port `5432` with a persistent volume (`postgres_data`).
- Waits for PostgreSQL readiness via health check (`pg_isready`).
- Runs database migrations (`python manage.py migrate`).
- Configures default roles and permissions (`python manage.py setup_roles`).
- Starts the Django development server on port `8000`.

### 2. Useful Docker Commands
```bash
# Seed initial demo data inside the container:
docker compose exec web python manage.py seed_demo_data

# Create a custom superuser:
docker compose exec web python manage.py createsuperuser

# Run automated tests inside the container:
docker compose exec web python manage.py test tests

# Stop containers:
docker compose down

# Stop and remove persistent database volume:
docker compose down -v
```

---

## 7. Environment Variables & Key Generation

| Variable | Description | Example / Default |
|---|---|---|
| `DJANGO_SECRET_KEY` | Django internal cryptographic secret | `django-insecure-...` |
| `DEBUG` | Enable/disable debug mode | `True` (dev) / `False` (prod) |
| `ALLOWED_HOSTS` | Comma-separated allowed host headers | `localhost,127.0.0.1,web` |
| `DB_NAME` | PostgreSQL database name | `securecart_db` |
| `DB_USER` | PostgreSQL username | `postgres` |
| `DB_PASSWORD` | PostgreSQL password | `postgres_secure_password` |
| `DB_HOST` | Database host | `db` (Docker) / `localhost` (local) |
| `DB_PORT` | Database port | `5432` |
| `USE_SQLITE` | Fallback to local SQLite for rapid testing | `False` |
| `AES_SECRET_KEY` | 32-byte (256-bit) Hex key for AES-GCM | 64-character hex string |

### Generating a New AES-256-GCM Key
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 8. Database Setup, Migrations & Role Seeding

### Running Migrations Manually
```bash
python manage.py makemigrations accounts products orders audit_logs
python manage.py migrate
```

### Initializing Groups and Permissions (`setup_roles`)
SecureCart uses Django Default Groups and Permissions to power its 3-tier Role-Based Access Control:
```bash
python manage.py setup_roles
```
This provisions:
- **`Customer` Group**:
  - Permissions: `accounts.add_address`, `accounts.change_address`, `accounts.delete_address`, `accounts.view_address`, `products.view_product`, `orders.add_order`, `orders.view_order`.
- **`Moderator` Group**:
  - Permissions: `products.add_product`, `products.change_product`, `products.view_product`, `accounts.add_address`, `accounts.view_address`, `orders.add_order`, `orders.view_order`.
  - *Explicitly lacks*: `products.delete_product` (strictly reserved for Admin) and staff administrative permissions.
- **`Admin` Group**:
  - Permissions: Full product catalog management (`add_product`, `change_product`, `delete_product`, `view_product`), order inspection (`orders.view_order`), custom permission `orders.view_sensitive_customer_data`, and audit trail inspection (`audit_logs.view_auditlog`). Staff access (`is_staff=True`).

### One-Click Demo Seeding (`seed_demo_data`)
```bash
python manage.py seed_demo_data
```
Creates:
- `admin` (Password: `AdminPass123!`) — Staff superuser in `Admin` group.
- `customer1` (Password: `CustomerPass123!`) — In `Customer` group with saved address.
- `customer2` (Password: `CustomerPass123!`) — Second customer to demonstrate IDOR defense.
- Catalog products: Hardware wallets, privacy screens, and security keys.

---

## 9. JWT Authentication Instructions

SecureCart uses `djangorestframework-simplejwt` and provides a public registration endpoint.

### 1. Register a New Customer Account
**`POST /api/auth/register/`** *(also accessible at `/api/register/`)*
```json
{
  "username": "new_customer",
  "email": "customer@example.com",
  "password": "SecurePassword123!",
  "password_confirm": "SecurePassword123!",
  "first_name": "Jane",
  "last_name": "Doe"
}
```
**Response (201 Created):**
```json
{
  "message": "User registered successfully.",
  "user": {
    "id": 3,
    "username": "new_customer",
    "email": "customer@example.com",
    "first_name": "Jane",
    "last_name": "Doe",
    "date_joined": "2026-11-05T02:14:16.929Z"
  },
  "tokens": {
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```
*Note: The newly created user is automatically added to the default `Customer` role group and issued an initial JWT token pair for immediate access to protected endpoints.*

### 2. Obtain Token Pair (Login)
**`POST /api/auth/token/`**
```json
{
  "username": "customer1",
  "password": "CustomerPass123!"
}
```
**Response:**
```json
{
  "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 3. Include Token in Subsequent Requests
Add the Bearer authorization header to all authenticated calls:
```http
Authorization: Bearer <access_token>
```

### 4. Refresh Access Token
**`POST /api/auth/token/refresh/`**
```json
{
  "refresh": "<refresh_token>"
}
```

---

## 10. API Endpoints & Documentation

Interactive Swagger & ReDoc documentation is available at:
👉 **Swagger UI:** `http://localhost:8000/api/docs/` *(also at `/docs/`, `/swagger/`)*
👉 **ReDoc UI:** `http://localhost:8000/api/redoc/` *(also at `/redoc/`)*
👉 **OpenAPI Schema (JSON/YAML):** `http://localhost:8000/api/schema/`

| Category | Method | Endpoint | Authorization | Description |
|---|---|---|---|---|
| **Auth** | `POST` | `/api/auth/register/` | Public | Register new customer account and obtain JWT tokens. |
| | `POST` | `/api/auth/token/` | Public | Obtain JWT access and refresh token. |
| | `POST` | `/api/auth/token/refresh/` | Public | Refresh expired access token. |
| **Products** | `GET` | `/api/products/` | Authenticated | List catalog products. |
| | `POST` | `/api/products/` | Moderator / Admin (`add_product`) | Create product (price, stock). Customer receives 403. |
| | `GET` | `/api/products/<id>/` | Authenticated | Retrieve product details. |
| | `PUT/PATCH` | `/api/products/<id>/` | Moderator / Admin (`change_product`) | Update product. Customer receives 403. |
| | `DELETE` | `/api/products/<id>/` | Admin / Superadmin ONLY (`delete_product`) | Delete product. **Moderator & Customer receive 403.** |
| **Addresses** | `GET` | `/api/addresses/` | Customer (`IsOwner`) | List user's saved addresses. |
| | `POST` | `/api/addresses/` | Customer | Create address (phone/email encrypted). |
| | `GET` | `/api/addresses/<id>/` | Customer (`IsOwner`) | Retrieve owned address with decrypted PII. |
| | `PATCH` | `/api/addresses/<id>/` | Customer (`IsOwner`) | Update owned address. |
| | `DELETE` | `/api/addresses/<id>/` | Customer (`IsOwner`) | Delete owned address. |
| **Order Addresses** | `GET` | `/api/order-addresses/` | Owner / Superadmin / Admin | List order addresses (scoped to owner; all for Admin/Superadmin). |
| | `GET` | `/api/order-addresses/<id>/` | Owner / Superadmin / Admin | Retrieve specific order address (decrypted for authorized callers). *(No update URLs).* |
| | `GET` | `/api/orders/<order_id>/address/` | Owner / Superadmin / Admin | Retrieve order address linked to specific order ID. |
| **Checkout & Orders** | `POST` | `/api/checkout/` | Customer | Atomic checkout, server totals, OrderAddress creation, PII encryption. |
| | `GET` | `/api/orders/` | Customer (`IsOwner`) | List customer's own orders. |
| | `GET` | `/api/orders/<id>/` | Owner / Authorized Admin | Retrieve order with decrypted PII and nested `order_address`. |
| **Admin & RBAC** | `GET` | `/api/admin/roles/` | Public / Authenticated | List available roles, assignment rules, and exact permission boundaries. |
| | `GET` | `/api/admin/users/` | Admin / Superadmin | List all users and their assigned roles and permissions. |
| | `GET` | `/api/admin/users/<id>/role/` | Admin / Superadmin | Retrieve a user's current role, groups, and explicit permissions. |
| | `POST/PUT` | `/api/admin/users/<id>/role/` | Admin / Superadmin (Hierarchy Gated) | Assign role (`CUSTOMER`, `MODERATOR`, `ADMIN`). Admins can assign Customer/Moderator; only Superadmin can assign Admin. |
| | `GET` | `/api/admin/orders/` | Admin (`view_order`) | List all orders across all customers. |
| | `GET` | `/api/admin/order-addresses/` | Admin (`view_order`) | List all order addresses across all customers. |
| | `GET` | `/api/admin/security-events/` | Admin (`view_auditlog`) | View immutable security audit logs. |

---

## 11. Checkout Flow: Encryption & Decryption Points

```
1. Customer initiates POST /api/checkout/ with items and contact details.
   │
2. Backend validates input serializer (phone_number, email, address, items).
   │
3. Database Transaction Begins (transaction.atomic):
   ├── SELECT FOR UPDATE on requested products (prevents inventory race conditions).
   ├── Validates stock: if requested > stock_quantity, transaction ROLLS BACK.
   ├── Server calculates order total: Σ(product.price * quantity)
   │   (Any client-submitted price is ignored).
   │
4. Encryption Step:
   ├── encrypt_value(phone_number)     ──> AES-256-GCM ciphertext
   ├── encrypt_value(email)            ──> AES-256-GCM ciphertext
   ├── encrypt_value(delivery_address) ──> AES-256-GCM ciphertext
   │
5. Database Persistence:
   ├── INSERT into orders_order (status='confirmed', total, snapshot address, encrypted_phone, encrypted_email)
   ├── INSERT into orders_orderaddress (order_id, user_id, recipient, street, city, postal_code, encrypted_street, encrypted_phone, encrypted_email)
   ├── INSERT into orders_orderitem (order_id, product_id, quantity, unit_price, subtotal)
   ├── UPDATE products_product (decrement stock_quantity)
   └── INSERT into audit_logs_auditlog (event='CHECKOUT_SUCCESS')
   │
6. Database Transaction Commits.
   │
7. Safe Response Returned: 201 Created with order ID, total, status, and summary message.
   (Does not leak unnecessary sensitive fields).
```

### Where Does Decryption Happen?
Decryption occurs only when an authorized party calls `GET /api/orders/<id>/`, `GET /api/order-addresses/<id>/`, or `GET /api/addresses/<id>/`:
1. The serializer checks `can_view_sensitive_data(request.user, instance)`.
2. If the user is the **ordering customer (owner)**, `decrypt_value()` decrypts the ciphertext.
3. If the user is a **superadmin** or user holding the **Admin role**, `decrypt_value()` decrypts the ciphertext AND logs an `ADMIN_SENSITIVE_DATA_ACCESS` audit record.
4. If an unauthorized user attempts access, `404 Not Found` is returned (preventing IDOR enumeration) and `UNAUTHORIZED_ACCESS_ATTEMPT` is logged.

---

## 12. Role-Based Access Control (RBAC) & Permission Boundaries

SecureCart implements a robust 3-tier Role-Based Access Control (RBAC) architecture with strictly enforced permission boundaries and an authoritative role-assignment hierarchy.

### The 3 Roles & Assignment Hierarchy

```
               ┌───────────────────────────────┐
               │    SUPERADMIN (Root Staff)    │
               │   (Django is_superuser=True)  │
               └───────────────┬───────────────┘
                               │
               Can assign ALL roles (Admin, Moderator, Customer)
                               │
                               ▼
               ┌───────────────────────────────┐
               │          ADMIN ROLE           │
               │  • Assigned ONLY by Superadmin│
               │  • Has is_staff=True          │
               └───────────────┬───────────────┘
                               │
               Can assign ONLY Moderator & Customer
               (Cannot elevate anyone to Admin)
                               │
                               ▼
               ┌───────────────────────────────┐
               │        MODERATOR ROLE         │
               │  • Assigned by Admin/Super    │
               │  • is_staff=False             │
               └───────────────────────────────┘
                               ▲
                               │
               ┌───────────────┴───────────────┐
               │         CUSTOMER ROLE         │
               │  • Auto-assigned on register  │
               │  • is_staff=False             │
               └───────────────────────────────┘
```

1. **`CUSTOMER`**:
   - **Assignment**: Automatically assigned to any new user during registration (`POST /api/auth/register/`).
   - **Boundary**: Can browse products, manage their own saved addresses, and create/view their own orders. Cannot create, update, or delete products; cannot access administrative routes or other customers' records.
2. **`MODERATOR`**:
   - **Assignment**: Can be assigned **only** by system `SUPERADMIN` or users with the `ADMIN` role via `POST /api/admin/users/<id>/role/`. Regular customers cannot assign roles.
   - **Boundary**: Can create new products (`POST /api/products/`) and update existing products (`PUT/PATCH /api/products/<id>/`), but **strictly CANNOT delete products** (`DELETE /api/products/<id>/` returns HTTP 403 Forbidden). Cannot view other customers' orders or audit logs.
3. **`ADMIN` & `SUPERADMIN`**:
   - **Assignment**: Can be assigned **ONLY by system `SUPERADMIN`** (`is_superuser=True`). If a standard Admin attempts to promote another user to `ADMIN`, the API returns HTTP 403 Forbidden and records an `UNAUTHORIZED_ACCESS_ATTEMPT` audit log.
   - **Boundary**: Full administrative privileges ("can do everything"): full product management (including deletion), cross-customer order inspection, decrypted customer PII access, and security audit trail inspection.

### Permission Boundary Matrix

| Feature / Action | HTTP Method & Path | Customer | Moderator | Admin | Superadmin |
|---|---|:---:|:---:|:---:|:---:|
| **Browse Products** | `GET /api/products/` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **View Product Details** | `GET /api/products/<id>/` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **Create Product** | `POST /api/products/` | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **Update Product** | `PUT/PATCH /api/products/<id>/` | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **Delete Product** | `DELETE /api/products/<id>/` | ❌ **403 Forbidden** | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed |
| **Checkout & Create Order** | `POST /api/checkout/` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **Manage Own Saved Addresses** | `CRUD /api/addresses/` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **View Own Orders & Addresses** | `GET /api/orders/`, `/api/order-addresses/` | ✅ Allowed | ✅ Allowed | ✅ Allowed | ✅ Allowed |
| **Access Other Customers' Orders** | `GET /api/orders/<foreign_id>/` | ❌ **404 (IDOR Defense)** | ❌ **404 (IDOR Defense)** | ✅ Allowed (Decrypted) | ✅ Allowed (Decrypted) |
| **View All Orders (Cross-Customer)** | `GET /api/admin/orders/` | ❌ **403 Forbidden** | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed |
| **View All Order Addresses** | `GET /api/admin/order-addresses/` | ❌ **403 Forbidden** | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed |
| **Inspect Security Audit Logs** | `GET /api/admin/security-events/` | ❌ **403 Forbidden** | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed |
| **View User Roles & Permissions** | `GET /api/admin/users/` | ❌ **403 Forbidden** | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed |
| **Assign `CUSTOMER` Role** | `POST /api/admin/users/<id>/role/` | ❌ **403 Forbidden** | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed |
| **Assign `MODERATOR` Role** | `POST /api/admin/users/<id>/role/` | ❌ **403 Forbidden** | ❌ **403 Forbidden** | ✅ Allowed | ✅ Allowed |
| **Assign `ADMIN` Role** | `POST /api/admin/users/<id>/role/` | ❌ **403 Forbidden** | ❌ **403 Forbidden** | ❌ **403 (Superadmin Only)** | ✅ **Allowed** |

### Role Management API Examples

#### 1. Inspect Role Definitions & Boundaries
**`GET /api/admin/roles/`** (Public / Authenticated)
```json
{
  "roles": [
    {
      "role": "CUSTOMER",
      "description": "Default role assigned automatically upon user registration.",
      "assignment_rule": "Automatically assigned upon registration. Can also be assigned by Admin or Superadmin.",
      "permissions": [
        "Create orders and checkout",
        "Create, view, and update own saved addresses",
        "View own order history and order delivery addresses",
        "Browse product catalog (read-only)"
      ],
      "prohibitions": [
        "Cannot create, edit, or delete products",
        "Cannot access other customers' orders or addresses",
        "Cannot access administrative endpoints or audit logs"
      ]
    },
    {
      "role": "MODERATOR",
      "description": "Content catalog moderator role.",
      "assignment_rule": "Can be assigned ONLY by system SUPERADMIN or users with the ADMIN role.",
      "permissions": [
        "Create product objects (POST /api/products/)",
        "Update product objects (PUT/PATCH /api/products/<id>/)",
        "Browse product catalog (read-only)",
        "Standard customer capabilities for own orders and addresses"
      ],
      "prohibitions": [
        "CANNOT delete products (DELETE /api/products/<id>/ is forbidden)",
        "Cannot access other customers' orders, addresses, or audit logs",
        "Cannot assign or modify user roles"
      ]
    },
    {
      "role": "ADMIN",
      "description": "System administrator with full operational privileges.",
      "assignment_rule": "Can be assigned ONLY by system SUPERADMIN. Admins cannot promote users to Admin.",
      "permissions": [
        "Full product catalog management including deletion (DELETE /api/products/<id>/)",
        "View all customer orders and decrypt sensitive customer PII",
        "Inspect immutable security audit event logs",
        "Assign CUSTOMER and MODERATOR roles to users"
      ],
      "prohibitions": [
        "Cannot assign ADMIN role to users without superadmin privileges"
      ]
    }
  ]
}
```

#### 2. Promote User to Moderator (as Admin or Superadmin)
**`POST /api/admin/users/4/role/`**
```json
{
  "role": "MODERATOR"
}
```
**Response (200 OK):**
```json
{
  "message": "User 'john_doe' role successfully updated to 'MODERATOR'.",
  "user_id": 4,
  "username": "john_doe",
  "role": "MODERATOR",
  "previous_role": "CUSTOMER"
}
```

#### 3. Admin Promotion Attempt by Non-Superadmin (Blocked & Audited)
When a regular Admin attempts to assign the `ADMIN` role:
```bash
curl -X POST http://localhost:8000/api/admin/users/4/role/ \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"role": "ADMIN"}'
```
**Response (403 Forbidden):**
```json
{
  "detail": "Only system superadmins can promote a user to the ADMIN role."
}
```
*Audit Log Event Created*: `UNAUTHORIZED_ACCESS_ATTEMPT` with actor username, client IP, and target user ID.

---

## 13. Authorization & Object-Level Access Control (IDOR Defense)

### Preventing BOLA / IDOR Vulnerabilities
In an Insecure Direct Object Reference (IDOR) attack, a malicious customer changes the order ID in the URL (e.g. from `/api/orders/1/` to `/api/orders/2/`) to view someone else's personal information.

**SecureCart enforces two-layer defense against IDOR:**
1. **Queryset Scoping**: In `OrderListAPIView` and `AddressListCreateAPIView`, the queryset is explicitly scoped to the authenticated user:
   ```python
   def get_queryset(self):
       return Order.objects.filter(user=self.request.user)
   ```
2. **Defensive `get_object()` in Retrieve Views**:
   When Customer Bob attempts `GET /api/orders/<alice_id>/`:
   - The view detects that Order `<alice_id>` exists but belongs to Alice.
   - It records an `UNAUTHORIZED_ACCESS_ATTEMPT` security audit event with Bob's user ID, IP address, and target order ID.
   - It raises `Http404 Not Found` (rather than 403) so the attacker cannot even determine whether that order ID exists.

---

## 14. Security Audit Logging

All security-relevant events are persisted to the `AuditLog` table:

| Event Type | Trigger Condition |
|---|---|
| `CHECKOUT_SUCCESS` | Customer successfully places an order and encrypts PII. |
| `USER_REGISTRATION` | New customer account registered and auto-assigned `Customer` role. |
| `ROLE_ASSIGNMENT_SUCCESS` | Superadmin or Admin assigns a new role (`CUSTOMER`, `MODERATOR`, `ADMIN`) to a user. |
| `UNAUTHORIZED_ACCESS_ATTEMPT` | User attempts IDOR access, unauthorized role modification, or regular Admin attempts to promote user to Admin. |
| `ADMIN_SENSITIVE_DATA_ACCESS` | Administrator accesses decrypted customer PII. |
| `DECRYPTION_FAILURE` | Decryption fails due to corrupted data, tampered tag, or key mismatch. |

Administrators with `audit_logs.view_auditlog` can inspect logs via:
`GET /api/admin/security-events/`

---

## 15. Automated Test Suite

SecureCart includes a comprehensive **67-test automated test suite** covering:
- **3-Tier RBAC & Role Boundaries (20 tests in `tests/test_role_boundaries.py`)**:
  - Automatic `CUSTOMER` role assignment upon registration.
  - Moderator role assignment by Superadmin and Admin.
  - Rejection of Customer / Moderator attempts to assign roles (HTTP 403 Forbidden).
  - Strict rejection of Admin attempts to promote a user to `ADMIN` (HTTP 403 Forbidden with audit log).
  - Moderator product creation (`POST /api/products/`) and partial/full updates (`PUT/PATCH /api/products/<id>/`).
  - Strict enforcement preventing Moderator from deleting products (`DELETE /api/products/<id>/` -> HTTP 403 Forbidden).
  - Admin & Superadmin product deletion verification (HTTP 204 No Content).
  - Rejection of Customer product writes (HTTP 403 Forbidden).
  - Verification that Moderator cannot access cross-customer orders or security audit logs.
  - Role metadata endpoint verification (`GET /api/admin/roles/`).
  - User and role inspection endpoints (`GET /api/admin/users/`).
  - Swagger UI and OpenAPI schema availability (`/api/docs/` and `/api/schema/`).
- **Order Address & Sensitive Data Gating (12 tests in `tests/test_order_address.py`)**:
  - Order address creation upon checkout and bidirectional relationship linking.
  - Encrypted storage of order street address, phone, and email at rest using AES-256-GCM.
  - Access control restricting order address visibility strictly to the ordering user, superadmin, and users with Admin role.
  - Prevention of unauthorized order address access (IDOR / BOLA defense returning 404 + audit log).
  - Rejection of order address update URLs (HTTP 405 Method Not Allowed on PUT/PATCH).
- **Core Security, Cryptography & Authentication (34 tests in `tests/test_security_and_checkout.py`)**:
  - User registration, password complexity validation, and duplicate account prevention.
  - Immediate JWT authorization for new accounts.
  - AES-256-GCM roundtrip encryption and semantic security (fresh nonces).
  - Tamper detection on ciphertext and authentication tag (`InvalidTag` rejection).
  - JWT token generation, refresh, and unauthenticated rejection.
  - Server-side price calculation and resistance against client price tampering.
  - Atomic checkout rollback on out-of-stock conditions.
  - Database verification that stored values are ciphertext != plaintext.
  - IDOR / BOLA prevention (Bob querying Alice's order gets 404 + audit log).
  - Admin permission-gated decryption and audit logging.
- **OpenAPI / Swagger Documentation (`tests/test_api_docs.py`)**:
  - OpenAPI 3.0 schema generation and Swagger UI accessibility.

### Run Tests:
```bash
# In local virtual environment:
python manage.py test tests

# Inside Docker Compose:
docker compose exec web python manage.py test tests
```

---

## 16. Interactive Demo Walkthrough

### Step 1: Start Services & Seed Demo Data
```bash
docker compose up -d --build
docker compose exec web python manage.py seed_demo_data
```

### Step 2: Log in as Customer 1
```bash
curl -X POST http://localhost:8000/api/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "customer1", "password": "CustomerPass123!"}'
```
*(Copy the returned `"access"` token)*

### Step 3: Execute Checkout as Customer 1
```bash
curl -X POST http://localhost:8000/api/checkout/ \
  -H "Authorization: Bearer <CUSTOMER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [{"product_id": 1, "quantity": 1}, {"product_id": 2, "quantity": 1}],
    "recipient_name": "Alice Customer",
    "phone_number": "+1-555-888-9999",
    "email": "alice@securecart.local",
    "delivery_address": "123 Cryptography Way",
    "delivery_city": "Springfield",
    "delivery_postal_code": "97477"
  }'
```

### Step 4: Verify Database Stores ONLY Ciphertext
Connect to PostgreSQL container and inspect the table:
```bash
docker compose exec db psql -U postgres -d securecart_db -c "SELECT id, recipient_name, total_amount, encrypted_phone, encrypted_email FROM orders_order;"
```
Notice that `encrypted_phone` and `encrypted_email` contain Base64 AES-GCM ciphertexts like:
`v1w2...==`. Plaintext is **nowhere in the database**!

### Step 5: Test IDOR Protection as Customer 2
Obtain a token for `customer2`:
```bash
curl -X POST http://localhost:8000/api/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "customer2", "password": "CustomerPass123!"}'
```
Attempt to view Customer 1's Order #1:
```bash
curl -X GET http://localhost:8000/api/orders/1/ \
  -H "Authorization: Bearer <CUSTOMER2_TOKEN>"
```
Returns: **`404 Not Found`** and logs `UNAUTHORIZED_ACCESS_ATTEMPT`.

### Step 6: Log in as Admin and View Audit Logs
```bash
curl -X POST http://localhost:8000/api/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "AdminPass123!"}'
```
Query security events:
```bash
curl -X GET http://localhost:8000/api/admin/security-events/ \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

---

## 17. Security Limitations & Future Improvements

This project is a demonstration of application-level encryption and RBAC. For production readiness, the following enhancements should be implemented:

1. **Hardware Security Module (HSM) / Cloud KMS**: Store encryption keys in AWS KMS, Google Cloud KMS, or HashiCorp Vault rather than environment variables.
2. **Envelope Encryption**: Implement Key Encryption Keys (KEK) and Data Encryption Keys (DEK) with automated key rotation.
3. **Blind Indexing**: To search for customers by phone number or email without decrypting every record, implement HMAC-SHA256 blind indexing.
4. **Rate Limiting**: Enforce IP- and user-based throttling on checkout and authentication endpoints using DRF throttling or Redis.
#   s e c u r e c a r t  
 