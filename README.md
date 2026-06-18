# SecureVault

**A Post-Quantum Cryptography-Based Secure Notes, Password, and Task Management System**

SecureVault is a FastAPI backend that stores user notes, passwords, and to-do tasks using **hybrid post-quantum encryption** (ML-KEM / CRYSTALS-Kyber + AES-256-GCM). It layers Argon2 password hashing, email OTP two-factor authentication, JWT sessions, rate limiting, behavioural risk scoring, and an SVM-based password strength classifier on top of the encrypted vault, so that no plaintext secret is ever written to disk and no account can be brute-forced without detection.

---

## Table of Contents

1. [Key Features](#key-features)
2. [System Architecture](#system-architecture)
3. [Technology Stack](#technology-stack)
4. [Project Structure](#project-structure)
5. [Core Concepts](#core-concepts)
   - [Hybrid Encryption Model](#hybrid-encryption-model)
   - [Authentication Flow](#authentication-flow)
   - [Risk Scoring Engine](#risk-scoring-engine)
   - [Rate Limiting](#rate-limiting)
6. [Database Schema (ERD Reference)](#database-schema-erd-reference)
7. [API Reference](#api-reference)
8. [Module-by-Module Reference](#module-by-module-reference)
9. [Sequence Flows (for UML Sequence Diagrams)](#sequence-flows-for-uml-sequence-diagrams)
10. [Use Cases (for UML Use Case Diagrams)](#use-cases-for-uml-use-case-diagrams)
11. [Class/Component Map (for UML Class Diagrams)](#classcomponent-map-for-uml-class-diagrams)
12. [Environment Variables](#environment-variables)
13. [Setup & Installation](#setup--installation)
14. [Security Design Notes](#security-design-notes)
15. [Known Limitations & Future Work](#known-limitations--future-work)

---

## Key Features

- **Hybrid Post-Quantum Encryption** — every note, password, and task is encrypted with AES-256-GCM using a key derived from an ML-KEM (Kyber-512) key encapsulation, with automatic fallback to a local backup AES key if the Kyber microservice is unreachable.
- **Two-Factor Authentication** — Argon2id password hashing plus a mandatory email-delivered OTP step for signup, login, and password reset.
- **Stateless Session Management** — JWT (HS256) bearer tokens for all protected routes, with a parallel session table for visibility and revocation.
- **Behavioural Risk Engine** — every suspicious event (failed login, wrong OTP, decrypt abuse, multi-IP access, admin failure) is scored and aggregated into a rolling 24-hour risk score that drives automatic lockouts and email alerts.
- **Rate Limiting** — per-IP request throttling on every sensitive endpoint via SlowAPI.
- **ML-Based Password Strength Meter** — an SVM model classifies a candidate password as weak / medium / strong from five lexical features.
- **Admin Encrypted-DB Viewer** — OTP-gated endpoint that lets an administrator inspect ciphertext/nonce/KEM metadata across all vault tables without ever exposing plaintext.
- **Live PQC Benchmarking** — a `/pqc/metrics` endpoint that measures key generation, encryption, and decryption timings on every call (not hardcoded).

---

## System Architecture

```
                                ┌─────────────────────────┐
                                │   Static Frontend        │
                                │  (HTML / CSS / JS)       │
                                │  served from /static     │
                                └────────────┬─────────────┘
                                             │ HTTPS
                                             ▼
                    ┌───────────────────────────────────────────┐
                    │              FastAPI Application            │
                    │  (main.py)                                   │
                    │                                               │
                    │  Middleware: CORS, SlowAPIMiddleware          │
                    │  Exception Handler: RateLimitExceeded         │
                    └──────────────┬───────────────┬───────────────┘
                                   │               │
            ┌──────────────────────┼───────────────┼──────────────────────┐
            │                      │               │                      │
            ▼                      ▼               ▼                      ▼
   ┌─────────────────┐   ┌──────────────────┐ ┌──────────────────┐ ┌───────────────┐
   │   /auth router    │   │  /vault router    │ │ /security router │ │ /pqc, /health  │
   │  auth_routes.py   │   │  vault_routes.py  │ │ security_routes  │ │  metrics.py    │
   └─────────┬─────────┘   └─────────┬──────────┘ └────────┬─────────┘ └───────────────┘
             │                       │                      │
   ┌─────────▼─────────┐   ┌─────────▼──────────┐ ┌─────────▼─────────┐
   │ auth_utils.py      │   │ vault_utils.py      │ │ security_utils.py  │
   │ jwt_dependency.py   │   │ (hybrid encryption) │ │ session_utils.py   │
   │ otp_utils.py        │   │                      │ │ rate_limit.py      │
   │ email_utils.py      │   │                      │ │                    │
   └─────────┬─────────┘   └─────────┬──────────┘ └─────────┬─────────┘
             │                       │                      │
             │                       ▼                      │
             │           ┌──────────────────────┐           │
             │           │  Kyber Microservice    │           │
             │           │  (external HTTP API)   │           │
             │           │  /encapsulate           │           │
             │           │  /decapsulate           │           │
             │           └──────────────────────┘           │
             │                                                │
             └──────────────────────┬─────────────────────────┘
                                     ▼
                        ┌─────────────────────────┐
                        │   SQLite Database          │
                        │  (app/database.py: conn)   │
                        │                             │
                        │  users, otp_tokens,         │
                        │  notes, todos, passwords,    │
                        │  login_history,              │
                        │  user_sessions,               │
                        │  security_logs,                │
                        │  account_locks                  │
                        └─────────────────────────┘
```

**Design principle:** plaintext never crosses the boundary into the database layer. Every write to `notes`, `todos`, or `passwords` goes through `encrypt_text()`; every read that returns plaintext goes through `decrypt_text()`, and that decrypt path is itself rate-limited and abuse-monitored.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Web framework | FastAPI (ASGI, Python) |
| Server | Uvicorn |
| Database | SQLite (raw `sqlite3` connection, no ORM) |
| Post-quantum KEM | ML-KEM / CRYSTALS-Kyber-512 (external microservice) |
| Symmetric encryption | AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`) |
| Password hashing | Argon2id (`argon2-cffi`) |
| Session tokens | JWT / HS256 (`python-jose`) |
| Rate limiting | SlowAPI (`slowapi`) |
| Email delivery | Brevo Transactional Email HTTP API |
| Password strength ML | scikit-learn SVM, persisted with `joblib` |
| User-agent parsing | `user-agents` |
| Config | `python-dotenv` |
| HTTP client (internal) | `requests` |

---

## Project Structure

```
securevault-backend/
├── main.py                          # FastAPI app, middleware, routers, startup, warmup thread
├── app/
│   ├── config.py                    # Centralised env-var configuration
│   ├── database.py                  # SQLite connection object `conn` (referenced, not shown)
│   ├── models.py                    # create_tables() — users table (referenced, not shown)
│   ├── schemas.py                   # Pydantic models: SignupRequest, LoginRequest, TokenResponse
│   │
│   ├── auth/
│   │   ├── auth_routes.py           # /auth/* endpoints
│   │   ├── auth_utils.py            # hash_password, verify_password, create_jwt, get_current_user
│   │   ├── jwt_dependency.py        # Alternate Bearer-token get_current_user dependency
│   │   ├── otp_utils.py             # generate_otp, store_otp, verify_otp
│   │   └── email_utils.py           # send_email via Brevo API
│   │
│   ├── vault/
│   │   ├── vault_routes.py          # /vault/* endpoints (notes, todos, passwords, admin)
│   │   ├── vault_models.py          # create_vault_tables() + safe column migrations
│   │   └── vault_utils.py           # encrypt_text, decrypt_text, Kyber encapsulate/decapsulate
│   │
│   ├── security/
│   │   ├── security_routes.py       # /security/* endpoints (sessions, dashboard)
│   │   ├── security_models.py       # create_security_tables()
│   │   ├── security_utils.py        # risk scoring, account locks, failed-attempt counters
│   │   ├── session_utils.py         # session + login history CRUD
│   │   ├── rate_limit.py            # Limiter instance + named rate-limit strings
│   │   └── password_check_utils.py  # static password policy + common-password blocklist
│   │
│   ├── ml/
│   │   ├── password_strength_model.py  # SVM inference wrapper
│   │   └── password_strength_svm.pkl   # pre-trained model artifact (binary, not in repo listing)
│   │
│   └── pqc/
│       ├── kyber.py                 # simulated_kyber_key_exchange, encrypt_data (legacy/alt path)
│       └── metrics.py                # get_pqc_metrics() — live benchmark for /pqc/metrics
│
└── static/                          # index.html, signup.html, otp.html, dashboard.html,
                                      # notes.html, todos.html, passwords.html, pqc.html,
                                      # css/style.css, js/*.js
```

> **Note on `app/database.py` and `app/models.py`:** these two modules are imported throughout the codebase (`from app.database import conn`, `from app.models import create_tables`) but were not part of the supplied source files. `database.py` is expected to expose a module-level `conn` (a `sqlite3.Connection`, presumably created with `check_same_thread=False` since it is shared across request threads), and `models.py` is expected to expose `create_tables()` which creates the `users` table consumed by `auth_routes.py` (`email`, `password_hash`, `is_verified`).

> **Note on duplication:** `app/auth/auth_utils.py` and `app/auth/jwt_dependency.py` both implement a `get_current_user` dependency, but with **different extraction mechanisms** — `auth_utils.py` uses `OAuth2PasswordBearer`, while `jwt_dependency.py` uses `HTTPBearer`. `vault_routes.py` and `auth_routes.py` import `get_current_user` from `app.auth.auth_utils`, while `security_routes.py` imports it from `app.auth.jwt_dependency`. Both ultimately validate the same JWT shape (`{"sub": email, "exp": ...}`) signed with the same `JWT_SECRET`, so they are functionally interchangeable from the client's perspective (a Bearer token works against both), but this is a duplication worth consolidating.

---

## Core Concepts

### Hybrid Encryption Model

Every encryption operation follows the same two-stage pipeline, implemented in `app/vault/vault_utils.py`:

**1. Key establishment (ML-KEM or backup):**

```
encrypt_text(plaintext):
    nonce = random 12 bytes
    (kem_ciphertext, aes_key) = _encapsulate()      # POST {KYBER_SERVICE_URL}/encapsulate
    if aes_key exists:
        encryption_type = "ML-KEM"
    else:
        encryption_type = "BACKUP"
        aes_key = SHA-256(SECUREVAULT_AES_KEY env var or default string)
        kem_ciphertext = null
```

**2. Symmetric encryption (always AES-256-GCM):**

```
    ciphertext = AES-256-GCM.Encrypt(aes_key, nonce, plaintext, aad=None)
    return { ciphertext (b64), nonce (b64), kem_ciphertext (b64|null), encryption_type }
```

Decryption (`decrypt_text`) is the mirror image: if `encryption_type == "ML-KEM"`, the AES key is recovered by `POST {KYBER_SERVICE_URL}/decapsulate` with the stored `kem_ciphertext`; if `encryption_type == "BACKUP"`, the same SHA-256-derived backup key is recomputed locally.

**Stored per record:** `ciphertext`, `nonce`, `kem_ciphertext` (nullable), `encryption_type` (`"ML-KEM"` or `"BACKUP"`), `created_at`, and the owning `user_email`. The plaintext itself is never persisted, never logged, and never present in any table.

There is also a second, independent PQC code path in `app/pqc/kyber.py` (`simulated_kyber_key_exchange` + `encrypt_data`) which fetches a shared secret from a GET endpoint at `KYBER_SERVICE_URL` directly (rather than the POST `/encapsulate` used by `vault_utils.py`) and derives an AES key via `SHA-256(shared_secret)`. This module is not wired into any router in the supplied code and appears to be a legacy/alternate implementation kept alongside `vault_utils.py`; `vault_utils.py` is the one actually used by `vault_routes.py`.

### Authentication Flow

SecureVault uses a **three-step authentication sequence**: password → OTP → JWT.

1. **Signup** (`POST /auth/signup`) — password policy validated (`password_check_utils.get_password_warning`), Argon2 hash stored, account created with `is_verified = 0`, OTP generated and emailed.
2. **Verify signup OTP** (`POST /auth/verify-signup-otp`) — OTP checked against `otp_tokens`; on success, `is_verified` flips to `1`.
3. **Login step 1** (`POST /auth/login`) — Argon2 password check; on success, a fresh OTP is generated and emailed (this is the 2FA step). Login does **not** issue a JWT yet.
4. **Login step 2** (`POST /auth/login-otp`) — OTP verified; only then is the JWT created (`create_jwt`), a session row inserted (`create_session`), login history recorded, and a "new login" notification email sent. If the user has been seen from ≥3 distinct IPs in the last hour, a `multiple_ips` security event is also logged and a warning email sent.
5. **Every subsequent request** to a protected route presents the JWT as `Authorization: Bearer <token>`, validated by `get_current_user` (in either `auth_utils.py` or `jwt_dependency.py`), which decodes the token with `JWT_SECRET` and extracts the `sub` (email) claim.

Password reset follows the same password→OTP pattern but without a pre-existing valid password: `POST /auth/reset-password` sends an OTP unconditionally for the given email, and `POST /auth/reset-password-confirm` validates the OTP and the new password policy before updating the Argon2 hash.

### Risk Scoring Engine

Implemented in `app/security/security_utils.py`. Every meaningful security-relevant event is written to `security_logs` with a fixed point value:

| Event Type | Risk Score | Raised By |
|---|---|---|
| `failed_login` | 10 | `auth_routes.login()` on bad password |
| `wrong_otp` | 15 | any OTP verification failure (`auth_routes.py`) |
| `too_many_requests` | 20 | reserved for rate-limit-driven scoring |
| `decrypt_abuse` | 25 | every call to `/vault/*/decrypted` (logged as `info`, see note below) |
| `multiple_ips` | 20 | `auth_routes.login_otp()` when ≥3 distinct IPs seen in 1 hour |
| `admin_failure` | 40 | wrong admin credentials or wrong admin OTP (`vault_routes.py`) |

> Note: `decrypt_abuse` is logged on **every successful** decrypt call (status `"info"`), not only on abuse — it is used as a frequency counter so that `get_failed_attempts(user, "decrypt_abuse", 10)` can detect bursts within a 10-minute window, separately from the `risk_score` total contributed to the 24-hour rolling sum.

The cumulative score over the trailing 24 hours determines a `risk_level`:

```
score ≥ 80  →  critical
score ≥ 50  →  high
score ≥ 25  →  medium
score <  25 →  low
```

This score and level are surfaced via `GET /security/dashboard`. Independently, **specific event counters** within shorter windows trigger hard lockouts via `is_account_locked` / `lock_account`:

| Lock Type | Trigger | Window Checked | Lock Duration |
|---|---|---|---|
| `login` | ≥5 `failed_login` events | 30 min | 10 min (`LOGIN_LOCK_MINUTES`) |
| `otp` | ≥3 `wrong_otp` events | 30 min | 5 min (`OTP_LOCK_MINUTES`) |
| `admin` | ≥2 `admin_failure` events | 60 min | 15 min (`ADMIN_LOCK_MINUTES`) |
| `decrypt` | ≥10 `decrypt_abuse` events | 10 min | 5 min (`DECRYPT_LOCK_MINUTES`) |

Email alerts are sent at intermediate thresholds too (e.g. a warning email after 3 failed logins, before the lock fires at 5).

### Rate Limiting

Defined centrally in `app/security/rate_limit.py` using SlowAPI's IP-keyed `Limiter`:

| Limit Name | Value | Applied To |
|---|---|---|
| `GLOBAL_LIMIT` | 100/minute | (defined, not seen applied to a specific route in supplied code) |
| `HEALTH_LIMIT` | 30/minute | `GET /health` |
| `SIGNUP_LIMIT` | 3/minute | `POST /auth/signup` |
| `LOGIN_LIMIT` | 5/minute | `POST /auth/login` |
| `OTP_LIMIT` | 5/minute | `/auth/verify-signup-otp`, `/auth/login-otp`, `/auth/reset-password-confirm` |
| `RESET_PASSWORD_LIMIT` | 2/minute | `POST /auth/reset-password` |
| `DECRYPT_LIMIT` | 8/minute | all three `*/decrypted` vault endpoints |
| `PASSWORD_STRENGTH_LIMIT` | 10/minute | `POST /vault/password-strength` |
| `ADMIN_LIMIT` | 2/minute | `/vault/admin/request-otp`, `/vault/admin/encrypted-db` |

Limits are IP-based (`get_remote_address`), so all users behind the same NAT/IP share a budget. Breaching a limit returns **HTTP 429**, handled globally by `_rate_limit_exceeded_handler` registered in `main.py`.

---

## Database Schema (ERD Reference)

Nine tables across three creation modules: `app/models.py::create_tables()` (users — referenced but not in supplied files), `app/vault/vault_models.py::create_vault_tables()`, and `app/security/security_models.py::create_security_tables()`. All are created idempotently on startup (`CREATE TABLE IF NOT EXISTS`), with `vault_models.py` additionally running a safe `ALTER TABLE ... ADD COLUMN` migration helper for `kem_ciphertext` and `encryption_type` so older databases self-upgrade.

### `users` *(inferred from usage in `auth_routes.py`; defined in `app/models.py`, not supplied)*
| Column | Type | Notes |
|---|---|---|
| `email` | TEXT | primary identifier, used as FK target conceptually for every other table's `email`/`user_email` column |
| `password_hash` | TEXT | Argon2id hash |
| `is_verified` | INTEGER (bool) | 0 until signup OTP confirmed |

### `otp_tokens`
| Column | Type | Notes |
|---|---|---|
| `email` | TEXT | one active OTP per email (old rows deleted before insert) |
| `otp` | TEXT | 6-digit numeric string |
| `expiry` | TEXT (ISO datetime) | `OTP_EXP_MINUTES` (default 5) from issuance |

### `notes`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `user_email` | TEXT NOT NULL | owner |
| `title` | TEXT | |
| `ciphertext` | TEXT NOT NULL | base64 AES-GCM output |
| `nonce` | TEXT NOT NULL | base64, 12 bytes |
| `kem_ciphertext` | TEXT | nullable; base64 ML-KEM ciphertext |
| `encryption_type` | TEXT DEFAULT 'BACKUP' | `'ML-KEM'` or `'BACKUP'` |
| `created_at` | TIMESTAMP DEFAULT CURRENT_TIMESTAMP | |

### `todos`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `user_email` | TEXT NOT NULL | owner |
| `ciphertext` | TEXT NOT NULL | encrypted task text |
| `nonce` | TEXT NOT NULL | |
| `completed` | INTEGER DEFAULT 0 | present in schema; no route currently toggles it |
| `kem_ciphertext` | TEXT | nullable |
| `encryption_type` | TEXT DEFAULT 'BACKUP' | |
| `created_at` | TIMESTAMP DEFAULT CURRENT_TIMESTAMP | |

### `passwords`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `user_email` | TEXT NOT NULL | owner |
| `site` | TEXT NOT NULL | e.g. "github.com" |
| `username` | TEXT NOT NULL | stored in **plaintext** (only the password value is encrypted) |
| `ciphertext` | TEXT NOT NULL | encrypted password |
| `nonce` | TEXT NOT NULL | |
| `kem_ciphertext` | TEXT | nullable |
| `encryption_type` | TEXT DEFAULT 'BACKUP' | |
| `created_at` | TIMESTAMP DEFAULT CURRENT_TIMESTAMP | |

### `login_history`
| Column | Type | Notes |
|---|---|---|
| `id` | INTEGE
