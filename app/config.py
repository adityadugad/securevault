import os
from dotenv import load_dotenv

load_dotenv()

# ======================================================
# JWT CONFIG
# ======================================================

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", 15))

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set in environment variables")

# ======================================================
# KYBER SERVICE
# ======================================================

KYBER_SERVICE_URL = os.getenv("KYBER_SERVICE_URL", "")

# ======================================================
# ADMIN CONFIG
# ======================================================

ADMIN_ID = "admin"
ADMIN_PASS = "secure123"
ADMIN_EMAIL = "adityadugad@gmail.com"
# ======================================================
# FRONTEND / CORS
# ======================================================

FRONTEND_URL = os.getenv("FRONTEND_URL", "*")

# ======================================================
# SECURITY LIMITS
# ======================================================

MAX_FAILED_LOGIN_ATTEMPTS = int(
    os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", 5)
)

MAX_WRONG_OTP_ATTEMPTS = int(
    os.getenv("MAX_WRONG_OTP_ATTEMPTS", 3)
)

LOGIN_LOCK_MINUTES = int(
    os.getenv("LOGIN_LOCK_MINUTES", 10)
)

OTP_LOCK_MINUTES = int(
    os.getenv("OTP_LOCK_MINUTES", 5)
)

ADMIN_LOCK_MINUTES = int(
    os.getenv("ADMIN_LOCK_MINUTES", 15)
)

DECRYPT_LOCK_MINUTES = int(
    os.getenv("DECRYPT_LOCK_MINUTES", 5)
)
