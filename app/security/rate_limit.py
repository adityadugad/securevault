from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# =========================================================
# GLOBAL LIMITS
# =========================================================

GLOBAL_LIMIT = "100/minute"
HEALTH_LIMIT = "30/minute"

# =========================================================
# AUTH LIMITS
# =========================================================

SIGNUP_LIMIT = "3/minute"
LOGIN_LIMIT = "5/minute"
OTP_LIMIT = "5/minute"
RESET_PASSWORD_LIMIT = "2/minute"

# =========================================================
# VAULT LIMITS
# =========================================================

DECRYPT_LIMIT = "8/minute"
PASSWORD_STRENGTH_LIMIT = "10/minute"

# =========================================================
# ADMIN LIMITS
# =========================================================

ADMIN_LIMIT = "2/minute"
