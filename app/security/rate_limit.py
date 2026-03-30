from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# =========================================================
# RATE LIMIT RULES
# =========================================================

SIGNUP_LIMIT = "5/minute"
LOGIN_LIMIT = "5/minute"
OTP_LIMIT = "5/minute"
RESET_PASSWORD_LIMIT = "3/minute"
DECRYPT_LIMIT = "10/minute"
ADMIN_LIMIT = "2/minute"
PASSWORD_STRENGTH_LIMIT = "20/minute"