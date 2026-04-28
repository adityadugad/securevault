from argon2 import PasswordHasher
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import os


# ======================================================
# ENV-SAFE CONFIG (RENDER + LOCAL)
# ======================================================

JWT_SECRET = os.environ.get("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET environment variable is required"
    )

JWT_EXP_MINUTES = int(
    os.environ.get("JWT_EXP_MINUTES", 60)
)


# ======================================================
# INIT
# ======================================================

ph = PasswordHasher()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login"
)


# ======================================================
# PASSWORD UTILS
# ======================================================

def hash_password(password: str) -> str:
    """
    Hash password using Argon2
    """
    return ph.hash(password)


def verify_password(
    password_hash: str,
    password: str
) -> bool:
    """
    Safely verify password using Argon2

    IMPORTANT FIX:
    Argon2 can raise exceptions like:
    - VerifyMismatchError
    - VerificationError
    - InvalidHash

    Without try/except:
    wrong password can crash login route,
    causing:
    - Network error on frontend
    - failed attempts not counted
    - account lock never triggered

    With this fix:
    wrong password safely returns False
    and account lock works correctly.
    """

    try:
        return ph.verify(
            password_hash,
            password
        )

    except Exception:
        return False


# ======================================================
# JWT UTILS
# ======================================================

def create_jwt(email: str) -> str:
    """
    Create JWT token for authenticated user
    """

    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(
            minutes=JWT_EXP_MINUTES
        )
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )


def get_current_user(
    token: str = Depends(oauth2_scheme)
) -> str:
    """
    Decode JWT and return current user email
    """

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        email: str = payload.get("sub")

        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )

        return email

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired or invalid",
        )
