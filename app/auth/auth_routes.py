```python
from fastapi import APIRouter, HTTPException, status, Depends, Request
from app.database import conn
from app.schemas import SignupRequest, LoginRequest, TokenResponse
from app.auth.auth_utils import hash_password, verify_password, create_jwt
from app.auth.jwt_dependency import get_current_user
from app.auth.email_utils import send_email
from app.auth.otp_utils import generate_otp, store_otp, verify_otp

from app.security.rate_limit import (
    limiter,
    SIGNUP_LIMIT,
    LOGIN_LIMIT,
    OTP_LIMIT,
    RESET_PASSWORD_LIMIT,
)

from app.security.security_utils import (
    log_security_event,
    get_failed_attempts,
    lock_account,
    is_account_locked,
    reset_failed_attempts,
    check_multiple_ips,
)

from app.security.session_utils import (
    create_session,
    record_login_history,
)

from app.security.password_check_utils import get_password_warning

auth_router = APIRouter(tags=["Authentication"])

# ---------- SIGNUP (SEND OTP) ----------
@auth_router.post("/signup")
@limiter.limit(SIGNUP_LIMIT)
def signup(request: Request, data: SignupRequest):
    password_warning = get_password_warning(data.password)

    if password_warning:
        raise HTTPException(status_code=400, detail=password_warning)

    cur = conn.cursor()
    hashed = hash_password(data.password)

    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, is_verified) VALUES (?, ?, 0)",
            (data.email, hashed)
        )
        conn.commit()
    except:
        raise HTTPException(status_code=400, detail="User already exists")

    otp = generate_otp()
    store_otp(data.email, otp)

    send_email(
        data.email,
        "SecureVault Signup OTP",
        f"Your OTP is {otp}. It expires in 5 minutes."
    )

    return {"message": "OTP sent to email for verification"}

# ---------- VERIFY SIGNUP OTP ----------
@auth_router.post("/verify-signup-otp")
@limiter.limit(OTP_LIMIT)
def verify_signup_otp(request: Request, email: str, otp: str):
    if is_account_locked(email, "otp"):
        raise HTTPException(
            status_code=403,
            detail="Too many wrong OTP attempts. Try again later."
        )

    if not verify_otp(email, otp):
        log_security_event(
            email=email,
            ip_address=request.client.host,
            endpoint="/auth/verify-signup-otp",
            event_type="wrong_otp",
            status="failed"
        )

        failed_otps = get_failed_attempts(email, "wrong_otp", 30)

        if failed_otps >= 3:
            lock_account(email, "otp", 5)

            try:
                send_email(
                    email,
                    "SecureVault OTP Locked",
                    "Too many wrong OTP attempts were detected. OTP verification is temporarily locked."
                )
            except:
                pass

        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    reset_failed_attempts(email, "wrong_otp")

    cur = conn.cursor()
    cur.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
    conn.commit()

    return {"message": "Account verified successfully"}

# ---------- LOGIN (SEND 2FA OTP) ----------
@auth_router.post("/login")
@limiter.limit(LOGIN_LIMIT)
def login(request: Request, data: LoginRequest):
    if is_account_locked(data.email, "login"):
        raise HTTPException(
            status_code=403,
            detail="Too many failed logins. Account locked for 10 minutes."
        )

    cur = conn.cursor()
    cur.execute(
        "SELECT password_hash, is_verified FROM users WHERE email = ?",
        (data.email,)
    )
    user = cur.fetchone()

    if not user or not verify_password(user[0], data.password):
        log_security_event(
            email=data.email,
            ip_address=request.client.host,
            endpoint="/auth/login",
            event_type="failed_login",
            status="failed"
        )

        record_login_history(
            email=data.email,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
            success=False
        )

        failed_logins = get_failed_attempts(data.email, "failed_login", 30)

        if failed_logins >= 3:
            try:
                send_email(
                    data.email,
                    "SecureVault Security Alert",
                    "Multiple failed login attempts were detected on your account."
                )
            except:
                pass

        if failed_logins >= 5:
            lock_account(data.email, "login", 10)

            try:
                send_email(
                    data.email,
                    "SecureVault Account Locked",
                    "Too many failed login attempts were detected. Login is temporarily locked."
                )
            except:
                pass

        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user[1]:
        raise HTTPException(status_code=403, detail="Email not verified")

    otp = generate_otp()
    store_otp(data.email, otp)

    send_email(
        data.email,
        "SecureVault Login OTP",
        f"Your login OTP is {otp}. It expires in 5 minutes."
    )

    return {"message": "2FA OTP sent to email"}

# ---------- VERIFY LOGIN OTP (ISSUE JWT) ----------
@auth_router.post("/login-otp", response_model=TokenResponse)
@limiter.limit(OTP_LIMIT)
def login_otp(request: Request, email: str, otp: str):
    if is_account_locked(email, "otp"):
        raise HTTPException(
            status_code=403,
            detail="Too many wrong OTP attempts. Try again later."
        )

    if not verify_otp(email, otp):
        log_security_event(
            email=email,
            ip_address=request.client.host,
            endpoint="/auth/login-otp",
            event_type="wrong_otp",
            status="failed"
        )

        failed_otps = get_failed_attempts(email, "wrong_otp", 30)

        if failed_otps >= 3:
            lock_account(email, "otp", 5)

            try:
                send_email(
                    email,
                    "SecureVault OTP Locked",
                    "Too many wrong OTP attempts were detected. OTP verification is temporarily locked."
                )
            except:
                pass

        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    token = create_jwt(email)

    reset_failed_attempts(email, "failed_login")
    reset_failed_attempts(email, "wrong_otp")

    record_login_history(
        email=email,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", ""),
        success=True
    )

    create_session(
        email=email,
        jwt_token=token,
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", "")
    )

    if check_multiple_ips(email):
        log_security_event(
            email=email,
            ip_address=request.client.host,
            endpoint="/auth/login-otp",
            event_type="multiple_ips",
            status="warning"
        )

        try:
            send_email(
                email,
                "SecureVault Security Warning",
                "Your account was accessed from multiple IP addresses recently."
            )
        except:
            pass

    try:
        send_email(
            email,
            "SecureVault New Login",
            f"New login detected from IP: {request.client.host}"
        )
    except:
        pass

    return {"access_token": token}

# ---------- PASSWORD RESET (SEND OTP) ----------
@auth_router.post("/reset-password")
@limiter.limit(RESET_PASSWORD_LIMIT)
def reset_password(request: Request, email: str):
    otp = generate_otp()
    store_otp(email, otp)

    send_email(
        email,
        "SecureVault Password Reset OTP",
        f"Your password reset OTP is {otp}. It expires in 5 minutes."
    )

    return {"message": "Password reset OTP sent"}

# ---------- CONFIRM PASSWORD RESET ----------
@auth_router.post("/reset-password-confirm")
@limiter.limit(OTP_LIMIT)
def reset_password_confirm(
    request: Request,
    email: str,
    otp: str,
    new_password: str
):
    password_warning = get_password_warning(new_password)

    if password_warning:
        raise HTTPException(status_code=400, detail=password_warning)

    if is_account_locked(email, "otp"):
        raise HTTPException(
            status_code=403,
            detail="Too many wrong OTP attempts. Try again later."
        )

    if not verify_otp(email, otp):
        log_security_event(
            email=email,
            ip_address=request.client.host,
            endpoint="/auth/reset-password-confirm",
            event_type="wrong_otp",
            status="failed"
        )

        failed_otps = get_failed_attempts(email, "wrong_otp", 30)

        if failed_otps >= 3:
            lock_account(email, "otp", 5)

            try:
                send_email(
                    email,
                    "SecureVault OTP Locked",
                    "Too many wrong OTP attempts were detected. OTP verification is temporarily locked."
                )
            except:
                pass

        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    hashed = hash_password(new_password)

    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (hashed, email)
    )
    conn.commit()

    reset_failed_attempts(email, "wrong_otp")

    send_email(
        email,
        "SecureVault Password Changed",
        "Your password was changed successfully. If this was not you, please secure your account immediately."
    )

    return {"message": "Password updated successfully"}

# ---------- PROTECTED TEST ----------
@auth_router.get("/me")
def read_current_user(current_user: str = Depends(get_current_user)):
    return {
        "email": current_user,
        "message": "JWT authentication successful"
    }
```
