from fastapi import APIRouter, HTTPException, status, Depends
from app.database import conn
from app.schemas import SignupRequest, LoginRequest, TokenResponse
from app.auth.auth_utils import hash_password, verify_password, create_jwt
from app.auth.jwt_dependency import get_current_user
from app.auth.email_utils import send_email
from app.auth.otp_utils import generate_otp, store_otp, verify_otp

auth_router = APIRouter(tags=["Authentication"])

# ---------- SIGNUP (SEND OTP) ----------
@auth_router.post("/signup")
def signup(data: SignupRequest):
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
def verify_signup_otp(email: str, otp: str):
    if not verify_otp(email, otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    cur = conn.cursor()
    cur.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
    conn.commit()
    return {"message": "Account verified successfully"}

# ---------- LOGIN (SEND 2FA OTP) ----------
@auth_router.post("/login")
def login(data: LoginRequest):
    cur = conn.cursor()
    cur.execute(
        "SELECT password_hash, is_verified FROM users WHERE email = ?",
        (data.email,)
    )
    user = cur.fetchone()

    if not user or not verify_password(user[0], data.password):
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
def login_otp(email: str, otp: str):
    if not verify_otp(email, otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    token = create_jwt(email)
    return {"access_token": token}

# ---------- PASSWORD RESET (SEND OTP) ----------
@auth_router.post("/reset-password")
def reset_password(email: str):
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
def reset_password_confirm(email: str, otp: str, new_password: str):
    if not verify_otp(email, otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    hashed = hash_password(new_password)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (hashed, email)
    )
    conn.commit()
    return {"message": "Password updated successfully"}

# ---------- PROTECTED TEST ----------
@auth_router.get("/me")
def read_current_user(current_user: str = Depends(get_current_user)):
    return {"email": current_user, "message": "JWT authentication successful"}
