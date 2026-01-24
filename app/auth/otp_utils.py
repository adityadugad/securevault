import random
from datetime import datetime, timedelta
from app.database import conn
import os
from dotenv import load_dotenv

load_dotenv()
OTP_EXP_MINUTES = int(os.getenv("OTP_EXP_MINUTES", 5))

def generate_otp() -> str:
    return str(random.randint(100000, 999999))

def store_otp(email: str, otp: str):
    expiry = (datetime.utcnow() + timedelta(minutes=OTP_EXP_MINUTES)).isoformat()
    cur = conn.cursor()
    cur.execute("DELETE FROM otp_tokens WHERE email = ?", (email,))
    cur.execute(
        "INSERT INTO otp_tokens (email, otp, expiry) VALUES (?, ?, ?)",
        (email, otp, expiry)
    )
    conn.commit()

def verify_otp(email: str, otp: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        "SELECT otp, expiry FROM otp_tokens WHERE email = ?",
        (email,)
    )
    row = cur.fetchone()
    if not row:
        return False

    saved_otp, expiry = row
    if saved_otp != otp:
        return False

    if datetime.utcnow() > datetime.fromisoformat(expiry):
        return False

    # cleanup after success
    cur.execute("DELETE FROM otp_tokens WHERE email = ?", (email,))
    conn.commit()
    return True
