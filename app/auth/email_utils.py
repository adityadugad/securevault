import os
import requests
from dotenv import load_dotenv

load_dotenv()

# ======================================================
# RESEND CONFIG
# ======================================================

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL")  # e.g. "SecureVault <onboarding@resend.dev>"

RESEND_API_URL = "https://api.resend.com/emails"


# ======================================================
# SEND EMAIL (RENDER SAFE)
# ======================================================

def send_email(to_email: str, subject: str, body: str):
    if not RESEND_API_KEY or not FROM_EMAIL:
        raise RuntimeError("Resend environment variables not set")

    payload = {
        "from": FROM_EMAIL,
        "to": [to_email],
        "subject": subject,
        "text": body
    }

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.post(
        RESEND_API_URL,
        json=payload,
        headers=headers,
        timeout=10
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Failed to send email via Resend: {response.status_code} - {response.text}"
        )
