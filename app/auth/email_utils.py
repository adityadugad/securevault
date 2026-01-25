import os
import requests
from dotenv import load_dotenv

load_dotenv()

# ======================================================
# BREVO CONFIG (HTTP API ONLY)
# ======================================================

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL")  # e.g. "no-reply@brevo.email"

# NOTE: This is NOT SMTP. This is HTTP REST endpoint.
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


# ======================================================
# SEND EMAIL (SAFE FOR RENDER & PRODUCTION)
# ======================================================

def send_email(to_email: str, subject: str, body: str):
    if not BREVO_API_KEY or not FROM_EMAIL:
        raise RuntimeError("Brevo environment variables not set (BREVO_API_KEY or FROM_EMAIL missing)")

    payload = {
        "sender": {
            "name": "SecureVault",
            "email": FROM_EMAIL
        },
        "to": [
            {"email": to_email}
        ],
        "subject": subject,
        "htmlContent": f"<html><body><p>{body}</p></body></html>"
    }

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    try:
        response = requests.post(
            BREVO_API_URL,
            json=payload,
            headers=headers,
            timeout=10
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Network error while sending email: {str(e)}")

    # Successful responses are 200/201/202
    if response.status_code not in (200, 201, 202):
        raise RuntimeError(
            f"Failed to send email via Brevo: {response.status_code} - {response.text}"
        )
