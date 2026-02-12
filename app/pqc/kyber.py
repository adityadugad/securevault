import os
import time
import base64
import hashlib
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ======================================================
# CONFIG
# ======================================================

KYBER_SERVICE_URL = os.environ.get(
    "KYBER_SERVICE_URL",
    "https://your-kyber-service.onrender.com/kyber"
)

BACKUP_SECRET = os.environ.get(
    "KYBER_BACKUP_SECRET",
    "securevault-backup-secret"
).encode()


# ======================================================
# REAL KYBER (REPLACES SIMULATION)
# ======================================================

def simulated_kyber_key_exchange():
    """
    Same function name.
    Same return format.
    But now uses real Kyber service.
    """

    metrics = {}

    start = time.perf_counter()

    try:
        response = requests.get(KYBER_SERVICE_URL, timeout=5)

        if response.status_code != 200:
            raise Exception("Non-200 response")

        data = response.json()

        shared_secret_b64 = data.get("shared_secret_b64")
        if not shared_secret_b64:
            raise Exception("Missing shared_secret_b64")

        shared_secret = base64.b64decode(shared_secret_b64)

        metrics["kyber_source"] = "external_service"

    except Exception as e:
        # Fallback to backup key
        shared_secret = hashlib.sha256(BACKUP_SECRET).digest()
        metrics["kyber_source"] = "backup_key"
        metrics["error"] = str(e)

    metrics["shared_secret_size"] = len(shared_secret)
    metrics["fetch_time_ms"] = (time.perf_counter() - start) * 1000

    return shared_secret, metrics


# ======================================================
# AES KEY DERIVATION (UNCHANGED)
# ======================================================

def derive_aes_key(shared_secret: bytes) -> bytes:
    return hashlib.sha256(shared_secret).digest()


# ======================================================
# ENCRYPTION (UNCHANGED)
# ======================================================

def encrypt_data(data: bytes):
    shared_secret, metrics = simulated_kyber_key_exchange()
    aes_key = derive_aes_key(shared_secret)

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "metrics": metrics
    }
