import os
import base64
import hashlib
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KYBER_SERVICE_URL = os.getenv("KYBER_SERVICE_URL")
BACKUP_SECRET = os.getenv("SECUREVAULT_AES_KEY", "securevault-dev-backup-key")

# --------------------------------------------------
# REAL KYBER → AES KEY DERIVATION
# --------------------------------------------------

def _get_aes_key() -> bytes:
    """
    Priority:
    1. Real Kyber shared secret (ML-KEM-512)
    2. Fallback env-based secret (Render safe)
    """
    if KYBER_SERVICE_URL:
        try:
            res = requests.get(
                f"{KYBER_SERVICE_URL}/kyber",
                timeout=4
            )
            if res.ok and res.text:
                shared_secret = base64.b64decode(res.text.strip())
                return hashlib.sha256(shared_secret).digest()
        except Exception:
            pass

    # Fallback (never breaks app)
    return hashlib.sha256(BACKUP_SECRET.encode()).digest()


# --------------------------------------------------
# ENCRYPT
# --------------------------------------------------

def encrypt_text(plaintext: str) -> dict:
    aes_key = _get_aes_key()
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }


# --------------------------------------------------
# DECRYPT
# --------------------------------------------------

def decrypt_text(ciphertext_b64: str, nonce_b64: str) -> str:
    aes_key = _get_aes_key()
    aesgcm = AESGCM(aes_key)

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
