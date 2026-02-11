import os
import base64
import hashlib
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KYBER_SERVICE_URL = os.getenv("KYBER_SERVICE_URL")
BACKUP_SECRET = os.getenv("SECUREVAULT_AES_KEY", "securevault-dev-backup-key")

# --------------------------------------------------
# BACKUP AES KEY (DERIVED ONCE)
# --------------------------------------------------

BACKUP_AES_KEY = hashlib.sha256(BACKUP_SECRET.encode()).digest()


# --------------------------------------------------
# ENCAPSULATE (GET AES KEY + KEM CIPHERTEXT FROM KYBER)
# --------------------------------------------------

def _encapsulate():
    if not KYBER_SERVICE_URL:
        return None, None

    try:
        res = requests.post(
            f"{KYBER_SERVICE_URL}/encapsulate",
            timeout=5
        )

        if res.ok:
            data = res.json()
            kem_ciphertext = data.get("kem_ciphertext_b64")
            aes_key_b64 = data.get("aes_key_b64")

            if kem_ciphertext and aes_key_b64:
                aes_key = base64.b64decode(aes_key_b64)
                return kem_ciphertext, aes_key

    except Exception:
        pass

    return None, None


# --------------------------------------------------
# DECAPSULATE AES KEY
# --------------------------------------------------

def _decapsulate(kem_ciphertext_b64: str):
    if not KYBER_SERVICE_URL:
        raise RuntimeError("Kyber service not configured")

    res = requests.post(
        f"{KYBER_SERVICE_URL}/decapsulate",
        json={"kem_ciphertext_b64": kem_ciphertext_b64},
        timeout=5
    )

    if not res.ok:
        raise RuntimeError("Decapsulation failed")

    data = res.json()
    aes_key_b64 = data.get("aes_key_b64")

    if not aes_key_b64:
        raise RuntimeError("Invalid decapsulation response")

    return base64.b64decode(aes_key_b64)


# --------------------------------------------------
# ENCRYPT (HYBRID MODEL)
# --------------------------------------------------

def encrypt_text(plaintext: str) -> dict:
    nonce = os.urandom(12)

    # Try ML-KEM encapsulation first
    kem_ciphertext_b64, aes_key = _encapsulate()

    if aes_key:
        encryption_type = "ML-KEM"
    else:
        # Fallback to BACKUP mode
        encryption_type = "BACKUP"
        aes_key = BACKUP_AES_KEY
        kem_ciphertext_b64 = None

    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "kem_ciphertext": kem_ciphertext_b64,
        "encryption_type": encryption_type
    }


# --------------------------------------------------
# DECRYPT (HYBRID MODEL)
# --------------------------------------------------

def decrypt_text(ciphertext_b64: str,
                 nonce_b64: str,
                 encryption_type: str,
                 kem_ciphertext_b64: str = None) -> str:

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)

    if encryption_type == "ML-KEM":
        aes_key = _decapsulate(kem_ciphertext_b64)

    elif encryption_type == "BACKUP":
        aes_key = BACKUP_AES_KEY

    else:
        raise RuntimeError("Unknown encryption type")

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")
