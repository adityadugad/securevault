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
# FETCH PUBLIC KEY FROM KYBER SERVICE
# --------------------------------------------------

def _fetch_public_key():
    if not KYBER_SERVICE_URL:
        return None

    try:
        res = requests.get(f"{KYBER_SERVICE_URL}/public-key", timeout=5)
        if res.ok:
            data = res.json()
            return base64.b64decode(data.get("public_key_b64"))
    except Exception:
        pass

    return None


# --------------------------------------------------
# ENCAPSULATE AES KEY USING ML-KEM
# --------------------------------------------------

def _encapsulate_aes_key(aes_key: bytes):
    if not KYBER_SERVICE_URL:
        return None

    try:
        res = requests.post(
            f"{KYBER_SERVICE_URL}/encapsulate",
            json={"aes_key_b64": base64.b64encode(aes_key).decode()},
            timeout=5
        )
        if res.ok:
            data = res.json()
            return data.get("kem_ciphertext_b64")
    except Exception:
        pass

    return None


# --------------------------------------------------
# DECAPSULATE AES KEY USING ML-KEM
# --------------------------------------------------

def _decapsulate_aes_key(kem_ciphertext_b64: str):
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
    return base64.b64decode(data.get("aes_key_b64"))


# --------------------------------------------------
# ENCRYPT (HYBRID MODEL)
# --------------------------------------------------

def encrypt_text(plaintext: str) -> dict:
    nonce = os.urandom(12)

    # Generate random AES-256 key per item
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    # Try ML-KEM encapsulation
    kem_ciphertext_b64 = _encapsulate_aes_key(aes_key)

    if kem_ciphertext_b64:
        encryption_type = "ML-KEM"
    else:
        # Fallback to BACKUP mode
        encryption_type = "BACKUP"
        aes_key = BACKUP_AES_KEY
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            None
        )
        kem_ciphertext_b64 = None

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "kem_ciphertext": kem_ciphertext_b64,
        "encryption_type": encryption_type
    }


# --------------------------------------------------
# DECRYPT (HYBRID MODEL)
# --------------------------------------------------

def decrypt_text(ciphertext_b64: str, nonce_b64: str,
                 encryption_type: str,
                 kem_ciphertext_b64: str = None) -> str:

    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)

    if encryption_type == "ML-KEM":
        aes_key = _decapsulate_aes_key(kem_ciphertext_b64)

    elif encryption_type == "BACKUP":
        aes_key = BACKUP_AES_KEY

    else:
        raise RuntimeError("Unknown encryption type")

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")
