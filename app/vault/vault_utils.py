from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import hashlib

# ======================================================
# AES CONFIG (RENDER + LOCAL SAFE)
# ======================================================
# Render env vars are STRINGS
# We derive a stable 32-byte AES-256 key using SHA-256

def _derive_aes_key() -> bytes:
    secret = os.environ.get(
        "SECUREVAULT_AES_KEY",
        "securevault-dev-key-change-this"
    )

    # Ensure string → bytes
    if not isinstance(secret, str):
        secret = str(secret)

    # SHA-256 → always 32 bytes (AES-256 safe)
    return hashlib.sha256(secret.encode("utf-8")).digest()


AES_KEY = _derive_aes_key()

# ======================================================
# ENCRYPT
# ======================================================

def encrypt_text(plaintext: str) -> dict:
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)  # AES-GCM standard nonce size

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8")
    }


# ======================================================
# DECRYPT
# ======================================================

def decrypt_text(ciphertext_b64: str, nonce_b64: str) -> str:
    aesgcm = AESGCM(AES_KEY)

    ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
    nonce = base64.b64decode(nonce_b64.encode("utf-8"))

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")
