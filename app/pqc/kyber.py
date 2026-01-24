import os
import time
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Official CRYSTALS-Kyber-512 parameters (NIST)
KYBER_PUBLIC_KEY_SIZE = 800
KYBER_CIPHERTEXT_SIZE = 768
KYBER_SHARED_SECRET_SIZE = 32


def simulated_kyber_key_exchange():
    metrics = {}

    # Simulate key generation
    start = time.perf_counter()
    public_key = os.urandom(KYBER_PUBLIC_KEY_SIZE)
    private_key = os.urandom(2400)  # Kyber512 secret key size
    metrics["keygen_time_ms"] = (time.perf_counter() - start) * 1000

    # Simulate encapsulation
    start = time.perf_counter()
    ciphertext = os.urandom(KYBER_CIPHERTEXT_SIZE)
    shared_secret = os.urandom(KYBER_SHARED_SECRET_SIZE)
    metrics["encapsulation_time_ms"] = (time.perf_counter() - start) * 1000

    # Simulate decapsulation
    start = time.perf_counter()
    recovered_secret = shared_secret
    metrics["decapsulation_time_ms"] = (time.perf_counter() - start) * 1000

    metrics["public_key_size"] = len(public_key)
    metrics["ciphertext_size"] = len(ciphertext)
    metrics["shared_secret_size"] = len(shared_secret)

    return shared_secret, metrics


def derive_aes_key(shared_secret: bytes) -> bytes:
    return hashlib.sha256(shared_secret).digest()


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
