import os
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", 15))

# 🔐 External Kyber Service
KYBER_SERVICE_URL = os.getenv("KYBER_SERVICE_URL", "")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set in environment variables")
