import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", 15))

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set in environment variables")
