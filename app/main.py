from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os

from app.models import create_tables
from app.auth.auth_routes import auth_router
from app.pqc.metrics import get_pqc_metrics
from app.vault.vault_routes import vault_router
from app.vault.vault_models import create_vault_tables

# -------------------------------------------------
# APP INIT
# -------------------------------------------------
app = FastAPI(
    title="SecureVault PQC Backend",
    docs_url="/docs",        # enable Swagger on Render
    redoc_url="/redoc"
)

# -------------------------------------------------
# CORS (RENDER + LOCAL SAFE)
# -------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # safe because auth is JWT-based
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------
# DATABASE INIT (RUNS ON STARTUP)
# -------------------------------------------------
# SQLite path comes from env on Render, local fallback otherwise
os.makedirs(os.path.dirname(os.getenv("DATABASE_PATH", "")), exist_ok=True)

create_tables()
create_vault_tables()

# -------------------------------------------------
# API ROUTERS
# -------------------------------------------------
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(vault_router, prefix="/vault", tags=["Vault"])

# -------------------------------------------------
# STATIC FRONTEND (HTML / CSS / JS)
# -------------------------------------------------
# Expected structure:
# static/
#   index.html
#   signup.html
#   otp.html
#   dashboard.html
#   notes.html
#   todos.html
#   passwords.html
#   pqc.html
#   css/style.css
#   js/*.js
#
app.mount("/static", StaticFiles(directory="static"), name="static")

# -------------------------------------------------
# FRONTEND ENTRY POINT
# -------------------------------------------------
@app.get("/", include_in_schema=False)
def home():
    return FileResponse("static/index.html")

# -------------------------------------------------
# PQC METRICS API (REAL-TIME)
# -------------------------------------------------
@app.get("/pqc/metrics", tags=["PQC"])
def pqc_metrics():
    return get_pqc_metrics()

# -------------------------------------------------
# HEALTH CHECK (RENDER USES THIS)
# -------------------------------------------------
@app.get("/health", tags=["System"])
def health():
    return {
        "status": "SecureVault Backend Running",
        "environment": os.getenv("RENDER", "local"),
    }
