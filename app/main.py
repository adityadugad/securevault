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
    allow_origins=["*"],          
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------
# DATABASE INIT (RUNS ON STARTUP)
# -------------------------------------------------
os.makedirs(os.path.dirname(os.getenv("DATABASE_PATH", "")), exist_ok=True)

create_tables()
create_vault_tables()

# -------------------------------------------------
# API ROUTERS
# -------------------------------------------------
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(vault_router, prefix="/vault", tags=["Vault"])

# -------------------------------------------------
# STATIC FRONTEND
# -------------------------------------------------
app.mount("/static", StaticFiles(directory="static"), name="static")

# -------------------------------------------------
# FRONTEND ENTRY POINT
# -------------------------------------------------
@app.get("/", include_in_schema=False)
def home():
    return FileResponse("static/index.html")

# -------------------------------------------------
# PQC METRICS API
# -------------------------------------------------
@app.get("/pqc/metrics", tags=["PQC"])
def pqc_metrics():
    return get_pqc_metrics()

# -------------------------------------------------
# HEALTH CHECK
# -------------------------------------------------
@app.get("/health", tags=["System"])
def health():
    return {
        "status": "SecureVault Backend Running",
        "environment": os.getenv("RENDER", "local"),
    }

# -------------------------------------------------
# KYBER SERVICE WARMUP
# -------------------------------------------------
import threading
import requests
from app.config import KYBER_SERVICE_URL

def warmup_kyber():
    if not KYBER_SERVICE_URL:
        return
    try:
        requests.get(f"{KYBER_SERVICE_URL}/kyber", timeout=1)
    except Exception:
        pass

threading.Thread(target=warmup_kyber, daemon=True).start()


# -------------------------------------------------
# SITEMAP (ADDED ONLY THIS PART)
# -------------------------------------------------
@app.get("/sitemap.xml", include_in_schema=False)
def sitemap():
    return FileResponse("sitemap.xml")

@app.get("/robots.txt", include_in_schema=False)
def robots():
    return FileResponse("robots.txt")
