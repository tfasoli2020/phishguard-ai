import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config import settings
from app.database import init_db
from app.routes import analyze, history, health
from app.services.ml_classifier import load_model

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables and warm up the ML model on startup
    init_db()
    try:
        load_model(settings.ML_MODEL_PATH)
        logger.info("ML model ready")
    except Exception as exc:
        logger.warning("ML model warm-up failed: %s", exc)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "PhishGuard AI — Defensive email triage and analysis API. "
        "For security education and portfolio use only."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Security headers / CORS ───────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Accept"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(analyze.router)
app.include_router(history.router)
