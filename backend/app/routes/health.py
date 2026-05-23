from fastapi import APIRouter
from app.models.schemas import HealthResponse
from app.config import settings
from app.services.ml_classifier import is_model_loaded

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["System"])
def health_check():
    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        ml_model_loaded=is_model_loaded(),
    )
