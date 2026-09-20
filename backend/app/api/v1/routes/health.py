from fastapi import APIRouter
from app.schemas.health import HealthResponse

router = APIRouter()

@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def get_health():
    """
    Health check endpoint for MAILSENTINEL API service.
    """
    return {
        "status": "ok",
        "service": "mailsentinel-api",
        "version": "0.1.0"
    }
